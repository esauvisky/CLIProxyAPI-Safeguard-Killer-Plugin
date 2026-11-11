package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	methodHostAuthList   = "host.auth.list"
	methodHostAuthModels = "host.auth.models"

	// Scheduler option metadata set by the host (cliproxy executor and session packages).
	metadataRequestedModel     = "requested_model"
	metadataCanonicalSessionID = "canonical_session_id"
	metadataDerivedSessionID   = "derived_session_id"

	hostCacheTTL     = 15 * time.Second
	maxDecisions     = 200
	minHoursToReset  = 0.25
	sessionRetention = 24 * time.Hour
)

type schedulerPickRequest struct {
	Model      string               `json:"Model"`
	Options    schedulerOptions     `json:"Options"`
	Candidates []schedulerCandidate `json:"Candidates"`
}

type schedulerOptions struct {
	Metadata map[string]any `json:"Metadata"`
}

type schedulerCandidate struct {
	ID       string `json:"ID"`
	Provider string `json:"Provider"`
}

type schedulerPickResponse struct {
	AuthID  string `json:"AuthID,omitempty"`
	Handled bool   `json:"Handled"`
}

type hostAuthListResponse struct {
	Files []hostAuth `json:"files"`
}

type hostAuthModelsResponse struct {
	Credentials []struct {
		ID        string   `json:"id"`
		AuthIndex string   `json:"auth_index"`
		Provider  string   `json:"provider"`
		Models    []string `json:"models"`
	} `json:"credentials"`
}

type hostSnapshot struct {
	auths  []hostAuth
	models map[string][]string
	// synthesized holds the IDs of credentials with no backing auth file, reported only by
	// host.auth.models (config-synthesized openai-compatibility providers). They carry no
	// management record, so their weight and quota are defaulted rather than required.
	synthesized map[string]struct{}
	fetchedAt   time.Time
}

var (
	// hostCall is the host callback entry point; unit tests replace it because they run without a host.
	hostCall = callHost

	hostMu    sync.Mutex
	hostCache hostSnapshot

	stateMu   sync.Mutex
	sessions  = make(map[string]*sessionBinding)
	decisions []decision
)

// hostState returns the credential list and per-credential models, cached for hostCacheTTL.
func hostState(now time.Time) (hostSnapshot, error) {
	hostMu.Lock()
	defer hostMu.Unlock()
	if !hostCache.fetchedAt.IsZero() && now.Sub(hostCache.fetchedAt) < hostCacheTTL {
		return hostCache, nil
	}
	rawList, errList := hostCall(methodHostAuthList, struct{}{})
	if errList != nil {
		return hostSnapshot{}, errList
	}
	var list hostAuthListResponse
	if errUnmarshal := json.Unmarshal(rawList, &list); errUnmarshal != nil {
		return hostSnapshot{}, fmt.Errorf("decode host.auth.list: %w", errUnmarshal)
	}
	rawModels, errModels := hostCall(methodHostAuthModels, struct{}{})
	if errModels != nil {
		return hostSnapshot{}, errModels
	}
	var modelsResp hostAuthModelsResponse
	if errUnmarshal := json.Unmarshal(rawModels, &modelsResp); errUnmarshal != nil {
		return hostSnapshot{}, fmt.Errorf("decode host.auth.models: %w", errUnmarshal)
	}
	models := make(map[string][]string, len(modelsResp.Credentials))
	for _, credential := range modelsResp.Credentials {
		models[credential.ID] = credential.Models
	}
	// host.auth.list omits credentials with no backing auth file (config-synthesized
	// openai-compatibility providers), but host.auth.models reports them from the full
	// auth manager. Take the union so a candidate the host offers is never rejected as
	// absent; the models response is authoritative for "this credential exists".
	auths := make([]hostAuth, 0, len(list.Files)+len(modelsResp.Credentials))
	seen := make(map[string]struct{}, len(list.Files))
	for _, auth := range list.Files {
		auths = append(auths, auth)
		seen[auth.ID] = struct{}{}
	}
	synthesized := make(map[string]struct{}, len(modelsResp.Credentials))
	for _, credential := range modelsResp.Credentials {
		if _, ok := seen[credential.ID]; ok {
			continue
		}
		auths = append(auths, hostAuth{ID: credential.ID, AuthIndex: credential.AuthIndex, Provider: credential.Provider})
		synthesized[credential.ID] = struct{}{}
	}
	hostCache = hostSnapshot{auths: auths, models: models, synthesized: synthesized, fetchedAt: now}
	return hostCache, nil
}

func authsByID(snapshot hostSnapshot, ids []string) ([]hostAuth, error) {
	byID := make(map[string]hostAuth, len(snapshot.auths))
	for _, auth := range snapshot.auths {
		byID[auth.ID] = auth
	}
	out := make([]hostAuth, 0, len(ids))
	for _, id := range ids {
		auth, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("credential %s is not in the host credential list", id)
		}
		out = append(out, auth)
	}
	return out, nil
}

// pick balances the candidate credentials of a model, a single candidate included so its
// exclusions still apply: a session keeps its credential while
// prompts keep coming, and a new or idle session goes to the credential with the highest
// weight * bottleneck rate / (1 + load). When every candidate is excluded the pick fails with
// HTTP 503 listing each exclusion; handing the request back to the host would undo them.
func pick(req schedulerPickRequest, cfg pluginConfig, now time.Time) (schedulerPickResponse, error) {
	// Without a management key balancing is off by configuration and the host selector decides.
	if cfg.ManagementKey == "" {
		return schedulerPickResponse{Handled: false}, nil
	}
	if len(req.Candidates) == 0 {
		return schedulerPickResponse{}, &statusError{Code: "no_eligible_credential", Message: "scheduler offered no candidate credentials for " + req.Model, HTTPStatus: http.StatusServiceUnavailable}
	}
	requested, okRequested := req.Options.Metadata[metadataRequestedModel].(string)
	if !okRequested {
		return schedulerPickResponse{}, fmt.Errorf("scheduler request has no %s metadata", metadataRequestedModel)
	}
	snapshot, errHost := hostState(now)
	if errHost != nil {
		return schedulerPickResponse{}, errHost
	}
	ids := make([]string, 0, len(req.Candidates))
	for _, candidate := range req.Candidates {
		ids = append(ids, candidate.ID)
	}
	auths, errAuths := authsByID(snapshot, ids)
	if errAuths != nil {
		return schedulerPickResponse{}, errAuths
	}
	ensureQuotaFresh(cfg.ManagementKey, auths)
	if errWeights := loadAuthWeights(cfg.ManagementKey, ids, snapshot.synthesized, now); errWeights != nil {
		return schedulerPickResponse{}, errWeights
	}
	session := sessionKey(req.Options.Metadata)
	bindingKey := session + "\x00" + req.Model

	// Ranking and binding happen under one lock so concurrent new sessions see each other's
	// bindings in Load instead of all landing on the same credential.
	stateMu.Lock()
	defer stateMu.Unlock()
	ranking := rankCredentials(cfg, auths, req.Model, now)
	if session != "" {
		if binding, ok := sessions[bindingKey]; ok && now.Before(binding.IdleExpiresAt) {
			if entry, found := findRank(ranking, binding.AuthID); found && entry.Excluded == "" {
				touchSession(binding, cfg, now)
				recordDecision(decision{Time: now, Kind: "balance", Model: requested, Session: session, AuthID: binding.AuthID, Reason: "session active, kept credential", Ranking: ranking})
				return schedulerPickResponse{AuthID: binding.AuthID, Handled: true}, nil
			}
		}
	}
	best, ok := bestRank(ranking)
	if !ok {
		exclusions := make([]string, 0, len(ranking))
		for _, entry := range ranking {
			exclusions = append(exclusions, entry.AuthID+": "+entry.Excluded)
		}
		message := "no credential eligible for " + requested + ": " + strings.Join(exclusions, "; ")
		recordDecision(decision{Time: now, Kind: "balance", Model: requested, Session: session, Reason: message, Ranking: ranking})
		return schedulerPickResponse{}, &statusError{Code: "no_eligible_credential", Message: message, HTTPStatus: http.StatusServiceUnavailable}
	}
	reason := "highest score (no session identity)"
	if session != "" {
		sessions[bindingKey] = &sessionBinding{Session: session, AuthID: best.AuthID, Provider: best.Provider, Model: req.Model, BoundAt: now}
		touchSession(sessions[bindingKey], cfg, now)
		reason = "new or idle session bound to highest score"
	}
	recordDecision(decision{Time: now, Kind: "balance", Model: requested, Session: session, AuthID: best.AuthID, Reason: reason, Ranking: ranking})
	pruneSessions(now)
	return schedulerPickResponse{AuthID: best.AuthID, Handled: true}, nil
}

// sessionKey uses the session identity the host derived for the request.
func sessionKey(metadata map[string]any) string {
	if canonical, ok := metadata[metadataCanonicalSessionID].(string); ok && canonical != "" {
		return canonical
	}
	if derived, ok := metadata[metadataDerivedSessionID].(string); ok && derived != "" {
		return "derived:" + derived
	}
	return ""
}

func touchSession(binding *sessionBinding, cfg pluginConfig, now time.Time) {
	binding.LastSeen = now
	binding.IdleExpiresAt = now.Add(time.Duration(cfg.IdleMinutes) * time.Minute)
}

func pruneSessions(now time.Time) {
	for key, binding := range sessions {
		if now.Sub(binding.LastSeen) > sessionRetention {
			delete(sessions, key)
		}
	}
}

// rankCredentials evaluates credentials for a model, best first; excluded ones go last. Score is
// weight * bottleneck rate / (1 + load), where load counts sessions bound to the credential
// within idle_minutes. It reads sessions, so callers hold stateMu, and the account weights of
// every auth must be loaded (loadAuthWeights).
func rankCredentials(cfg pluginConfig, auths []hostAuth, model string, now time.Time) []rankEntry {
	load := activeBindings(now)
	ranking := make([]rankEntry, 0, len(auths))
	for _, auth := range auths {
		weight, ok := authWeight(auth.ID)
		if !ok {
			panic(fmt.Sprintf("account weight for credential %s is not loaded", auth.ID))
		}
		entry := rankEntry{AuthID: auth.ID, Provider: auth.Provider, Weight: weight, Load: load[auth.ID]}
		switch {
		case auth.Disabled:
			entry.Excluded = "credential disabled"
		case auth.Unavailable && auth.NextRetryAfter.IsZero():
			entry.Excluded = "credential unavailable"
		case auth.Unavailable && auth.NextRetryAfter.After(now):
			entry.Excluded = "credential unavailable until " + auth.NextRetryAfter.Format(time.RFC3339)
		case weight == 0:
			entry.Excluded = "account weight is 0"
		default:
			// An unavailable credential whose retry time has passed is eligible again: the host
			// offered it as a candidate and the host snapshot lags by up to hostCacheTTL.
			rateCredential(&entry, model, cfg.MinRemaining, now)
			if entry.Excluded == "" {
				entry.Score = entry.Rate * weight / float64(1+entry.Load)
			}
		}
		ranking = append(ranking, entry)
	}
	sort.SliceStable(ranking, func(i, j int) bool {
		if (ranking[i].Excluded == "") != (ranking[j].Excluded == "") {
			return ranking[i].Excluded == ""
		}
		return ranking[i].Score > ranking[j].Score
	})
	return ranking
}

// activeBindings counts session bindings per credential that are still within idle_minutes;
// callers hold stateMu. The host reports no per-credential request lifecycle (request.complete
// carries only a request ID), so active sessions are the load signal, not in-flight requests.
func activeBindings(now time.Time) map[string]int {
	counts := make(map[string]int)
	for _, binding := range sessions {
		if now.Before(binding.IdleExpiresAt) {
			counts[binding.AuthID]++
		}
	}
	return counts
}

// neutralRate is the rate of a credential whose quota is optional by provider design: the
// provider has no quota source, no reported window applies to the model, or no applicable window
// reports a reset time. Weight and load still apply to it.
const neutralRate = 1

// rateCredential scores a credential from its quota windows that apply to the model. Every
// applicable window must keep at least minRemaining. The rate is the bottleneck: the lowest
// remaining / hours_to_reset among applicable windows that report a reset time. A window without
// a reset time (the provider does not report one) only takes part in the threshold check.
// A missing snapshot, a fetch error, or a snapshot without windows excludes the credential.
func rateCredential(entry *rankEntry, model string, minRemaining float64, now time.Time) {
	quota, ok := quotaFor(entry.AuthID)
	if !ok {
		entry.Excluded = "quota not fetched yet"
		return
	}
	if quota.Source == quotaSourceNone {
		entry.Window = "no quota source"
		entry.Rate = neutralRate
		return
	}
	if quota.Error != "" {
		entry.Excluded = "quota error: " + quota.Error
		return
	}
	if len(quota.Windows) == 0 {
		entry.Excluded = "quota snapshot has no windows"
		return
	}
	applicable := 0
	found := false
	var bottleneck string
	var bottleneckRemaining, bottleneckHours, bottleneckRate float64
	for _, window := range quota.Windows {
		if len(window.Models) > 0 && !containsString(window.Models, model) {
			continue
		}
		applicable++
		remaining, resetAt := rolledWindow(window, now)
		if remaining < minRemaining {
			entry.Excluded = fmt.Sprintf("%s has %.0f%% left", window.Name, remaining*100)
			return
		}
		if resetAt.IsZero() {
			continue
		}
		hours := math.Max(resetAt.Sub(now).Hours(), minHoursToReset)
		rate := remaining / hours
		if !found || rate < bottleneckRate {
			found = true
			bottleneck, bottleneckRemaining, bottleneckHours, bottleneckRate = window.Name, remaining, hours, rate
		}
	}
	if applicable == 0 {
		entry.Window = "no window applies to " + model
		entry.Rate = neutralRate
		return
	}
	if !found {
		entry.Window = "no reset time reported"
		entry.Rate = neutralRate
		return
	}
	entry.Window = bottleneck
	entry.Remaining = bottleneckRemaining
	entry.HoursToReset = bottleneckHours
	entry.Rate = bottleneckRate
}

// rolledWindow applies resets that happened since the snapshot: a passed reset with a known
// period means the window is full again until the next period boundary.
func rolledWindow(window quotaWindow, now time.Time) (float64, time.Time) {
	if window.ResetAt.IsZero() || window.ResetAt.After(now) || window.Period <= 0 {
		return window.Remaining, window.ResetAt
	}
	periods := math.Floor(float64(now.Sub(window.ResetAt))/float64(window.Period)) + 1
	return 1, window.ResetAt.Add(time.Duration(periods) * window.Period)
}

func bestRank(ranking []rankEntry) (rankEntry, bool) {
	if len(ranking) == 0 || ranking[0].Excluded != "" {
		return rankEntry{}, false
	}
	return ranking[0], true
}

func findRank(ranking []rankEntry, authID string) (rankEntry, bool) {
	for _, entry := range ranking {
		if entry.AuthID == authID {
			return entry, true
		}
	}
	return rankEntry{}, false
}

// recordDecision appends to the ring buffer; callers hold stateMu.
func recordDecision(entry decision) {
	decisions = append(decisions, entry)
	if len(decisions) > maxDecisions {
		decisions = decisions[len(decisions)-maxDecisions:]
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func buildUIState() uiState {
	now := time.Now()
	cfg := currentConfig()
	state := uiState{Version: pluginVersion, Now: now, Config: cfg, ManagementError: managementStatus(cfg.ManagementKey, now), Metrics: computeRoutingMetrics()}
	snapshot, errHost := hostState(now)
	if errHost != nil {
		state.Error = errHost.Error()
	}
	if state.ManagementError == "" {
		ensureQuotaFresh(cfg.ManagementKey, snapshot.auths)
	}
	models := make(map[string]bool)
	stateMu.Lock()
	defer stateMu.Unlock()
	for _, auth := range snapshot.auths {
		quota, hasQuota := quotaFor(auth.ID)
		state.Credentials = append(state.Credentials, uiCredential{Auth: auth, Quota: quota, HasQuota: hasQuota, Models: snapshot.models[auth.ID]})
		for _, model := range snapshot.models[auth.ID] {
			models[model] = true
		}
	}
	for model := range models {
		state.Models = append(state.Models, model)
	}
	sort.Strings(state.Models)
	for _, binding := range sessions {
		state.Sessions = append(state.Sessions, *binding)
	}
	for full, conversation := range groupStates {
		view := conversationBindingView(conversation)
		view.Model = strings.TrimPrefix(full, conversation.Key+"\x00")
		state.Sessions = append(state.Sessions, view)
	}
	sort.Slice(state.Sessions, func(i, j int) bool { return state.Sessions[i].LastSeen.After(state.Sessions[j].LastSeen) })
	for index := len(decisions) - 1; index >= 0; index-- {
		state.Decisions = append(state.Decisions, decisions[index])
	}
	return state
}
