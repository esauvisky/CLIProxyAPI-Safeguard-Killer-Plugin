package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func setQuota(t *testing.T, authID string, windows ...quotaWindow) {
	t.Helper()
	quotaMu.Lock()
	quotaSnapshots[authID] = credentialQuota{AuthID: authID, Windows: windows, FetchedAt: time.Now()}
	quotaMu.Unlock()
	t.Cleanup(func() {
		quotaMu.Lock()
		delete(quotaSnapshots, authID)
		quotaMu.Unlock()
	})
}

func weekly(remaining float64, resetIn time.Duration) quotaWindow {
	return quotaWindow{Name: "7d", Remaining: remaining, ResetAt: testNow.Add(resetIn), Period: 7 * 24 * time.Hour}
}

// fakeHost answers host.auth.list / host.auth.models for the given auth IDs (all serving models)
// and delegates every other method to other.
func fakeHost(t *testing.T, models []string, other func(method string, payload any) (json.RawMessage, error), ids ...string) {
	t.Helper()
	fakeHostSplit(t, models, other, ids, ids)
}

// fakeHostSplit answers the two host callbacks with independent ID sets, so a test can reproduce
// a credential the host offers as a candidate (present in host.auth.models) but omits from
// host.auth.list, as config-synthesized openai-compatibility providers are.
func fakeHostSplit(t *testing.T, models []string, other func(method string, payload any) (json.RawMessage, error), listIDs, modelIDs []string) {
	t.Helper()
	hostCall = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case methodHostAuthList:
			files := make([]hostAuth, 0, len(listIDs))
			for index, id := range listIDs {
				files = append(files, hostAuth{ID: id, AuthIndex: string(rune('a' + index)), Provider: "claude"})
			}
			return json.Marshal(hostAuthListResponse{Files: files})
		case methodHostAuthModels:
			var resp hostAuthModelsResponse
			for _, id := range modelIDs {
				resp.Credentials = append(resp.Credentials, struct {
					ID        string   `json:"id"`
					AuthIndex string   `json:"auth_index"`
					Provider  string   `json:"provider"`
					Models    []string `json:"models"`
				}{ID: id, Provider: "claude", Models: models})
			}
			return json.Marshal(resp)
		}
		return other(method, payload)
	}
	resetHostState(t)
}

func resetHostState(t *testing.T) {
	t.Helper()
	sessionStatePath = ""
	hostMu.Lock()
	hostCache = hostSnapshot{}
	hostMu.Unlock()
	stateMu.Lock()
	sessions = make(map[string]*sessionBinding)
	groupStates = make(map[string]*conversationState)
	decisions = nil
	stateMu.Unlock()
	t.Cleanup(func() {
		hostCall = callHost
		hostMu.Lock()
		hostCache = hostSnapshot{}
		hostMu.Unlock()
	})
}

// fakeWeights serves the management auth-files list with the given body and clears the
// account weight cache.
func fakeWeights(t *testing.T, body string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/auth-files" {
			t.Errorf("unexpected management call %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	origURL := managementBaseURL
	managementBaseURL = server.URL
	resetWeights := func() {
		authWeightMu.Lock()
		authWeights = make(map[string]float64)
		authWeightsAt = time.Time{}
		authWeightMu.Unlock()
	}
	resetWeights()
	t.Cleanup(func() {
		server.Close()
		managementBaseURL = origURL
		resetWeights()
	})
}

func noOther(t *testing.T) func(string, any) (json.RawMessage, error) {
	return func(method string, _ any) (json.RawMessage, error) {
		t.Fatalf("unexpected host call %s", method)
		return nil, nil
	}
}

func balanceConfig() pluginConfig {
	cfg := defaultPluginConfig()
	cfg.ManagementKey = "k"
	quotaRefreshAge = 1000 * time.Minute
	return cfg
}

const weightsAB = `{"files":[{"id":"a"},{"id":"b"}]}`

func pickReq(session string, ids ...string) schedulerPickRequest {
	req := schedulerPickRequest{Model: "claude-opus-4-8", Options: schedulerOptions{Metadata: map[string]any{metadataRequestedModel: "claude-opus-4-8"}}}
	if session != "" {
		req.Options.Metadata[metadataCanonicalSessionID] = session
	}
	for _, id := range ids {
		req.Candidates = append(req.Candidates, schedulerCandidate{ID: id, Provider: "claude"})
	}
	return req
}

func TestPickPrefersQuotaExpiringSooner(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, weightsAB)
	// a: 30% left resetting in 24h (1.25%/h) beats b: 60% left resetting in 6 days (0.42%/h).
	setQuota(t, "a", weekly(0.30, 24*time.Hour))
	setQuota(t, "b", weekly(0.60, 144*time.Hour))
	resp, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow)
	if errPick != nil || resp.AuthID != "a" || !resp.Handled {
		t.Fatalf("pick() = %+v, %v; want a", resp, errPick)
	}
}

func TestPickSessionStickyUntilIdle(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, weightsAB)
	setQuota(t, "a", weekly(0.30, 24*time.Hour))
	setQuota(t, "b", weekly(0.60, 144*time.Hour))
	cfg := balanceConfig()
	if resp, _ := pick(pickReq("s1", "a", "b"), cfg, testNow); resp.AuthID != "a" {
		t.Fatalf("first pick = %+v, want a", resp)
	}
	// b becomes the better credential, but the active session keeps a.
	setQuota(t, "b", weekly(0.90, 2*time.Hour))
	if resp, _ := pick(pickReq("s1", "a", "b"), cfg, testNow.Add(4*time.Minute)); resp.AuthID != "a" {
		t.Fatalf("active session pick = %+v, want a", resp)
	}
	// After more than idle_minutes without a prompt the session re-ranks.
	if resp, _ := pick(pickReq("s1", "a", "b"), cfg, testNow.Add(10*time.Minute)); resp.AuthID != "b" {
		t.Fatalf("idle session pick = %+v, want b", resp)
	}
}

// assertNoEligible requires pick to fail with HTTP 503 naming want.
func assertNoEligible(t *testing.T, errPick error, want string) {
	t.Helper()
	var errStatus *statusError
	if !errors.As(errPick, &errStatus) || errStatus.HTTPStatus != http.StatusServiceUnavailable || !strings.Contains(errStatus.Message, want) {
		t.Fatalf("pick() error = %v, want 503 containing %q", errPick, want)
	}
}

func TestPickFailsWhenLowQuotaOrNoData(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "drained", "nodata")
	fakeWeights(t, `{"files":[{"id":"drained"},{"id":"nodata"}]}`)
	setQuota(t, "drained", weekly(0.9, 48*time.Hour), quotaWindow{Name: "5h", Remaining: 0.01, ResetAt: testNow.Add(time.Hour), Period: 5 * time.Hour})
	quotaMu.Lock()
	quotaSnapshots["nodata"] = credentialQuota{AuthID: "nodata", FetchedAt: time.Now()}
	quotaMu.Unlock()
	t.Cleanup(func() { quotaMu.Lock(); delete(quotaSnapshots, "nodata"); quotaMu.Unlock() })

	_, errPick := pick(pickReq("", "drained", "nodata"), balanceConfig(), testNow)
	assertNoEligible(t, errPick, "5h has 1% left")
	assertNoEligible(t, errPick, "nodata: quota snapshot has no windows")
	stateMu.Lock()
	last := decisions[len(decisions)-1]
	stateMu.Unlock()
	if last.AuthID != "" || !strings.Contains(last.Reason, "no credential eligible") {
		t.Fatalf("decision = %+v, want recorded exclusions", last)
	}
}

func TestPickFailsWhenAllExcludedByWeight(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, `{"files":[{"id":"a","weight":0},{"id":"b","weight":0}]}`)
	setQuota(t, "a", weekly(0.9, 24*time.Hour))
	setQuota(t, "b", weekly(0.9, 24*time.Hour))
	_, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow)
	assertNoEligible(t, errPick, "account weight is 0")
}

func TestPickNeutralRateForOptionalQuota(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, `{"files":[{"id":"a"},{"id":"b","weight":0}]}`)
	quotaMu.Lock()
	quotaSnapshots["a"] = credentialQuota{AuthID: "a", Source: quotaSourceNone, Error: "opencode: no quota source", FetchedAt: time.Now()}
	quotaMu.Unlock()
	t.Cleanup(func() { quotaMu.Lock(); delete(quotaSnapshots, "a"); quotaMu.Unlock() })
	setQuota(t, "b", weekly(0.9, 24*time.Hour))
	resp, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow)
	if errPick != nil || resp.AuthID != "a" {
		t.Fatalf("pick() = %+v, %v; want a with neutral rate", resp, errPick)
	}
	stateMu.Lock()
	last := decisions[len(decisions)-1]
	stateMu.Unlock()
	if entry, _ := findRank(last.Ranking, "a"); entry.Rate != neutralRate || entry.Score != neutralRate {
		t.Fatalf("ranking = %+v, want a at neutral rate", last.Ranking)
	}
}

func TestRateNeutralWithoutApplicableWindowOrReset(t *testing.T) {
	setQuota(t, "scoped", quotaWindow{Name: "7d Fable", Remaining: 0.5, ResetAt: testNow.Add(time.Hour), Models: []string{"claude-fable-5"}})
	setQuota(t, "noreset", quotaWindow{Name: "monthly", Remaining: 0.5})
	setQuota(t, "noreset-low", quotaWindow{Name: "monthly", Remaining: 0.01})
	for id, wantWindow := range map[string]string{"scoped": "no window applies to m", "noreset": "no reset time reported"} {
		entry := rankEntry{AuthID: id}
		rateCredential(&entry, "m", 0.02, testNow)
		if entry.Excluded != "" || entry.Rate != neutralRate || entry.Window != wantWindow {
			t.Fatalf("rateCredential(%s) = %+v, want neutral rate", id, entry)
		}
	}
	entry := rankEntry{AuthID: "noreset-low"}
	rateCredential(&entry, "m", 0.02, testNow)
	if entry.Excluded != "monthly has 1% left" {
		t.Fatalf("rateCredential(noreset-low) = %+v, want threshold exclusion", entry)
	}
}

func TestPickSingleCandidateBalancedAndNoKeyUnhandled(t *testing.T) {
	if resp, errPick := pick(pickReq("", "a", "b"), defaultPluginConfig(), testNow); errPick != nil || resp.Handled {
		t.Fatalf("pick without management key = %+v, %v; want unhandled", resp, errPick)
	}
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, `{"files":[{"id":"a"},{"id":"b","weight":0}]}`)
	setQuota(t, "a", weekly(0.5, 24*time.Hour))
	setQuota(t, "b", weekly(0.5, 24*time.Hour))
	if resp, errPick := pick(pickReq("", "a"), balanceConfig(), testNow); errPick != nil || !resp.Handled || resp.AuthID != "a" {
		t.Fatalf("single eligible candidate = %+v, %v; want a handled", resp, errPick)
	}
	_, errPick := pick(pickReq("", "b"), balanceConfig(), testNow)
	assertNoEligible(t, errPick, "account weight is 0")
	_, errPick = pick(pickReq(""), balanceConfig(), testNow)
	assertNoEligible(t, errPick, "no candidate credentials")
}

func TestPickModelScopedWindow(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8", "claude-fable-5"}, noOther(t), "a", "b")
	fakeWeights(t, weightsAB)
	setQuota(t, "a", weekly(0.5, 24*time.Hour), quotaWindow{Name: "7d Fable", Remaining: 0, ResetAt: testNow.Add(24 * time.Hour), Period: 7 * 24 * time.Hour, Models: []string{"claude-fable-5"}})
	setQuota(t, "b", weekly(0.5, 100*time.Hour))
	if resp, _ := pick(pickReq("", "a", "b"), balanceConfig(), testNow); resp.AuthID != "a" {
		t.Fatalf("opus pick = %+v, want a", resp)
	}
	fable := pickReq("", "a", "b")
	fable.Model = "claude-fable-5"
	if resp, _ := pick(fable, balanceConfig(), testNow); resp.AuthID != "b" {
		t.Fatalf("fable pick = %+v, want b", resp)
	}
}

func TestRolledWindowRefillsAfterReset(t *testing.T) {
	remaining, resetAt := rolledWindow(weekly(0, -24*time.Hour), testNow)
	if remaining != 1 || !resetAt.Equal(testNow.Add(6*24*time.Hour)) {
		t.Fatalf("rolledWindow = %v, %v; want 1, now+6d", remaining, resetAt)
	}
}

func TestValidateConfigGroups(t *testing.T) {
	m := []groupModel{{ID: "m"}}
	cases := map[string][]modelGroup{
		"needs a name":  {{ID: "g", Mode: groupModeQuality, Models: m}},
		"at least one":  {{ID: "g", Name: "G", Mode: groupModeQuality}},
		"used twice":    {{ID: "g", Name: "G", Mode: groupModeQuality, Models: m}, {ID: "g", Name: "H", Mode: groupModeQuality, Models: m}},
		"groups cannot": {{ID: "g", Name: "G", Mode: groupModeQuality, Models: []groupModel{{ID: "h"}}}, {ID: "h", Name: "H", Mode: groupModeQuality, Models: m}},
		"needs an id":   {{Name: "G", Mode: groupModeQuality, Models: m}},
	}
	for want, groups := range cases {
		cfg := defaultPluginConfig()
		cfg.Groups = groups
		if errValidate := validateConfig(cfg); errValidate == nil || !strings.Contains(errValidate.Error(), want) {
			t.Fatalf("validateConfig(%+v) = %v, want %q", groups, errValidate, want)
		}
	}
	cfg := defaultPluginConfig()
	cfg.Groups = []modelGroup{{ID: "uncensored-models", Name: "Uncensored", Mode: groupModeQuality, Models: []groupModel{{ID: "glm-5.3-uncensored"}, {ID: "deepseek-v4.1-flash-uncensored"}}}}
	if errValidate := validateConfig(cfg); errValidate != nil {
		t.Fatalf("validateConfig(valid) = %v", errValidate)
	}
	cfg.IdleMinutes = 0
	if errValidate := validateConfig(cfg); errValidate != nil {
		t.Fatalf("validateConfig(idle_minutes=0) = %v", errValidate)
	}
	cfg.IdleMinutes = -1
	if errValidate := validateConfig(cfg); errValidate == nil {
		t.Fatalf("validateConfig(idle_minutes=-1) = nil, want error")
	}
}

func TestRateUsesBottleneckWindow(t *testing.T) {
	// weekly allows 0.9/24h = 0.0375/h, the 5h window only 0.1/4h = 0.025/h: the 5h window binds.
	setQuota(t, "a", weekly(0.9, 24*time.Hour), quotaWindow{Name: "5h", Remaining: 0.1, ResetAt: testNow.Add(4 * time.Hour), Period: 5 * time.Hour})
	entry := rankEntry{AuthID: "a"}
	rateCredential(&entry, "m", 0.05, testNow)
	if entry.Excluded != "" || entry.Window != "5h" || entry.Rate != 0.1/4 {
		t.Fatalf("rateCredential = %+v, want 5h bottleneck at 0.025/h", entry)
	}
}

func TestPickSpreadsNewSessionsByLoad(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, weightsAB)
	// a rates 0.5/24h, b 0.4/24h: the first session goes to a, the second sees a loaded and takes b.
	setQuota(t, "a", weekly(0.5, 24*time.Hour))
	setQuota(t, "b", weekly(0.4, 24*time.Hour))
	cfg := balanceConfig()
	if resp, _ := pick(pickReq("s1", "a", "b"), cfg, testNow); resp.AuthID != "a" {
		t.Fatalf("first session pick = %+v, want a", resp)
	}
	resp, errPick := pick(pickReq("s2", "a", "b"), cfg, testNow)
	if errPick != nil || resp.AuthID != "b" {
		t.Fatalf("second session pick = %+v, %v; want b", resp, errPick)
	}
	stateMu.Lock()
	last := decisions[len(decisions)-1]
	stateMu.Unlock()
	if entry, _ := findRank(last.Ranking, "a"); entry.Load != 1 {
		t.Fatalf("ranking = %+v, want a with load 1", last.Ranking)
	}
}

func TestPickExcludesZeroWeightAndRejectsInvalidWeight(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, `{"files":[{"id":"a","weight":0},{"id":"b","weight":null}]}`)
	setQuota(t, "a", weekly(0.9, 24*time.Hour))
	setQuota(t, "b", weekly(0.1, 144*time.Hour))
	resp, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow)
	if errPick != nil || resp.AuthID != "b" {
		t.Fatalf("pick() = %+v, %v; want b (a has weight 0)", resp, errPick)
	}

	fakeWeights(t, `{"files":[{"id":"a","weight":-1},{"id":"b"}]}`)
	if _, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow); errPick == nil || !strings.Contains(errPick.Error(), "negative") {
		t.Fatalf("pick() error = %v, want negative weight error", errPick)
	}
}

func TestPickFailsWhenWeightsUnavailable(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, `{"files":[{"id":"a"}]}`)
	setQuota(t, "a", weekly(0.5, 24*time.Hour))
	setQuota(t, "b", weekly(0.5, 24*time.Hour))
	if _, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow); errPick == nil || !strings.Contains(errPick.Error(), "credential b is not in") {
		t.Fatalf("pick() error = %v, want missing credential error", errPick)
	}
}

// A config-synthesized openai-compatibility provider has no backing auth file: it is reported by
// host.auth.models but omitted from host.auth.list and the management weight list. The picker must
// still consider it instead of rejecting it as absent from the host credential list.
func TestPickIncludesSynthesizedCredentialMissingFromHostList(t *testing.T) {
	fakeHostSplit(t, []string{"claude-opus-4-8"}, noOther(t), []string{"a"}, []string{"a", "modal"})
	fakeWeights(t, `{"files":[{"id":"a"}]}`)
	setQuota(t, "a", weekly(0.1, 144*time.Hour))
	setQuota(t, "modal", weekly(0.9, 24*time.Hour))
	resp, errPick := pick(pickReq("", "a", "modal"), balanceConfig(), testNow)
	if errPick != nil {
		t.Fatalf("pick() error = %v, want success", errPick)
	}
	if resp.AuthID != "modal" {
		t.Fatalf("pick() = %+v, want modal (higher remaining quota)", resp)
	}
}

func TestPickFailsOnQuotaTelemetryError(t *testing.T) {
	fakeHost(t, []string{"claude-opus-4-8"}, noOther(t), "a", "b")
	fakeWeights(t, weightsAB)
	for _, id := range []string{"a", "b"} {
		quotaMu.Lock()
		quotaSnapshots[id] = credentialQuota{AuthID: id, FetchedAt: time.Now(), Error: "HTTP 500"}
		quotaMu.Unlock()
	}
	t.Cleanup(func() { quotaMu.Lock(); delete(quotaSnapshots, "a"); delete(quotaSnapshots, "b"); quotaMu.Unlock() })
	_, errPick := pick(pickReq("", "a", "b"), balanceConfig(), testNow)
	assertNoEligible(t, errPick, "a: quota error: HTTP 500")
}

func TestRankExcludesDisabledAndCoolingDown(t *testing.T) {
	resetHostState(t)
	fakeWeights(t, weightsAB)
	authWeightMu.Lock()
	authWeights = map[string]float64{"a": 1, "b": 1, "c": 1}
	authWeightsAt = testNow
	authWeightMu.Unlock()
	for _, id := range []string{"a", "b", "c"} {
		setQuota(t, id, weekly(0.5, 24*time.Hour))
	}
	auths := []hostAuth{
		{ID: "a", Disabled: true},
		{ID: "b", Unavailable: true, NextRetryAfter: testNow.Add(time.Minute)},
		{ID: "c", Unavailable: true, NextRetryAfter: testNow.Add(-time.Minute)},
	}
	stateMu.Lock()
	ranking := rankCredentials(balanceConfig(), auths, "m", testNow)
	stateMu.Unlock()
	if ranking[0].AuthID != "c" || ranking[0].Excluded != "" {
		t.Fatalf("ranking = %+v, want c eligible first", ranking)
	}
	if entry, _ := findRank(ranking, "a"); entry.Excluded != "credential disabled" {
		t.Fatalf("a = %+v, want disabled", entry)
	}
	if entry, _ := findRank(ranking, "b"); !strings.Contains(entry.Excluded, "unavailable until") {
		t.Fatalf("b = %+v, want cooling down", entry)
	}
}
