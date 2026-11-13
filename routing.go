package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// conversationFailure is one model's failure inside one conversation.
type conversationFailure struct {
	Kind    string    `json:"kind"`
	Reason  string    `json:"reason,omitempty"`
	AtBytes int       `json:"at_bytes,omitempty"`
	At      time.Time `json:"at"`
	// FirstRefusalHash is the sha256 of the first payload this model refused.
	// A byte-identical repeat is not new information and its notice is suppressed.
	FirstRefusalHash string `json:"first_refusal_hash,omitempty"`
	// FirstRefusalNotified records whether the switch notice for this hash was shown.
	FirstRefusalNotified bool `json:"first_refusal_notified,omitempty"`
}

// conversationState is the routing state of exactly one conversation (one
// transcript). It never merges state across parent/child or helper requests:
// conversationKey() guarantees that. All access is guarded by stateMu.
type conversationState struct {
	Key              string                          `json:"key"`
	Current          string                          `json:"current,omitempty"`
	Failures         map[string]*conversationFailure `json:"failures,omitempty"`
	Turns            int                             `json:"turns,omitempty"`
	LastPayloadBytes int                             `json:"last_payload_bytes,omitempty"`
	LastMessageCount int                             `json:"last_message_count,omitempty"`
	CacheWarm        bool                            `json:"cache_warm,omitempty"`
	LastSeen         time.Time                       `json:"last_seen"`
	BoundAt          time.Time                       `json:"bound_at"`
}

// skipReasonLocked returns why model should not be attempted for payload, or "".
// A nil receiver means the conversation has no state yet: nothing is skipped.
func (s *conversationState) skipReasonLocked(model string, payload []byte) string {
	if s == nil || len(s.Failures) == 0 {
		return ""
	}
	f, ok := s.Failures[model]
	if !ok || f == nil {
		return ""
	}
	switch f.Kind {
	case "no_tools", "not_found":
		return f.Reason
	case "no_vision":
		if payloadHasImage(payload) {
			return f.Reason
		}
		delete(s.Failures, model)
		return ""
	case "context_too_long":
		if f.AtBytes > 0 && len(payload) >= f.AtBytes {
			return f.Reason
		}
		delete(s.Failures, model)
		return ""
	case "refusal":
		// The refused content stays in the history until compaction resets this
		// conversation. Growing the conversation does not call the refused
		// model again.
		return f.Reason
	}
	return ""
}

// conversationCompactedLocked reports whether payload replaced a long
// transcript with a summary. A byte shrink alone is Claude Code clearing old
// tool results, not compaction: the message list must collapse too.
func (s *conversationState) conversationCompactedLocked(payload []byte) bool {
	if s.LastPayloadBytes < compactionMinPrevBytes || s.LastMessageCount < compactionMinMessages || len(payload) == 0 {
		return false
	}
	if float64(len(payload)) >= float64(s.LastPayloadBytes)*compactionShrinkRatio {
		return false
	}
	messageCount := payloadMessageCount(payload)
	return messageCount > 0 && messageCount*2 <= s.LastMessageCount
}

func payloadMessageCount(payload []byte) int {
	var body struct {
		Messages []json.RawMessage `json:"messages"`
		Request  struct {
			Messages []json.RawMessage `json:"messages"`
		} `json:"request"`
	}
	if len(payload) == 0 {
		return 0
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		panic(fmt.Errorf("decode group history payload: %w", err))
	}
	if n := len(body.Messages); n > 0 {
		return n
	}
	return len(body.Request.Messages)
}

// groupStates maps conversationKey()+"\x00"+groupID to its routing state.
var groupStates = make(map[string]*conversationState)

func ensureConversationLocked(key, groupID string, now time.Time) *conversationState {
	full := key + "\x00" + groupID
	state, ok := groupStates[full]
	if !ok || state == nil {
		state = &conversationState{
			Key:      key,
			Failures: make(map[string]*conversationFailure),
			LastSeen: now,
		}
		groupStates[full] = state
		return state
	}
	if state.Failures == nil {
		state.Failures = make(map[string]*conversationFailure)
	}
	return state
}

// logRouting records a routing transition in the decision ring buffer.
func logRouting(group modelGroup, key, event, detail string) {
	stateMu.Lock()
	recordDecision(decision{Time: time.Now(), Kind: "route", Model: group.ID, Session: key, AuthID: event, Reason: detail, Version: pluginVersion})
	stateMu.Unlock()
}

// logRoutingLocked records a routing transition; callers hold stateMu.
func logRoutingLocked(group modelGroup, key, event, detail string) {
	recordDecision(decision{Time: time.Now(), Kind: "route", Model: group.ID, Session: key, AuthID: event, Reason: detail, Version: pluginVersion})
}

const (
	modelScoreTolerance   = 3.0
	modelScoreTemperature = 1.0
)

type modelScore struct {
	Model       string  `json:"model"`
	Quality     float64 `json:"quality"`
	Cost        float64 `json:"cost"`
	Score       float64 `json:"score"`
	Probability float64 `json:"probability"`
	Excluded    string  `json:"excluded,omitempty"`
}

func scoreModels(group modelGroup) []modelScore {
	scores := make([]modelScore, 0, len(group.Models))
	for _, model := range group.Models {
		if model.Disabled {
			continue
		}
		var score float64
		switch group.Mode {
		case groupModeQuality:
			score = 0.8*model.Quality - 0.2*model.Cost
		case groupModeCost:
			score = 0.2*model.Quality - 0.8*model.Cost
		default:
			panic(fmt.Errorf("group %s has invalid mode %q", group.ID, group.Mode))
		}
		scores = append(scores, modelScore{Model: model.ID, Quality: model.Quality, Cost: model.Cost, Score: score})
	}
	return scores
}

// Selection only happens at conversation boundaries or when the pinned model is unusable.
func planConversation(cfg pluginConfig, session string, group modelGroup, payload []byte, now time.Time) groupRoutingPlan {
	plan := groupRoutingPlan{Scores: scoreModels(group)}
	stateMu.Lock()
	var state *conversationState
	if session != "" {
		state = groupStates[session+"\x00"+group.ID]
	}
	if state != nil {
		if state.conversationCompactedLocked(payload) {
			beforeBytes, beforeMessages := state.LastPayloadBytes, state.LastMessageCount
			plan.Compacted = true
			state.Current = ""
			state.Failures = make(map[string]*conversationFailure)
			state.CacheWarm = false
			state.LastPayloadBytes = len(payload)
			state.LastMessageCount = payloadMessageCount(payload)
			savePersistedSessionsLocked()
			logRoutingLocked(group, session, "compaction", fmt.Sprintf("payload %d to %d bytes, messages %d to %d", beforeBytes, len(payload), beforeMessages, state.LastMessageCount))
		}
		plan.PrevModel = state.Current
	}
	active := ""
	if state != nil {
		active = state.Current
	}
	for i := range plan.Scores {
		plan.Scores[i].Excluded = state.skipReasonLocked(plan.Scores[i].Model, payload)
	}
	stateMu.Unlock()

	for i := range plan.Scores {
		candidate := &plan.Scores[i]
		if candidate.Excluded == "" {
			reason, err := skipReason(cfg, candidate.Model, now)
			if err != nil {
				plan.Err = err
				return plan
			}
			candidate.Excluded = reason
		}
		if candidate.Excluded != "" {
			plan.Skipped = append(plan.Skipped, groupAttempt{Model: candidate.Model, Result: "skipped: " + candidate.Excluded})
		} else if candidate.Model == active {
			plan.Sticky = true
		}
	}
	setSelectionProbabilities(plan.Scores, active, plan.Sticky)
	if session != "" {
		stateMu.Lock()
		reason := "weighted selection among close scores"
		if plan.Sticky {
			reason = "conversation pinned to " + active
		}
		recordDecision(decision{Time: now, Kind: "route", Model: group.ID, Session: session, AuthID: "selection", Reason: reason, Version: pluginVersion, Mode: group.Mode, ModelScores: append([]modelScore(nil), plan.Scores...)})
		stateMu.Unlock()
	}
	return plan
}

func setSelectionProbabilities(scores []modelScore, active string, sticky bool) {
	best := math.Inf(-1)
	for i := range scores {
		scores[i].Probability = 0
		if scores[i].Excluded == "" && scores[i].Score > best {
			best = scores[i].Score
		}
	}
	total := 0.0
	for i := range scores {
		if scores[i].Excluded != "" {
			continue
		}
		if sticky {
			if scores[i].Model == active {
				scores[i].Probability = 1
			}
		} else if best-scores[i].Score <= modelScoreTolerance {
			scores[i].Probability = math.Exp((scores[i].Score - best) / modelScoreTemperature)
			total += scores[i].Probability
		}
	}
	if !sticky && total > 0 {
		for i := range scores {
			scores[i].Probability /= total
		}
	}
}

// Each unsuccessful attempt removes one candidate before recalculating the shortlist.
func (p *groupRoutingPlan) nextModel(draw float64) (string, bool) {
	if p.Err != nil {
		return "", false
	}
	cumulative := 0.0
	last := -1
	for i := range p.Scores {
		if p.Scores[i].Probability <= 0 {
			continue
		}
		last = i
		cumulative += p.Scores[i].Probability
		if draw < cumulative {
			last = i
			break
		}
	}
	if last < 0 {
		return "", false
	}
	p.SelectedScores = append([]modelScore(nil), p.Scores...)
	model := p.Scores[last].Model
	p.Scores[last].Excluded = "attempted"
	p.Sticky = false
	setSelectionProbabilities(p.Scores, "", false)
	return model, true
}

// recordConversationFailure records how a model failed within a conversation
// so subsequent turns apply the right skip. Caller does not hold stateMu.
func recordConversationFailure(session, groupID, model, rawDetail string, payload []byte, now time.Time) {
	payloadBytes := len(payload)
	if summarizeAttemptReason(rawDetail) == "insufficient quota" {
		noteQuotaDenied(model, now)
	}
	if session == "" || groupID == "" || model == "" {
		return
	}
	kind := classifyAttemptFailure(rawDetail)
	stateMu.Lock()
	state := ensureConversationLocked(session, groupID, now)
	f, ok := state.Failures[model]
	if !ok || f == nil {
		f = &conversationFailure{}
		state.Failures[model] = f
	}
	if kind == "refusal" {
		hash := refusalPayloadHash(payload)
		switch {
		case f.FirstRefusalHash == "" || f.FirstRefusalHash != hash:
			f.FirstRefusalHash = hash
			f.FirstRefusalNotified = true
		default:
			f.FirstRefusalNotified = false
		}
	}
	f.Kind = kind
	f.Reason = summarizeAttemptReason(rawDetail)
	f.AtBytes = payloadBytes
	f.At = now
	savePersistedSessionsLocked()
	stateMu.Unlock()
	logRouting(modelGroup{ID: groupID}, session, "failure", model+" "+kind)
}

// suppressedRefusals returns the set of models whose latest refusal is a
// byte-identical repeat of an already-notified refusal. The flag is consumed:
// a third identical refusal stays suppressed via the hash, a changed payload
// re-notifies once.
func suppressedRefusals(session, groupID string, models []string) map[string]bool {
	out := make(map[string]bool)
	if session == "" || groupID == "" {
		return out
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	state, ok := groupStates[session+"\x00"+groupID]
	if !ok || state == nil {
		return out
	}
	for _, model := range models {
		f, ok := state.Failures[model]
		if !ok || f == nil {
			continue
		}
		if f.Kind == "refusal" && f.FirstRefusalHash != "" && !f.FirstRefusalNotified {
			f.FirstRefusalNotified = true
			out[model] = true
		}
	}
	return out
}

// recordServed records the model that served a group request and returns the
// model that served the previous turn in this conversation ("" if none).
func recordServed(cfg pluginConfig, session, groupID, served, prevFromLookup string, payload []byte, now time.Time) string {
	if session == "" {
		return prevFromLookup
	}
	stateMu.Lock()
	state := ensureConversationLocked(session, groupID, now)
	prev := prevFromLookup
	if prev == "" {
		prev = state.Current
	}
	if state.Current != served || state.BoundAt.IsZero() {
		state.BoundAt = now
	}
	state.Current = served
	state.LastSeen = now
	state.Turns++
	if len(payload) > 0 {
		state.LastPayloadBytes = len(payload)
		state.LastMessageCount = payloadMessageCount(payload)
	}
	delete(state.Failures, served)
	savePersistedSessionsLocked()
	stateMu.Unlock()
	return prev
}

// A mid-stream refusal is already visible to the client; the continuation selects a fresh eligible model.
func advanceConversationOnRefusal(session string, group modelGroup, failedModel string, now time.Time) {
	if session == "" {
		return
	}
	stateMu.Lock()
	state := ensureConversationLocked(session, group.ID, now)
	state.Failures[failedModel] = &conversationFailure{Kind: "refusal", Reason: "refusal: stream", AtBytes: state.LastPayloadBytes, At: now}
	state.LastSeen = now
	savePersistedSessionsLocked()
	logRoutingLocked(group, session, "stream-refusal", failedModel+" refused; continuation reselects")
	stateMu.Unlock()
}

// observeConversationUsage updates cache telemetry from a streamed chunk.
func observeConversationUsage(session, groupID string, chunk []byte) {
	if session == "" || groupID == "" || len(chunk) == 0 {
		return
	}
	if !bytes.Contains(chunk, []byte(`"usage"`)) {
		return
	}
	trimmed := bytes.TrimSpace(chunk)
	var inTok, crTok, ccTok int
	found := false
	if len(trimmed) > 0 && trimmed[0] == '{' {
		inTok, crTok, ccTok, found = extractUsageFromJSON(trimmed)
	} else {
		for _, line := range bytes.Split(chunk, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if len(data) == 0 || data[0] != '{' || !bytes.Contains(data, []byte(`"usage"`)) {
				continue
			}
			if in, cr, cc, ok := extractUsageFromJSON(data); ok {
				if in > 0 {
					inTok = in
				}
				if cr > 0 {
					crTok = cr
				}
				if cc > 0 {
					ccTok = cc
				}
				found = true
			}
		}
	}
	if !found {
		return
	}
	stateMu.Lock()
	if state, ok := groupStates[session+"\x00"+groupID]; ok && state != nil {
		if inTok > 0 || crTok > 0 {
			state.CacheWarm = crTok > 0 || ccTok > 0
		}
	}
	stateMu.Unlock()
}

// conversationKey extracts the conversation identity for a group executor
// request from host metadata, the request payload (Claude metadata.user_id or
// OpenAI/Codex session fields), or headers. A parent identity describes
// ancestry, not the transcript whose routing state may be reset.
func conversationKey(req executorRequest) string {
	key := sessionKey(req.Metadata)
	var body struct {
		SessionID      string `json:"session_id"`
		ConversationID string `json:"conversation_id"`
		PromptCacheKey string `json:"prompt_cache_key"`
		Metadata       struct {
			UserID     string `json:"user_id"`
			AgentID    string `json:"agent_id"`
			SubagentID string `json:"subagent_id"`
		} `json:"metadata"`
		Request struct {
			Metadata struct {
				UserID     string `json:"user_id"`
				AgentID    string `json:"agent_id"`
				SubagentID string `json:"subagent_id"`
			} `json:"metadata"`
		} `json:"request"`
	}
	var agentID string
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &body); err != nil {
			panic(fmt.Errorf("decode group session payload: %w", err))
		}
		userID := strings.TrimSpace(body.Metadata.UserID)
		if userID == "" {
			userID = strings.TrimSpace(body.Request.Metadata.UserID)
		}
		for _, candidate := range []string{body.Metadata.AgentID, body.Metadata.SubagentID, body.Request.Metadata.AgentID, body.Request.Metadata.SubagentID} {
			if trimmed := strings.TrimSpace(candidate); trimmed != "" {
				agentID = trimmed
				break
			}
		}
		if strings.HasPrefix(userID, "{") {
			var parsed struct {
				SessionID  string `json:"session_id"`
				AgentID    string `json:"agent_id"`
				SubagentID string `json:"subagent_id"`
			}
			if err := json.Unmarshal([]byte(userID), &parsed); err != nil {
				panic(fmt.Errorf("decode Claude session metadata: %w", err))
			}
			if sid := strings.TrimSpace(parsed.SessionID); sid != "" {
				key = "claude:" + sid
			}
			for _, candidate := range []string{parsed.AgentID, parsed.SubagentID} {
				if trimmed := strings.TrimSpace(candidate); trimmed != "" {
					agentID = trimmed
					break
				}
			}
		} else if idx := strings.LastIndex(userID, "_session_"); idx != -1 {
			if sid := strings.TrimSpace(userID[idx+len("_session_"):]); sid != "" {
				key = "claude:" + sid
			}
		}
		if key == "" {
			for _, candidate := range []string{body.SessionID, body.ConversationID, body.PromptCacheKey} {
				if trimmed := strings.TrimSpace(candidate); trimmed != "" {
					key = "session:" + trimmed
					break
				}
			}
		}
	}
	if key == "" {
		for _, header := range []string{"Session_id", "X-Session-Id", "Conversation_id", "X-Claude-Code-Session-Id"} {
			if val := strings.TrimSpace(http.Header(req.Headers).Get(header)); val != "" {
				key = "header:" + val
				break
			}
		}
	}
	if key == "" {
		return ""
	}
	if agentID != "" {
		key += "\x00agent:" + agentID
	}
	if isAuxiliaryRequest(req.Payload) {
		key += "\x00auxiliary"
	}
	return key
}

type groupRoutingPlan struct {
	Scores         []modelScore
	SelectedScores []modelScore
	Skipped        []groupAttempt
	PrevModel      string
	Compacted      bool
	Sticky         bool
	Err            error
}

func payloadHasImage(payload []byte) bool {
	return bytes.Contains(payload, []byte(`"type":"image"`)) ||
		bytes.Contains(payload, []byte(`"type": "image"`)) ||
		bytes.Contains(payload, []byte(`"image_url"`))
}

func classifyAttemptFailure(rawDetail string) string {
	summary := summarizeAttemptReason(rawDetail)
	switch summary {
	case "no tools":
		return "no_tools"
	case "not found":
		return "not_found"
	case "no vision":
		return "no_vision"
	case "context too long":
		return "context_too_long"
	case "empty response", "refusal":
		return "refusal"
	}
	if strings.HasPrefix(summary, "refusal:") {
		return "refusal"
	}
	return "transient"
}

// isAuxiliaryRequest reports whether the request is a background helper call (such as Claude Code's
// away_summary recap, prompt_suggestion, session rename, or agent_summary) where injecting a
// human-facing router banner would corrupt the caller's parsed output.
func isAuxiliaryRequest(payload []byte) bool {
	for _, marker := range []string{
		"The user stepped away and is coming back. Recap in under",
		"Reply with ONLY the suggestion, no quotes or explanation.",
		`Return JSON with a "name" field.`,
		"most recent action in 3-5 words using present tense (-ing).",
		"Never consult the advisor tool.",
		"Your task is to create a detailed summary of the conversation",
	} {
		if bytes.Contains(payload, []byte(marker)) {
			return true
		}
	}
	return false
}
func extractUsageFromJSON(raw []byte) (inputTok, cacheReadTok, cacheCreateTok int, found bool) {
	var env struct {
		Usage *struct {
			InputTokens              int `json:"input_tokens"`
			PromptTokens             int `json:"prompt_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			PromptTokensDetails      *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			InputTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
		Message *struct {
			Usage *struct {
				InputTokens              int `json:"input_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Response *struct {
			Usage *struct {
				InputTokens        int `json:"input_tokens"`
				InputTokensDetails *struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"input_tokens_details"`
			} `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return 0, 0, 0, false
	}
	if u := env.Usage; u != nil {
		in := u.InputTokens
		if in == 0 {
			in = u.PromptTokens
		}
		cr := u.CacheReadInputTokens
		if cr == 0 && u.PromptTokensDetails != nil {
			cr = u.PromptTokensDetails.CachedTokens
		}
		if cr == 0 && u.InputTokensDetails != nil {
			cr = u.InputTokensDetails.CachedTokens
		}
		if in > 0 || cr > 0 || u.CacheCreationInputTokens > 0 {
			return in, cr, u.CacheCreationInputTokens, true
		}
	}
	if env.Message != nil && env.Message.Usage != nil {
		u := env.Message.Usage
		if u.InputTokens > 0 || u.CacheReadInputTokens > 0 || u.CacheCreationInputTokens > 0 {
			return u.InputTokens, u.CacheReadInputTokens, u.CacheCreationInputTokens, true
		}
	}
	if env.Response != nil && env.Response.Usage != nil {
		u := env.Response.Usage
		cr := 0
		if u.InputTokensDetails != nil {
			cr = u.InputTokensDetails.CachedTokens
		}
		if u.InputTokens > 0 || cr > 0 {
			return u.InputTokens, cr, 0, true
		}
	}
	return 0, 0, 0, false
}

// conversationBindingView projects a conversationState for the sessionBinding
// consumers (UI, persistence migration).
func conversationBindingView(s *conversationState) sessionBinding {
	if s == nil {
		return sessionBinding{}
	}
	view := sessionBinding{
		Session:          s.Key,
		AuthID:           s.Current,
		Provider:         groupProvider,
		LastSeen:         s.LastSeen,
		BoundAt:          s.BoundAt,
		Turns:            s.Turns,
		LastPayloadBytes: s.LastPayloadBytes,
		LastMessageCount: s.LastMessageCount,
		CacheWarm:        s.CacheWarm,
		ModelStates:      make(map[string]*modelSessionState, len(s.Failures)),
	}
	for model, f := range s.Failures {
		if f != nil {
			view.ModelStates[model] = &modelSessionState{
				FailureKind:   f.Kind,
				Reason:        f.Reason,
				FailedAtBytes: f.AtBytes,
				FailedAt:      f.At,
			}
		}
	}
	return view
}

// trailEntry is one persisted routing event for a conversation.
type trailEntry struct {
	Time        time.Time      `json:"time"`
	Version     string         `json:"version"`
	Mode        string         `json:"mode,omitempty"`
	ModelScores []modelScore   `json:"model_scores,omitempty"`
	Attempts    []groupAttempt `json:"attempts,omitempty"`
	Event       string         `json:"event"`
	Model       string         `json:"model"`
	Reason      string         `json:"reason"`
}

// buildConversationTrail returns the full decision trail for one conversation
// key (as recorded in the decision ring buffer), newest first. Key is the
// conversation key (optionally group-qualified with \x00groupID); the empty
// key returns every decision.
func buildConversationTrail(key string) []trailEntry {
	stateMu.Lock()
	defer stateMu.Unlock()
	out := make([]trailEntry, 0, len(decisions))
	for i := len(decisions) - 1; i >= 0; i-- {
		d := decisions[i]
		if key != "" && d.Session != key && !strings.HasPrefix(d.Session, key+"\x00") {
			continue
		}
		out = append(out, trailEntry{Time: d.Time, Version: d.Version, Event: d.AuthID, Model: d.Model, Reason: d.Reason, Mode: d.Mode, ModelScores: d.ModelScores, Attempts: d.Attempts})
	}
	return out
}

// drainConversationState removes one conversation's routing state without
// restarting the proxy. An empty groupID drains every group for the key.
func drainConversationState(key, groupID string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if key == "" {
		return
	}
	if groupID != "" {
		delete(groupStates, key+"\x00"+groupID)
	} else {
		prefix := key + "\x00"
		for full := range groupStates {
			if strings.HasPrefix(full, prefix) {
				delete(groupStates, full)
			}
		}
	}
	savePersistedSessionsLocked()
}

// routingMetrics aggregates routing decisions for the UI chart row.
type routingMetrics struct {
	RefusalsByModelAndCategory map[string]int `json:"refusals_by_model_category"`
	FallbackRate               float64        `json:"fallback_rate"`
	CompactionResets           int            `json:"compaction_resets"`
	SuppressedNotices          int            `json:"suppressed_notices"`
	TurnsOnFallback            int            `json:"turns_on_fallback"`
}

// computeRoutingMetrics aggregates live failures and retained routing decisions.
func computeRoutingMetrics() routingMetrics {
	stateMu.Lock()
	defer stateMu.Unlock()
	m := routingMetrics{RefusalsByModelAndCategory: make(map[string]int)}
	for _, state := range groupStates {
		for model, f := range state.Failures {
			if f == nil {
				continue
			}
			if f.Kind == "refusal" {
				category := f.Reason
				if category == "" {
					category = "refusal"
				}
				m.RefusalsByModelAndCategory[fmt.Sprintf("%s (%s)", model, category)]++
			}
		}
	}
	served, failed := 0, 0
	for _, d := range decisions {
		switch d.Kind {
		case "route":
			switch d.AuthID {
			case "compaction":
				m.CompactionResets++
			case "failure":
				failed++
			}
		case "group":
			if d.AuthID != "" {
				served++
				for _, attempt := range d.Attempts {
					if strings.HasPrefix(attempt.Result, "failed:") {
						m.TurnsOnFallback++
						break
					}
				}
			}
		}
	}
	if total := served + failed; total > 0 {
		m.FallbackRate = float64(failed) / float64(total)
	}
	return m
}

// refusalPayloadHash returns a stable digest of the request payload, used to
// detect a byte-identical repeat refusal.
func refusalPayloadHash(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
