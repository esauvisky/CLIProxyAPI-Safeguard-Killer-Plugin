package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"time"
)

// conversationFailure is one model's failure inside one conversation.
type conversationFailure struct {
	Kind    string    `json:"kind"`
	Reason  string    `json:"reason,omitempty"`
	AtBytes int       `json:"at_bytes,omitempty"`
	At      time.Time `json:"at"`
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
	TipShown         bool                            `json:"tip_shown,omitempty"`
	CacheWarm        bool                            `json:"cache_warm,omitempty"`
	LastSeen         time.Time                       `json:"last_seen"`
	IdleExpiresAt    time.Time                       `json:"idle_expires_at"`
}

// failure returns the model's failure entry, or nil.
func (s *conversationState) failure(model string) *conversationFailure {
	if s == nil {
		return nil
	}
	return s.Failures[model]
}

// skipReasonLocked returns why model should not be attempted for payload, or "".
// A nil receiver means the conversation has no state yet: nothing is skipped.
func (s *conversationState) skipReasonLocked(model string, payload []byte, now time.Time) string {
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
		if s.Current != "" {
			return "sticky to " + s.Current + " (cache warm)"
		}
		return f.Reason
	case "transient":
		if s.Current != "" && s.Current != model && now.Sub(f.At) < transientErrorCooldown {
			return "sticky to " + s.Current + " (cache warm)"
		}
		return ""
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

// planConversation computes the parallel probe list and sequential fallback
// order for one group turn. Compaction resets the conversation before
// planning; every reset is logged with its reason.
func planConversation(cfg pluginConfig, session string, group modelGroup, payload []byte, now time.Time) groupRoutingPlan {
	var plan groupRoutingPlan
	if len(group.Models) == 0 {
		return plan
	}
	strategy := group.effectiveStrategy()
	stickyEnabled := cfg.IdleMinutes > 0
	var activeModel string
	cacheStickActive := false

	if session != "" {
		key := session + "\x00" + group.ID
		stateMu.Lock()
		state, ok := groupStates[key]
		if ok && state != nil {
			plan.PrevModel = state.Current
			if state.conversationCompactedLocked(payload) {
				plan.Compacted = true
				state.Current = ""
				state.Failures = make(map[string]*conversationFailure)
				state.TipShown = false
				state.CacheWarm = false
				state.LastPayloadBytes = len(payload)
				state.LastMessageCount = payloadMessageCount(payload)
				savePersistedSessionsLocked()
				logRoutingLocked(group, session, "compaction", fmt.Sprintf("payload %d to %d bytes, messages %d to %d", state.LastPayloadBytes, len(payload), state.LastMessageCount, payloadMessageCount(payload)))
			}
			if stickyEnabled && state.Current != "" {
				activeModel = state.Current
				cacheStickActive = state.CacheWarm || now.Before(state.IdleExpiresAt)
			}
		}
		stateMu.Unlock()
	}

	stateMu.Lock()
	var state *conversationState
	if session != "" {
		state = groupStates[session+"\x00"+group.ID]
	}
	if strategy == groupStrategyRace {
		if activeModel != "" && cacheStickActive && state.skipReasonLocked(activeModel, payload, now) == "" {
			plan.Sequential = append(plan.Sequential, activeModel)
			for _, m := range group.Models {
				if m == activeModel {
					continue
				}
				if reason := state.skipReasonLocked(m, payload, now); reason != "" {
					plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
					continue
				}
				plan.Sequential = append(plan.Sequential, m)
			}
			stateMu.Unlock()
			return plan
		}
		for _, m := range group.Models {
			if reason := state.skipReasonLocked(m, payload, now); reason != "" {
				plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
				continue
			}
			plan.Parallel = append(plan.Parallel, m)
		}
		stateMu.Unlock()
		return plan
	}

	activeIdx := -1
	if activeModel != "" {
		for i, m := range group.Models {
			if m == activeModel {
				activeIdx = i
				break
			}
		}
	}

	if activeIdx > 0 && (strategy == groupStrategyUpgrade || strategy == groupStrategyStick) {
		var probeModels []string
		for _, m := range group.Models[:activeIdx] {
			if strategy == groupStrategyStick {
				plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: sticky to " + activeModel + " (cache warm)"})
				continue
			}
			reason := state.skipReasonLocked(m, payload, now)
			if reason != "" {
				plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
				continue
			}
			// If m has no recorded failure, only probe it once the active
			// binding's idle window expires so normal consecutive turns stay
			// pinned without racing.
			if state.failure(m) == nil && cacheStickActive {
				plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: sticky to " + activeModel + " (cache warm)"})
				continue
			}
			probeModels = append(probeModels, m)
		}
		if len(probeModels) > 0 {
			plan.Parallel = append(plan.Parallel, probeModels...)
			plan.Parallel = append(plan.Parallel, activeModel)
			for _, m := range group.Models[activeIdx+1:] {
				if reason := state.skipReasonLocked(m, payload, now); reason != "" {
					plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
					continue
				}
				plan.Sequential = append(plan.Sequential, m)
			}
			stateMu.Unlock()
			return plan
		}
		for _, m := range group.Models[activeIdx:] {
			if reason := state.skipReasonLocked(m, payload, now); reason != "" {
				plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
				continue
			}
			plan.Sequential = append(plan.Sequential, m)
		}
		// Keep earlier models at the tail only when nothing blocks retry.
		for _, m := range group.Models[:activeIdx] {
			if state.skipReasonLocked(m, payload, now) == "" {
				plan.Sequential = append(plan.Sequential, m)
			}
		}
		stateMu.Unlock()
		return plan
	}

	var eligible []string
	for _, m := range group.Models {
		if reason := state.skipReasonLocked(m, payload, now); reason != "" {
			plan.Skipped = append(plan.Skipped, groupAttempt{Model: m, Result: "skipped: " + reason})
			continue
		}
		eligible = append(eligible, m)
	}
	stateMu.Unlock()

	if activeIdx >= 0 && cacheStickActive && containsString(eligible, activeModel) && (strategy == groupStrategyQuota || strategy == groupStrategyRandom) {
		var rest []string
		for _, m := range eligible {
			if m != activeModel {
				rest = append(rest, m)
			}
		}
		orderedRest := orderByStrategy(cfg, rest, strategy, now)
		plan.Sequential = append(plan.Sequential, activeModel)
		plan.Sequential = append(plan.Sequential, orderedRest...)
		return plan
	}

	plan.Sequential = orderByStrategy(cfg, eligible, strategy, now)
	return plan
}

// recordConversationFailure records how a model failed within a conversation
// so subsequent turns apply the right skip. Caller does not hold stateMu.
func recordConversationFailure(session, groupID, model, rawDetail string, payloadBytes int, now time.Time) {
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
	f.Kind = kind
	f.Reason = summarizeAttemptReason(rawDetail)
	f.AtBytes = payloadBytes
	f.At = now
	savePersistedSessionsLocked()
	stateMu.Unlock()
	logRouting(modelGroup{ID: groupID}, session, "failure", model+" "+kind)
}

// promoteProbedModel promotes a probed higher-priority model that finished
// prefetch without refusing after a faster fallback model won the parallel
// race. Failure records are kept: a model that refused before stays refused.
func promoteProbedModel(cfg pluginConfig, session, groupID, model string, now time.Time) {
	if session == "" || groupID == "" || model == "" {
		return
	}
	stateMu.Lock()
	state := ensureConversationLocked(session, groupID, now)
	prev := state.Current
	state.Current = model
	state.LastSeen = now
	state.IdleExpiresAt = now.Add(time.Duration(cfg.IdleMinutes) * time.Minute)
	savePersistedSessionsLocked()
	stateMu.Unlock()
	logRouting(modelGroup{ID: groupID}, session, "promote", prev+" -> "+model)
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
	state.Current = served
	state.LastSeen = now
	state.IdleExpiresAt = now.Add(time.Duration(cfg.IdleMinutes) * time.Minute)
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

// advanceConversationOnRefusal moves the conversation's current model to the
// model after failedModel when a refusal happens mid-stream (after the
// prefetch buffer was already flushed), so the client's immediate
// continuation retry starts on the next model in the group. The failed model's
// refusal record is kept.
func advanceConversationOnRefusal(session string, group modelGroup, failedModel string, now time.Time) {
	if session == "" || len(group.Models) < 2 {
		return
	}
	nextIdx := -1
	for i, m := range group.Models {
		if m == failedModel && i+1 < len(group.Models) {
			nextIdx = i + 1
			break
		}
	}
	if nextIdx == -1 {
		return
	}
	stateMu.Lock()
	state := ensureConversationLocked(session, group.ID, now)
	f, ok := state.Failures[failedModel]
	if !ok || f == nil {
		f = &conversationFailure{}
		state.Failures[failedModel] = f
	}
	f.Kind = "refusal"
	f.Reason = "refusal: stream"
	f.AtBytes = state.LastPayloadBytes
	f.At = now
	state.Current = group.Models[nextIdx]
	state.LastSeen = now
	state.IdleExpiresAt = now.Add(groupCacheTTL)
	savePersistedSessionsLocked()
	stateMu.Unlock()
	logRouting(group, session, "stream-refusal", failedModel+" -> "+group.Models[nextIdx])
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

// compactionTipForSession returns one compaction tip when a large
// conversation (>= 128 KB) first lands on a fallback because the primary
// refused. Later turns stay quiet until compaction resets the tip state.
func compactionTipForSession(cfg pluginConfig, session string, group modelGroup, attempts []groupAttempt, served string, payloadBytes int) string {
	if !cfg.Features.ClientFallbackNotices || session == "" || len(group.Models) == 0 || served == group.Models[0] || payloadBytes < dilutionBaseBytes {
		return ""
	}
	strategy := group.effectiveStrategy()
	if strategy != groupStrategyUpgrade && strategy != groupStrategyStick {
		return ""
	}
	primary := group.Models[0]
	stateMu.Lock()
	defer stateMu.Unlock()
	state, ok := groupStates[session+"\x00"+group.ID]
	if !ok || state == nil || state.TipShown {
		return ""
	}
	refused := false
	if f, ok := state.Failures[primary]; ok && f != nil && f.Kind == "refusal" {
		refused = true
	}
	if !refused {
		for _, a := range attempts {
			if a.Model == primary && strings.HasPrefix(a.Result, "failed: ") && classifyAttemptFailure(strings.TrimPrefix(a.Result, "failed: ")) == "refusal" {
				refused = true
				break
			}
		}
	}
	if !refused {
		return ""
	}
	state.TipShown = true
	savePersistedSessionsLocked()
	logRoutingLocked(group, session, "tip", "primary "+primary+" refused; /compact retries")
	return fmt.Sprintf("💡 Tip: compact history (`/compact`) if you want to retry this session with `%s`", primary)
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

// groupRoutingPlan describes which models to race in parallel and which to try sequentially.
type groupRoutingPlan struct {
	Parallel   []string
	Sequential []string
	Skipped    []groupAttempt
	PrevModel  string
	Compacted  bool
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
func orderByStrategy(cfg pluginConfig, models []string, strategy string, now time.Time) []string {
	if len(models) <= 1 {
		return append([]string(nil), models...)
	}
	switch strategy {
	case groupStrategyRandom:
		out := append([]string(nil), models...)
		rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	case groupStrategyQuota:
		return orderByQuotaWeightedRandom(cfg, models, now)
	default:
		return append([]string(nil), models...)
	}
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

// hours_to_reset), so usage spreads across providers proportional to available quota per hour.
func orderByQuotaWeightedRandom(cfg pluginConfig, models []string, now time.Time) []string {
	weights := make([]float64, len(models))
	var positiveRates []float64
	snapshot, errHost := hostState(now)
	if errHost == nil && cfg.ManagementKey != "" {
		ensureQuotaFresh(cfg.ManagementKey, snapshot.auths)
		for i, model := range models {
			bestRate := 0.0
			sawCred := false
			allExhausted := true
			for _, auth := range snapshot.auths {
				if auth.Disabled || !containsString(snapshot.models[auth.ID], model) {
					continue
				}
				sawCred = true
				entry := rankEntry{AuthID: auth.ID, Provider: auth.Provider}
				rateCredential(&entry, model, cfg.MinRemaining, now)
				if entry.Excluded == "" && entry.Rate > bestRate {
					bestRate = entry.Rate
					allExhausted = false
				} else if !strings.Contains(entry.Excluded, "% left") {
					allExhausted = false
				}
			}
			if bestRate > 0 {
				weights[i] = bestRate
				positiveRates = append(positiveRates, bestRate)
			} else if sawCred && allExhausted {
				weights[i] = 1e-9
			}
		}
	}
	fallbackWeight := 1.0
	if len(positiveRates) > 0 {
		sum := 0.0
		for _, r := range positiveRates {
			sum += r
		}
		fallbackWeight = sum / float64(len(positiveRates))
	}
	type scoredModel struct {
		model string
		score float64
	}
	scored := make([]scoredModel, len(models))
	for i, m := range models {
		w := weights[i]
		if w <= 0 {
			w = fallbackWeight
		}
		u := rand.Float64()
		if u <= 1e-12 {
			u = 1e-12
		}
		// Efraimidis-Spirakis key u^(1/w); higher key (log(u)/w closer to 0) wins.
		scored[i] = scoredModel{model: m, score: math.Log(u) / w}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	out := make([]string, len(models))
	for i, s := range scored {
		out[i] = s.model
	}
	return out
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
		IdleExpiresAt:    s.IdleExpiresAt,
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

// conversationCandidateOrder returns the model order to try for a group request, any initial sticky-skip
// attempt records, and the model that served the previous turn in this conversation (if any).
func conversationCandidateOrder(cfg pluginConfig, session string, group modelGroup, now time.Time) (order []string, skipped []groupAttempt, prevModel string) {
	plan := planConversation(cfg, session, group, nil, now)
	order = make([]string, 0, len(plan.Parallel)+len(plan.Sequential))
	order = append(order, plan.Parallel...)
	order = append(order, plan.Sequential...)
	return order, plan.Skipped, plan.PrevModel
}
