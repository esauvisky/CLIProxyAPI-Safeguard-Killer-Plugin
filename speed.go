package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Measured output speeds map onto the rating scale logarithmically: 10 tok/s or less is 0,
	// 500 tok/s or more is 100. This is a throughput scale, not an AA benchmark.
	speedSlowTokensPerSec = 10.0
	speedFastTokensPerSec = 500.0
	// Models without samples start neutral, so a new speed group still ranks by quality.
	speedUnmeasuredRating = 50.0
	// Each completed response moves the per-model EWMA by a quarter of the new sample.
	speedSampleWeight = 0.25
	// First-token latency above 3s starts penalizing speed rating, up to 20 points at 23s+.
	speedFastFirstTokenSec  = 3.0
	speedSlowFirstTokenSec  = 23.0
	speedMaxFirstTokenPenal = 20.0
	// Quality mode subtracts up to qualityLatencyMaxPenalty points from a model whose measured
	// first-token latency exceeds qualityLatencyFreeSec, reaching the full penalty at
	// qualityLatencyFullSec, so a model that makes every turn wait a minute stops tying a fast one.
	qualityLatencyFreeSec    = 10.0
	qualityLatencyFullSec    = 70.0
	qualityLatencyMaxPenalty = 10.0
	// Reliability penalties subtract up to reliabilityMaxPenalty quality points from a model whose
	// refusal, empty-response, or loop rate reaches reliabilityFullPenaltyRate. A refusal counts
	// fully; a filter or cyber refusal counts half, because it names the prompt rather than the model.
	reliabilityMaxPenalty      = 20.0
	reliabilityFullPenaltyRate = 0.3
	// Every served attempt shrinks the failure counts, so a model that stopped refusing recovers
	// its score instead of carrying one refusal for the life of the stats.
	reliabilityDecayPerAttempt = 0.05
	reliabilityFilterWeight    = 0.5
	// A served turn emitting this many tool calls is counted as a loop turn: the real sessions that
	// stalled ran 25+ calls per turn on flash models repeating searches.
	loopLoopToolThreshold = 25
)

// modelSpeedStats carries throughput and empirical reliability learned from completed responses.
// Reliability events (refusals, empty responses, loop turns) are counted against Attempts so each
// rate is a fraction of the requests the model actually answered or was asked to answer.
type modelSpeedStats struct {
	Samples         int       `json:"samples,omitempty"`
	TokensPerSecond float64   `json:"tokens_per_second,omitempty"`
	FirstTokenSec   float64   `json:"first_token_sec,omitempty"`
	Attempts        int       `json:"attempts,omitempty"`
	Refusals        int       `json:"refusals,omitempty"`
	FilterRefusals  int       `json:"filter_refusals,omitempty"`
	EmptyResponses  int       `json:"empty_responses,omitempty"`
	LoopTurns       int       `json:"loop_turns,omitempty"`
	LastMeasured    time.Time `json:"last_measured,omitempty"`
}

// failureCount sums the reliability failures as weighted fractions: a filter or cyber refusal is
// the prompt's fault as much as the model's, so it counts half.
func (stats *modelSpeedStats) failureCount() float64 {
	return float64(stats.Refusals) + reliabilityFilterWeight*float64(stats.FilterRefusals) +
		float64(stats.EmptyResponses) + float64(stats.LoopTurns)
}

type modelSpeedSnapshot struct {
	Samples         int       `json:"samples"`
	TokensPerSecond float64   `json:"tokens_per_second,omitempty"`
	FirstTokenSec   float64   `json:"first_token_sec,omitempty"`
	Attempts        int       `json:"attempts,omitempty"`
	Refusals        int       `json:"refusals,omitempty"`
	FilterRefusals  int       `json:"filter_refusals,omitempty"`
	EmptyResponses  int       `json:"empty_responses,omitempty"`
	LoopTurns       int       `json:"loop_turns,omitempty"`
	Rating          float64   `json:"rating"`
	Reliability     float64   `json:"reliability"`
	LastMeasured    time.Time `json:"last_measured,omitempty"`
}

var (
	speedMu    sync.RWMutex
	speedStats = map[string]*modelSpeedStats{}
)

// speedRating maps measured output tokens per second to 0-100 on a log scale.
func speedRating(tokensPerSecond float64) float64 {
	if tokensPerSecond <= 0 || math.IsNaN(tokensPerSecond) || math.IsInf(tokensPerSecond, 0) {
		return 0
	}
	frac := math.Log(tokensPerSecond/speedSlowTokensPerSec) / math.Log(speedFastTokensPerSec/speedSlowTokensPerSec)
	return math.Round(100 * math.Min(1, math.Max(0, frac)))
}

// speedRatingWithTTFT combines output throughput (0-100) with a bounded penalty when first-token
// latency exceeds speedFastFirstTokenSec so interactive turns in speed mode prefer responsive models.
func speedRatingWithTTFT(tokensPerSecond, firstTokenSec float64) float64 {
	base := speedRating(tokensPerSecond)
	if base <= 0 || firstTokenSec <= speedFastFirstTokenSec || math.IsNaN(firstTokenSec) || math.IsInf(firstTokenSec, 0) {
		return base
	}
	frac := (firstTokenSec - speedFastFirstTokenSec) / (speedSlowFirstTokenSec - speedFastFirstTokenSec)
	penalty := math.Round(speedMaxFirstTokenPenal * math.Min(1, math.Max(0, frac)))
	return math.Max(0, base-penalty)
}

// measuredModelSpeed returns the learned rating, or a neutral 50 until a model completes a request
// with usage data. Missing usage is not a failure: some upstreams never report output tokens.
func measuredModelSpeed(model string) float64 {
	speedMu.RLock()
	stats := speedStats[model]
	speedMu.RUnlock()
	if stats == nil || stats.Samples == 0 || stats.TokensPerSecond <= 0 {
		return speedUnmeasuredRating
	}
	return speedRatingWithTTFT(stats.TokensPerSecond, stats.FirstTokenSec)
}

// firstTokenLatencyPenalty returns the quality points quality mode subtracts for model's measured
// first-token latency. A model without samples has no measured latency and no penalty.
func firstTokenLatencyPenalty(model string) float64 {
	speedMu.RLock()
	stats := speedStats[model]
	speedMu.RUnlock()
	if stats == nil || stats.Samples == 0 || stats.FirstTokenSec <= qualityLatencyFreeSec {
		return 0
	}
	frac := (stats.FirstTokenSec - qualityLatencyFreeSec) / (qualityLatencyFullSec - qualityLatencyFreeSec)
	return math.Round(qualityLatencyMaxPenalty * math.Min(1, frac))
}

// reliabilityRating returns the fraction of attempts that succeeded without a refusal, empty
// response, or loop turn, mapped to a 0-100 rating. A model with no attempts yet is neutral (100).
func reliabilityRating(stats *modelSpeedStats) float64 {
	if stats == nil || stats.Attempts == 0 {
		return 100
	}
	successRate := 1 - stats.failureCount()/float64(stats.Attempts)
	return math.Round(100 * math.Max(0, math.Min(1, successRate)))
}

// reliabilityPenalty subtracts up to reliabilityMaxPenalty quality points proportional to the
// model's failure rate, so a model that refuses or loops often no longer ties a clean model at the
// same Artificial Analysis quality.
func reliabilityPenalty(stats *modelSpeedStats) float64 {
	if stats == nil || stats.Attempts == 0 {
		return 0
	}
	rate := stats.failureCount() / float64(stats.Attempts)
	return math.Round(reliabilityMaxPenalty * math.Min(1, math.Max(0, rate/reliabilityFullPenaltyRate)))
}

// qualityRatingWithReliability applies the reliability penalty to a configured quality rating.
func qualityRatingWithReliability(model string, quality float64) float64 {
	speedMu.RLock()
	stats := speedStats[model]
	speedMu.RUnlock()
	return math.Max(0, quality-reliabilityPenalty(stats))
}

// recordModelReliabilityEvent counts one failure class against the model's attempt total.
func recordModelReliabilityEvent(model, kind string) {
	model = strings.TrimSpace(model)
	if model == "" {
		return
	}
	speedMu.Lock()
	stats := speedStats[model]
	if stats == nil {
		stats = &modelSpeedStats{}
		speedStats[model] = stats
	}
	stats.Attempts++
	switch kind {
	case "refusal":
		stats.Refusals++
	case "filter":
		stats.FilterRefusals++
	case "empty":
		stats.EmptyResponses++
	case "loop":
		stats.LoopTurns++
	}
	speedMu.Unlock()
	savePersistedSessions()
}

// recordModelReliabilityFailure classifies an attempt error into a reliability event: refusals and
// empty responses count against quality, while quota, capability, and transient errors do not.
func recordModelReliabilityFailure(model string, errDetail string) {
	summary := summarizeAttemptReason(errDetail)
	switch {
	case summary == "empty response":
		recordModelReliabilityEvent(model, "empty")
	case summary == "refusal: filter" || summary == "refusal: cyber":
		recordModelReliabilityEvent(model, "filter")
	case summary == "refusal" || strings.HasPrefix(summary, "refusal:"):
		recordModelReliabilityEvent(model, "refusal")
	}
}

// recordModelAttempt counts one completed attempt with no failure class against the model's total.
func recordModelAttempt(model string) {
	model = strings.TrimSpace(model)
	if model == "" {
		return
	}
	speedMu.Lock()
	stats := speedStats[model]
	if stats == nil {
		stats = &modelSpeedStats{}
		speedStats[model] = stats
	}
	stats.Attempts++
	decayReliability(stats)
	speedMu.Unlock()
	savePersistedSessions()
}

// decayReliability shrinks failure counts toward zero on every served attempt. Counts floor, so a
// refusal decays within a few served turns instead of rounding back to its old value.
func decayReliability(stats *modelSpeedStats) {
	stats.Refusals = decayCount(stats.Refusals)
	stats.FilterRefusals = decayCount(stats.FilterRefusals)
	stats.EmptyResponses = decayCount(stats.EmptyResponses)
	stats.LoopTurns = decayCount(stats.LoopTurns)
}

func decayCount(n int) int {
	if n == 0 {
		return 0
	}
	return int(math.Floor(float64(n) * (1 - reliabilityDecayPerAttempt)))
}

// recordModelServedTurn counts a served turn: an attempt plus a loop class when the turn emitted
// loopLoopToolThreshold or more tool calls, matching the runaway loops found across real sessions.
func recordModelServedTurn(model string, toolCount int) {
	if toolCount >= loopLoopToolThreshold {
		recordModelReliabilityEvent(model, "loop")
		return
	}
	recordModelAttempt(model)
}

// toolUseCountInResponse counts structured tool_use blocks in a completed response body. It walks
// Claude, OpenAI, and Gemini envelope shapes; only structured tool blocks count, so a text reply
// mentioning tools does not inflate the loop tally.
func toolUseCountInResponse(body []byte) int {
	var msg struct {
		Content json.RawMessage `json:"content"`
		Choices []struct {
			Message *struct {
				Content   json.RawMessage `json:"content"`
				ToolCalls []any           `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Response *struct {
			Candidates []geminiCandidate `json:"candidates"`
		} `json:"response"`
		Candidates []geminiCandidate `json:"candidates"`
	}
	if json.Unmarshal(bytes.TrimSpace(body), &msg) != nil {
		return 0
	}
	count := 0
	for _, block := range contentToBlocks(msg.Content) {
		var typ string
		if json.Unmarshal(block["type"], &typ) == nil && (typ == "tool_use" || typ == "server_tool_use") {
			count++
		}
	}
	for _, choice := range msg.Choices {
		if choice.Message != nil {
			count += len(choice.Message.ToolCalls)
			for _, block := range contentToBlocks(choice.Message.Content) {
				var typ string
				if json.Unmarshal(block["type"], &typ) == nil && typ == "tool_use" {
					count++
				}
			}
		}
	}
	candidates := msg.Candidates
	if msg.Response != nil {
		candidates = append(candidates, msg.Response.Candidates...)
	}
	for _, cand := range candidates {
		for _, part := range cand.Content.Parts {
			if part.FunctionCall != nil {
				count++
			}
		}
	}
	return count
}

func speedStatsSnapshot() map[string]modelSpeedSnapshot {
	speedMu.RLock()
	defer speedMu.RUnlock()
	out := make(map[string]modelSpeedSnapshot, len(speedStats))
	for model, stats := range speedStats {
		if stats == nil || stats.Samples == 0 {
			continue
		}
		out[model] = modelSpeedSnapshot{
			Samples:         stats.Samples,
			TokensPerSecond: stats.TokensPerSecond,
			FirstTokenSec:   stats.FirstTokenSec,
			Attempts:        stats.Attempts,
			Refusals:        stats.Refusals,
			FilterRefusals:  stats.FilterRefusals,
			EmptyResponses:  stats.EmptyResponses,
			LoopTurns:       stats.LoopTurns,
			Rating:          speedRatingWithTTFT(stats.TokensPerSecond, stats.FirstTokenSec),
			Reliability:     reliabilityRating(stats),
			LastMeasured:    stats.LastMeasured,
		}
	}
	return out
}

// recordModelSpeedSample learns throughput from one completed response. Failed or client-aborted
// streams never reach this call, and responses without reported output tokens contribute no sample.
func recordModelSpeedSample(model string, outputTokens int, started, firstToken, finished time.Time) {
	model = strings.TrimSpace(model)
	duration := finished.Sub(started).Seconds()
	if model == "" || outputTokens <= 0 || duration <= 0 || math.IsNaN(duration) || math.IsInf(duration, 0) {
		return
	}
	firstSec := firstToken.Sub(started).Seconds()
	if firstToken.IsZero() || firstSec < 0 {
		firstSec = 0
	}
	speedMu.Lock()
	stats := speedStats[model]
	if stats == nil {
		stats = &modelSpeedStats{}
		speedStats[model] = stats
	}
	tokensPerSecond := float64(outputTokens) / duration
	if stats.Samples == 0 {
		stats.TokensPerSecond = tokensPerSecond
		stats.FirstTokenSec = firstSec
	} else {
		stats.TokensPerSecond += speedSampleWeight * (tokensPerSecond - stats.TokensPerSecond)
		stats.FirstTokenSec += speedSampleWeight * (firstSec - stats.FirstTokenSec)
	}
	stats.Samples++
	stats.LastMeasured = finished
	speedMu.Unlock()
	savePersistedSessions()
}

// recordModelSpeedResponse measures a completed non-streaming response. There is no earlier output
// event, so first-token latency equals the full response latency.
func recordModelSpeedResponse(model string, body []byte, started, finished time.Time) {
	outputTokens := outputTokensFromChunk(body)
	if outputTokens == 0 {
		return
	}
	recordModelSpeedSample(model, outputTokens, started, finished, finished)
}

// outputTokensFromChunk finds the largest output-token count in a response body or SSE chunk. Stream
// usage is cumulative, so taking the largest avoids double counting incremental usage frames.
func outputTokensFromChunk(chunk []byte) int {
	if !bytes.Contains(chunk, []byte(`"usage"`)) && !bytes.Contains(chunk, []byte(`"usageMetadata"`)) {
		return 0
	}
	maxTokens := 0
	for _, raw := range responseJSONLines(chunk) {
		if tokens := outputTokensFromJSON(raw); tokens > maxTokens {
			maxTokens = tokens
		}
	}
	return maxTokens
}

func responseJSONLines(chunk []byte) [][]byte {
	trimmed := bytes.TrimSpace(chunk)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '{' {
		return [][]byte{trimmed}
	}
	var lines [][]byte
	for _, line := range bytes.Split(chunk, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(data) > 0 && data[0] == '{' {
			lines = append(lines, data)
		}
	}
	return lines
}

type speedUsage struct {
	OutputTokens     int `json:"output_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	CandidatesTokens int `json:"candidatesTokenCount"`
	ThoughtsTokens   int `json:"thoughtsTokenCount"`
}

func outputTokensFromJSON(raw []byte) int {
	var env struct {
		Usage         *speedUsage `json:"usage"`
		UsageMetadata *speedUsage `json:"usageMetadata"`
		Message       *struct {
			Usage *speedUsage `json:"usage"`
		} `json:"message"`
		Response *struct {
			Usage *speedUsage `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return 0
	}
	best := 0
	for _, u := range []*speedUsage{env.Usage, env.UsageMetadata} {
		if u == nil {
			continue
		}
		tokens := max(u.OutputTokens, u.CompletionTokens, u.CandidatesTokens+u.ThoughtsTokens)
		if tokens > best {
			best = tokens
		}
	}
	for _, nested := range []*speedUsage{messageUsage(env.Message), responseUsage(env.Response)} {
		if nested != nil && nested.OutputTokens > best {
			best = nested.OutputTokens
		}
	}
	return best
}

func messageUsage(message *struct {
	Usage *speedUsage `json:"usage"`
}) *speedUsage {
	if message == nil {
		return nil
	}
	return message.Usage
}

func responseUsage(response *struct {
	Usage *speedUsage `json:"usage"`
}) *speedUsage {
	if response == nil {
		return nil
	}
	return response.Usage
}

// Speed probes are explicit, operator-triggered requests. They cover every non-embedding model,
// sequentially so one provider's load does not distort another's measurement.
type speedRefreshStatus struct {
	Running    bool              `json:"running"`
	StartedAt  time.Time         `json:"started_at,omitempty"`
	FinishedAt time.Time         `json:"finished_at,omitempty"`
	Total      int               `json:"total,omitempty"`
	Completed  int               `json:"completed,omitempty"`
	LastModel  string            `json:"last_model,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`
}

const speedProbeTimeout = 90 * time.Second

var speedRefresh = struct {
	sync.RWMutex
	status speedRefreshStatus
}{}

func speedRefreshSnapshot() speedRefreshStatus {
	speedRefresh.RLock()
	defer speedRefresh.RUnlock()
	status := speedRefresh.status
	if status.Errors != nil {
		status.Errors = maps.Clone(status.Errors)
	}
	return status
}

// speedProbeModels lists every non-embedding model currently served by a host credential.
// Groups are deliberately not consulted: the button measures all usable models, not just group members.
func speedProbeModels() ([]string, error) {
	snapshot, err := hostState(time.Now())
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var models []string
	for _, credentialModels := range snapshot.models {
		for _, model := range credentialModels {
			model = strings.TrimSpace(model)
			if model == "" || seen[model] || strings.Contains(strings.ToLower(model), "embedding") {
				continue
			}
			seen[model] = true
			models = append(models, model)
		}
	}
	sort.Strings(models)
	return models, nil
}

// startSpeedRefresh starts one asynchronous probe run. A second click while one is running returns
// its current status instead of starting another run.
func startSpeedRefresh() (speedRefreshStatus, error) {
	speedRefresh.Lock()
	if speedRefresh.status.Running {
		status := speedRefresh.status
		speedRefresh.Unlock()
		return status, nil
	}
	models, errModels := speedProbeModels()
	if errModels != nil {
		speedRefresh.Unlock()
		return speedRefreshStatus{}, fmt.Errorf("list models for speed probes: %w", errModels)
	}
	if len(models) == 0 {
		speedRefresh.Unlock()
		return speedRefreshStatus{}, fmt.Errorf("no non-embedding models available to measure")
	}
	speedRefresh.status = speedRefreshStatus{
		Running:   true,
		StartedAt: time.Now(),
		Total:     len(models),
		Errors:    make(map[string]string),
	}
	speedRefresh.Unlock()
	go runSpeedRefresh(models)
	return speedRefreshSnapshot(), nil
}

func runSpeedRefresh(models []string) {
	for _, model := range models {
		speedRefresh.Lock()
		speedRefresh.status.LastModel = model
		speedRefresh.Unlock()
		err := probeModelSpeed(model)
		speedRefresh.Lock()
		speedRefresh.status.Completed++
		if err != nil {
			speedRefresh.status.Errors[model] = err.Error()
		}
		speedRefresh.Unlock()
	}
	speedRefresh.Lock()
	speedRefresh.status.Running = false
	speedRefresh.status.FinishedAt = time.Now()
	speedRefresh.Unlock()
}

// probeModelSpeed asks for a small fixed answer and measures the completed response. The request is
// non-streaming so the same code path works for every provider supported by the host.
func probeModelSpeed(model string) error {
	body, errMarshal := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{{
			"role":    "user",
			"content": "Write exactly 80 words about the ocean. Do not use headings or lists.",
		}},
		"max_tokens": 256,
	})
	if errMarshal != nil {
		return errMarshal
	}
	type result struct {
		raw json.RawMessage
		err error
	}
	started := time.Now()
	resultCh := make(chan result, 1)
	go func() {
		raw, err := hostCall(methodHostModelExecute, hostModelRequest{
			EntryProtocol: "openai",
			ExitProtocol:  "openai",
			Model:         model,
			Body:          body,
			Headers:       http.Header{"Content-Type": []string{"application/json"}},
		})
		resultCh <- result{raw: raw, err: err}
	}()
	select {
	case <-time.After(speedProbeTimeout):
		return fmt.Errorf("probe timed out after %s", speedProbeTimeout)
	case res := <-resultCh:
		if res.err != nil {
			return res.err
		}
		var response hostModelResponse
		if errDecode := json.Unmarshal(res.raw, &response); errDecode != nil {
			return fmt.Errorf("decode host.model.execute response: %w", errDecode)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("upstream returned HTTP %d: %s", response.StatusCode, summarizeAttemptReason(string(response.Body)))
		}
		if outputTokensFromChunk(response.Body) == 0 {
			return fmt.Errorf("response did not report output tokens")
		}
		recordModelSpeedResponse(model, response.Body, started, time.Now())
		return nil
	}
}
