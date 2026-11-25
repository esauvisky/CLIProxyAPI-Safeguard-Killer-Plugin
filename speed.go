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
	// Models without samples start neutral, so a new speed group still ranks by quality and cost.
	speedUnmeasuredRating = 50.0
	// Each completed response moves the per-model EWMA by a quarter of the new sample.
	speedSampleWeight = 0.25
)

type modelSpeedStats struct {
	Samples         int       `json:"samples,omitempty"`
	TokensPerSecond float64   `json:"tokens_per_second,omitempty"`
	FirstTokenSec   float64   `json:"first_token_sec,omitempty"`
	LastMeasured    time.Time `json:"last_measured,omitempty"`
}

type modelSpeedSnapshot struct {
	Samples         int       `json:"samples"`
	TokensPerSecond float64   `json:"tokens_per_second,omitempty"`
	FirstTokenSec   float64   `json:"first_token_sec,omitempty"`
	Rating          float64   `json:"rating"`
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

// measuredModelSpeed returns the learned rating, or a neutral 50 until a model completes a request
// with usage data. Missing usage is not a failure: some upstreams never report output tokens.
func measuredModelSpeed(model string) float64 {
	speedMu.RLock()
	stats := speedStats[model]
	speedMu.RUnlock()
	if stats == nil || stats.Samples == 0 || stats.TokensPerSecond <= 0 {
		return speedUnmeasuredRating
	}
	return speedRating(stats.TokensPerSecond)
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
			Rating:          speedRating(stats.TokensPerSecond),
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
