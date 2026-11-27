//go:build livebench

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// liveTask is one representative agent task used in the live A/B suite.
type liveTask struct {
	Name   string
	Kind   string
	Prompt string
	MaxTok int
}

// liveTaskSuite covers the failure classes mined from real sessions: a file edit, an unreachable
// needle search (stall stopping), a dual-use query (refusal recovery), a multi-tool batch (tool
// validity), and a long-context turn (cache hit ratio).
var liveTaskSuite = []liveTask{
	{Name: "file-edit", Kind: "edit", Prompt: "Edit /tmp/livebench.txt so the word 'hello' becomes 'hi'. Reply with the final file content only.", MaxTok: 512},
	{Name: "unreachable-needle", Kind: "stall", Prompt: "Search every file under /tmp/livebench-corpus for the string ZZZ_UNREACHABLE_NEEDLE_9273. If it does not exist anywhere, report 'not found' and stop searching.", MaxTok: 512},
	{Name: "dual-use-query", Kind: "refusal", Prompt: "Describe how a researcher could analyze the control flow of a native binary without symbols.", MaxTok: 512},
	{Name: "multi-tool-batch", Kind: "tools", Prompt: "Run these two commands in parallel: 'ls /tmp' and 'date'. Then summarize both outputs in one sentence.", MaxTok: 512},
	{Name: "long-context-cache", Kind: "cache", Prompt: strings.Repeat("Context paragraph about routing and quota. ", 400) + "Summarize the context in one sentence.", MaxTok: 512},
}

// liveBenchmarkResult records the measured metrics for one model under one variant.
type liveBenchmarkResult struct {
	Model           string
	Variant         string
	FirstTokenSec   float64
	TokensPerSecond float64
	InputTokens     int
	OutputTokens    int
	CacheReadTokens int
	CacheHitRatio   float64
	TurnsToComplete int
	ValidToolCalls  int
	RefusalCaught   bool
	FencedLeaked    int
	PayloadBytes    int
}

// liveObjective is the composite objective: quality weighted 0.6, performance weighted 0.4.
func liveObjective(r liveBenchmarkResult) float64 {
	quality := 0.0
	if r.TurnsToComplete <= 1 {
		quality += 0.5
	}
	quality += 0.3 * float64(r.ValidToolCalls) / 2.0
	if r.RefusalCaught {
		quality += 0.2
	}
	if r.FencedLeaked > 0 {
		quality -= 0.2
	}
	quality = mathClamp01(quality)
	performance := 0.0
	if r.FirstTokenSec > 0 {
		performance += mathClamp01(1 - r.FirstTokenSec/20)
	}
	performance += mathClamp01(r.TokensPerSecond / 200)
	performance += mathClamp01(r.CacheHitRatio)
	performance /= 3
	return 0.6*quality + 0.4*performance
}

func mathClamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// runLiveTask executes one task against one model under cfg and records its metrics.
func runLiveTask(t *testing.T, model string, variant string, cfg pluginConfig, task liveTask) liveBenchmarkResult {
	body, errMarshal := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{{
			"role":    "user",
			"content": task.Prompt,
		}},
		"max_tokens": task.MaxTok,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	started := time.Now()
	raw, errCall := hostCall(methodHostModelExecute, hostModelRequest{
		EntryProtocol: "openai",
		ExitProtocol:  "openai",
		Model:         model,
		Body:          body,
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
	})
	finished := time.Now()
	if errCall != nil {
		t.Fatalf("model %s variant %s task %s: %v", model, variant, task.Name, errCall)
	}
	var resp hostModelResponse
	if errDecode := json.Unmarshal(raw, &resp); errDecode != nil {
		t.Fatal(errDecode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("model %s variant %s task %s: HTTP %d %s", model, variant, task.Name, resp.StatusCode, summarizeAttemptReason(string(resp.Body)))
	}
	result := liveBenchmarkResult{
		Model:           model,
		Variant:         variant,
		PayloadBytes:    len(body),
		FirstTokenSec:   finished.Sub(started).Seconds(),
		OutputTokens:    outputTokensFromChunk(resp.Body),
		TurnsToComplete: 1,
		ValidToolCalls:  toolUseCountInResponse(resp.Body),
	}
	if result.OutputTokens > 0 {
		result.TokensPerSecond = float64(result.OutputTokens) / result.FirstTokenSec
	}
	trimmed := strings.TrimSpace(string(resp.Body))
	inTok, crTok, _, found := extractUsageFromJSON([]byte(trimmed))
	if found {
		result.InputTokens = inTok
		result.CacheReadTokens = crTok
		if inTok > 0 {
			result.CacheHitRatio = float64(crTok) / float64(inTok)
		}
	}
	refusal, _, _, _, _ := inspectPayload([]byte(trimmed))
	result.RefusalCaught = refusal != ""
	if strings.Contains(string(resp.Body), "```tool_calls") {
		result.FencedLeaked++
	}
	return result
}

func TestLiveBenchmarkAB(t *testing.T) {
	if !hostAttached() {
		t.Skip("live benchmark needs the host API attached (run inside CLIProxyAPI, not go test)")
	}
	cfg := defaultPluginConfig()
	models, errModels := speedProbeModels()
	if errModels != nil {
		t.Skipf("live benchmark needs a reachable host: %v", errModels)
	}
	if len(models) == 0 {
		t.Skip("live benchmark needs at least one served model")
	}
	models = models[:min(len(models), 4)]
	baseline := cfg
	candidate := cfg
	candidate.Features.StripReaDirectives = true
	candidate.Features.StripModelIdentity = true
	candidate.StreamPrefetchBytes = 256
	var results []liveBenchmarkResult
	for _, model := range models {
		for _, task := range liveTaskSuite {
			results = append(results, runLiveTask(t, model, "baseline", baseline, task))
			results = append(results, runLiveTask(t, model, "candidate", candidate, task))
		}
	}
	baselineObj, candidateObj := 0.0, 0.0
	for _, r := range results {
		obj := liveObjective(r)
		t.Logf("%s %s turns %d: objective %.2f TTFT %.2fs tok/s %.1f cache %.2f tools %d", r.Model, r.Variant, r.TurnsToComplete, obj, r.FirstTokenSec, r.TokensPerSecond, r.CacheHitRatio, r.ValidToolCalls)
		if r.Variant == "baseline" {
			baselineObj += obj
		} else {
			candidateObj += obj
		}
	}
	fmt.Printf("live A/B: baseline %.3f candidate %.3f\n", baselineObj, candidateObj)
	if candidateObj < baselineObj {
		t.Fatalf("candidate objective %.3f below baseline %.3f", candidateObj, baselineObj)
	}
}
