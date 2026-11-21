package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	defaultBenchmarkCodingURL = "https://artificialanalysis.ai/agents/coding-agents"
	defaultBenchmarkModelsURL = "https://artificialanalysis.ai/models"
	benchmarkUserAgent        = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	benchmarkRefreshAge       = 6 * time.Hour
	benchmarkHTTPTimeout      = 25 * time.Second
)

// modelBenchmark holds Artificial Analysis scores matched to a model ID.
type modelBenchmark struct {
	ModelName        string  `json:"model_name,omitempty"`
	CodingAgent      float64 `json:"coding_agent,omitempty"`
	Intelligence     float64 `json:"intelligence,omitempty"`
	FrontierCode     float64 `json:"frontier_code,omitempty"`
	TerminalBench    float64 `json:"terminal_bench,omitempty"`
	CostUSD          float64 `json:"cost_usd,omitempty"`
	WallTimeSec      float64 `json:"wall_time_sec,omitempty"`
	RefusedAttempts  int     `json:"refused_attempts,omitempty"`
	Source           string  `json:"source,omitempty"`
}

// PrimaryScore returns the best single 0–100 score (Coding Agent Index first, else Intelligence Index).
func (b modelBenchmark) PrimaryScore() (float64, string) {
	if b.CodingAgent > 0 {
		return b.CodingAgent, "AA"
	}
	if b.Intelligence > 0 {
		return b.Intelligence, "AA Intel"
	}
	return 0, ""
}

type benchmarkCatalog struct {
	// byKey maps normalized model keys (both variant-specific and base family) to best benchmark.
	byKey     map[string]modelBenchmark
	fetchedAt time.Time
	errText   string
}

var (
	benchmarkCodingURL   = defaultBenchmarkCodingURL
	benchmarkModelsURL   = defaultBenchmarkModelsURL
	benchmarkHTTPClient  = &http.Client{Timeout: benchmarkHTTPTimeout}
	benchmarkMu          sync.RWMutex
	benchmarkCache       = benchmarkCatalog{byKey: map[string]modelBenchmark{}}
	benchmarkRefreshing  atomic.Bool
	nextFPushChunkRegexp = regexp.MustCompile(`self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)`)
)

// ensureBenchmarksFresh kicks off a non-blocking background fetch when the cache is missing or stale.
func ensureBenchmarksFresh() {
	if testing.Testing() && benchmarkCodingURL == defaultBenchmarkCodingURL && benchmarkModelsURL == defaultBenchmarkModelsURL {
		return
	}
	benchmarkMu.RLock()
	fresh := !benchmarkCache.fetchedAt.IsZero() && time.Since(benchmarkCache.fetchedAt) < benchmarkRefreshAge
	benchmarkMu.RUnlock()
	if fresh || !benchmarkRefreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer benchmarkRefreshing.Store(false)
		_ = refreshBenchmarksNow()
	}()
}

// refreshBenchmarksNow fetches both Artificial Analysis pages synchronously and replaces the cache.
func refreshBenchmarksNow() error {
	codingHTML, errCoding := fetchBenchmarkPage(benchmarkCodingURL)
	modelsHTML, errModels := fetchBenchmarkPage(benchmarkModelsURL)

	merged := map[string]modelBenchmark{}
	var errs []string
	if errCoding != nil {
		errs = append(errs, "coding-agents: "+errCoding.Error())
	} else {
		for _, entry := range parseCodingAgentHTML(codingHTML) {
			indexBenchmarkEntry(merged, entry)
		}
	}
	if errModels != nil {
		errs = append(errs, "models: "+errModels.Error())
	} else {
		for _, entry := range parseModelsHTML(modelsHTML) {
			indexBenchmarkEntry(merged, entry)
		}
	}

	now := time.Now()
	benchmarkMu.Lock()
	defer benchmarkMu.Unlock()
	if len(merged) > 0 {
		benchmarkCache = benchmarkCatalog{
			byKey:     merged,
			fetchedAt: now,
			errText:   strings.Join(errs, "; "),
		}
		return nil
	}
	errMsg := strings.Join(errs, "; ")
	if errMsg == "" {
		errMsg = "no Artificial Analysis benchmark rows parsed"
	}
	benchmarkCache.errText = errMsg
	benchmarkCache.fetchedAt = now
	return fmt.Errorf("%s", errMsg)
}

func fetchBenchmarkPage(pageURL string) ([]byte, error) {
	if strings.TrimSpace(pageURL) == "" {
		return nil, fmt.Errorf("empty url")
	}
	req, errReq := http.NewRequest(http.MethodGet, pageURL, nil)
	if errReq != nil {
		return nil, errReq
	}
	req.Header.Set("User-Agent", benchmarkUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, errDo := benchmarkHTTPClient.Do(req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Cap read at 8 MB to bound memory on unexpected upstream responses.
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func decodeNextRSC(html []byte) string {
	matches := nextFPushChunkRegexp.FindAllSubmatch(html, -1)
	if len(matches) == 0 {
		return string(html)
	}
	var b strings.Builder
	b.Grow(len(html) / 2)
	for _, m := range matches {
		var unquoted string
		if err := json.Unmarshal(append([]byte{'"'}, append(m[1], '"')...), &unquoted); err == nil {
			b.WriteString(unquoted)
		} else {
			b.Write(m[1])
		}
	}
	return b.String()
}

func extractJSONArrayAfterKey(text, key string) ([]json.RawMessage, bool) {
	needle := `"` + key + `":[`
	idx := strings.Index(text, needle)
	if idx < 0 {
		return nil, false
	}
	start := idx + len(needle) - 1
	dec := json.NewDecoder(strings.NewReader(text[start:]))
	var arr []json.RawMessage
	if err := dec.Decode(&arr); err != nil {
		return nil, false
	}
	return arr, true
}

func parseCodingAgentHTML(html []byte) []modelBenchmark {
	rsc := decodeNextRSC(html)
	// Next.js RSC stores the top highlighted rows in "rows" and references them from
	// "benchmarkRows" via "$...:rows:N" pointer strings, so parse both arrays.
	var rawRows []json.RawMessage
	for _, key := range []string{"rows", "benchmarkRows"} {
		if arr, ok := extractJSONArrayAfterKey(rsc, key); ok {
			rawRows = append(rawRows, arr...)
		}
	}
	if len(rawRows) == 0 {
		return nil
	}
	out := make([]modelBenchmark, 0, len(rawRows))
	for _, raw := range rawRows {
		var row struct {
			Display struct {
				Model string `json:"model"`
			} `json:"display"`
			DisplayLabel string  `json:"displayLabel"`
			IndexScore   float64 `json:"indexScore"`
			Mean         struct {
				CostUSD          float64 `json:"costUsd"`
				AgentWallTimeSec float64 `json:"agentWallTimeSec"`
			} `json:"mean"`
			Safety struct {
				RefusedAttemptCount int `json:"refusedAttemptCount"`
			} `json:"safety"`
		}
		if json.Unmarshal(raw, &row) != nil || row.IndexScore <= 0 {
			continue
		}
		name := strings.TrimSpace(row.Display.Model)
		if name == "" {
			name = strings.TrimSpace(row.DisplayLabel)
		}
		if name == "" || strings.Contains(name, " + ") {
			continue
		}
		out = append(out, modelBenchmark{
			ModelName:       name,
			CodingAgent:     round1(row.IndexScore * 100),
			CostUSD:         round2(row.Mean.CostUSD),
			WallTimeSec:     math.Round(row.Mean.AgentWallTimeSec),
			RefusedAttempts: row.Safety.RefusedAttemptCount,
			Source:          "coding-agents",
		})
	}
	return out
}

func parseModelsHTML(html []byte) []modelBenchmark {
	rsc := decodeNextRSC(html)
	rawRows, ok := extractJSONArrayAfterKey(rsc, "initialModels")
	if !ok {
		return nil
	}
	out := make([]modelBenchmark, 0, len(rawRows))
	for _, raw := range rawRows {
		var row struct {
			Slug              string  `json:"slug"`
			Name              string  `json:"name"`
			IntelligenceIndex float64 `json:"intelligenceIndex"`
			FrontierCode20    float64 `json:"frontierCode20"`
			TerminalBench40   float64 `json:"terminalBench40"`
		}
		if json.Unmarshal(raw, &row) != nil || row.IntelligenceIndex <= 0 {
			continue
		}
		name := strings.TrimSpace(row.Name)
		if name == "" {
			name = strings.TrimSpace(row.Slug)
		}
		if name == "" {
			continue
		}
		out = append(out, modelBenchmark{
			ModelName:     name,
			Intelligence:  round1(row.IntelligenceIndex),
			FrontierCode:  round1(row.FrontierCode20 * 100),
			TerminalBench: round1(row.TerminalBench40 * 100),
			Source:        "models",
		})
	}
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// normalizeBenchmarkKey converts a model name or CPA ID into a canonical hyphenated key.
func normalizeBenchmarkKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "models/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	// Strip CPA colon tags like :free
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// Remove parenthetical metadata tokens other than reasoning level
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// splitNameAndLevel extracts base model name and optional reasoning effort from AA names like
// "Gemini 4 Neon (Xhigh)" or "Claude Fable 5.2 (High, Default Fallback)".
func splitNameAndLevel(name string) (baseKey, level string) {
	base := name
	if open := strings.Index(name, "("); open >= 0 {
		base = strings.TrimSpace(name[:open])
		inner := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name[open+1:]), ")"))
		for _, part := range strings.Split(inner, ",") {
			p := strings.TrimSpace(part)
			switch p {
			case "xhigh", "high", "medium", "low", "max", "minimal":
				level = p
			}
			if level != "" {
				break
			}
		}
	}
	baseKey = normalizeBenchmarkKey(base)
	// Normalize vendor prefixes / release-date suffixes used in AA names
	baseKey = strings.TrimPrefix(baseKey, "tencent-")
	baseKey = strings.TrimPrefix(baseKey, "reflection-")
	// Strip 4-digit MMDD release suffixes like deepseek-v4-1-flash-1017 -> deepseek-v4-1-flash
	parts := strings.Split(baseKey, "-")
	if len(parts) > 2 && len(parts[len(parts)-1]) == 4 && isAllDigits(parts[len(parts)-1]) {
		baseKey = strings.Join(parts[:len(parts)-1], "-")
	}
	// Map "beam-1-0" -> "beam"
	if baseKey == "beam-1-0" {
		baseKey = "beam"
	}
	return baseKey, level
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func indexBenchmarkEntry(dst map[string]modelBenchmark, entry modelBenchmark) {
	baseKey, level := splitNameAndLevel(entry.ModelName)
	if baseKey == "" {
		return
	}
	mergeInto := func(k string) {
		prev, exists := dst[k]
		if !exists {
			dst[k] = entry
			return
		}
		// Keep the highest CodingAgent score and merge Intelligence/FC2/TB4 fields across sources.
		if entry.CodingAgent > prev.CodingAgent {
			prev.CodingAgent = entry.CodingAgent
			prev.CostUSD = entry.CostUSD
			prev.WallTimeSec = entry.WallTimeSec
			prev.RefusedAttempts = entry.RefusedAttempts
			prev.ModelName = entry.ModelName
			prev.Source = entry.Source
		}
		if entry.Intelligence > prev.Intelligence {
			prev.Intelligence = entry.Intelligence
		}
		if entry.FrontierCode > prev.FrontierCode {
			prev.FrontierCode = entry.FrontierCode
		}
		if entry.TerminalBench > prev.TerminalBench {
			prev.TerminalBench = entry.TerminalBench
		}
		if prev.ModelName == "" {
			prev.ModelName = entry.ModelName
		}
		dst[k] = prev
	}
	if level != "" {
		mergeInto(baseKey + "-" + level)
	}
	mergeInto(baseKey)
}

// lookupBenchmark returns the cached Artificial Analysis score for a CPA model ID, if available.
func lookupBenchmark(modelID string) (modelBenchmark, bool) {
	benchmarkMu.RLock()
	defer benchmarkMu.RUnlock()
	return lookupBenchmarkLocked(modelID)
}

func lookupBenchmarkLocked(modelID string) (modelBenchmark, bool) {
	key := normalizeBenchmarkKey(modelID)
	if key == "" || len(benchmarkCache.byKey) == 0 {
		return modelBenchmark{}, false
	}
	if b, ok := benchmarkCache.byKey[key]; ok {
		return b, true
	}
	// Strip common CPA variant suffixes to match the base AA model family.
	for _, suffix := range []string{"-free", "-contributor", "-highspeed", "-xhigh", "-high", "-medium", "-low", "-max", "-preview"} {
		if strings.HasSuffix(key, suffix) {
			trimmed := strings.TrimSuffix(key, suffix)
			if b, ok := benchmarkCache.byKey[trimmed]; ok {
				return b, true
			}
			// Handle double suffix like "-contributor-free" or "-preview-free"
			for _, suffix2 := range []string{"-contributor", "-preview", "-flash"} {
				if strings.HasSuffix(trimmed, suffix2) {
					if b, ok := benchmarkCache.byKey[strings.TrimSuffix(trimmed, suffix2)]; ok {
						return b, true
					}
				}
			}
		}
	}
	return modelBenchmark{}, false
}

// formatModelWithBenchmark formats `model` with its cached AA score when present (e.g. "`gemini-4-neon-xhigh` (AA 58.6)").
func formatModelWithBenchmark(modelID string) string {
	b, ok := lookupBenchmark(modelID)
	if !ok {
		return fmt.Sprintf("`%s`", modelID)
	}
	score, label := b.PrimaryScore()
	if score <= 0 {
		return fmt.Sprintf("`%s`", modelID)
	}
	return fmt.Sprintf("`%s` (%s %.1f)", modelID, label, score)
}

func benchmarkSnapshotForModels(models []string) (map[string]modelBenchmark, time.Time, string) {
	benchmarkMu.RLock()
	defer benchmarkMu.RUnlock()
	out := make(map[string]modelBenchmark)
	if len(benchmarkCache.byKey) > 0 {
		for _, m := range models {
			if b, ok := lookupBenchmarkLocked(m); ok {
				out[m] = b
			}
		}
	}
	return out, benchmarkCache.fetchedAt, benchmarkCache.errText
}
