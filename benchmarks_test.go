package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAndMatchArtificialAnalysisBenchmarks(t *testing.T) {
	codingHTML := `<html><script>self.__next_f.push([1,"{\"rows\":[{\"id\":\"1\",\"display\":{\"model\":\"Gemini 4 Neon (Xhigh)\"},\"indexScore\":0.586,\"mean\":{\"costUsd\":6.86,\"agentWallTimeSec\":1829},\"safety\":{\"refusedAttemptCount\":0}},{\"id\":\"2\",\"display\":{\"model\":\"Claude Fable 5.2 (Xhigh, Default Fallback)\"},\"indexScore\":0.585,\"mean\":{\"costUsd\":15.47,\"agentWallTimeSec\":3195},\"safety\":{\"refusedAttemptCount\":55}}],\"benchmarkRows\":[\"$31:props:rows:0\",\"$31:props:rows:1\",{\"id\":\"3\",\"display\":{\"model\":\"DeepSeek V4.1 Flash 1017 (Max)\"},\"indexScore\":0.368,\"mean\":{\"costUsd\":0.32,\"agentWallTimeSec\":1887},\"safety\":{\"refusedAttemptCount\":0}},{\"id\":\"4\",\"display\":{\"model\":\"Kimi K3.1 Pro\"},\"indexScore\":0.486,\"mean\":{\"costUsd\":2.94,\"agentWallTimeSec\":2509},\"safety\":{\"refusedAttemptCount\":0}},{\"id\":\"5\",\"display\":{\"model\":\"Beam 1.0\"},\"indexScore\":0.155,\"mean\":{\"costUsd\":0.31,\"agentWallTimeSec\":2427},\"safety\":{\"refusedAttemptCount\":0}},{\"id\":\"6\",\"display\":{\"model\":\"Claude Opus 5.5 Max + GPT-6 Luna High\"},\"indexScore\":0.584}]}"])</script></html>`
	modelsHTML := `<html><script>self.__next_f.push([1,"{\"initialModels\":[{\"slug\":\"claude-fable-5-2\",\"name\":\"Claude Fable 5.2 (Max, Default Fallback)\",\"intelligenceIndex\":64.6,\"frontierCode20\":0.488,\"terminalBench40\":0.596},{\"slug\":\"qwen4-max\",\"name\":\"Qwen4 Max\",\"intelligenceIndex\":42.9,\"frontierCode20\":0.265,\"terminalBench40\":0.485},{\"slug\":\"tencent-hy4\",\"name\":\"Tencent Hy4\",\"intelligenceIndex\":34.6,\"frontierCode20\":0.314,\"terminalBench40\":0.374}]}"])</script></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/coding":
			_, _ = w.Write([]byte(codingHTML))
		case "/models":
			_, _ = w.Write([]byte(modelsHTML))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevCoding, prevModels := benchmarkCodingURL, benchmarkModelsURL
	benchmarkCodingURL = srv.URL + "/coding"
	benchmarkModelsURL = srv.URL + "/models"
	t.Cleanup(func() {
		benchmarkCodingURL = prevCoding
		benchmarkModelsURL = prevModels
		benchmarkMu.Lock()
		benchmarkCache = benchmarkCatalog{byKey: map[string]modelBenchmark{}}
		benchmarkMu.Unlock()
	})

	if err := refreshBenchmarksNow(); err != nil {
		t.Fatalf("refreshBenchmarksNow: %v", err)
	}

	cases := []struct {
		id       string
		wantCode float64
		wantInt  float64
		wantFmt  string
	}{
		{"gemini-4-neon-xhigh", 58.6, 0, "`gemini-4-neon-xhigh` (AA 58.6)"},
		{"claude-fable-5-2", 58.5, 64.6, "`claude-fable-5-2` (AA 58.5)"},
		{"deepseek-v4.1-flash", 36.8, 0, "`deepseek-v4.1-flash` (AA 36.8)"},
		{"kimi-k3.1-pro-highspeed", 48.6, 0, "`kimi-k3.1-pro-highspeed` (AA 48.6)"},
		{"qwen4-max", 0, 42.9, "`qwen4-max` (AA Intel 42.9)"},
		{"hy4", 0, 34.6, "`hy4` (AA Intel 34.6)"},
		{"beam-free", 15.5, 0, "`beam-free` (AA 15.5)"},
	}
	for _, tc := range cases {
		b, ok := lookupBenchmark(tc.id)
		if !ok {
			t.Fatalf("lookupBenchmark(%q) = false, want match", tc.id)
		}
		if b.CodingAgent != tc.wantCode || b.Intelligence != tc.wantInt {
			t.Fatalf("lookupBenchmark(%q) = (code=%.1f, intel=%.1f), want (%.1f, %.1f)", tc.id, b.CodingAgent, b.Intelligence, tc.wantCode, tc.wantInt)
		}
		if got := formatModelWithBenchmark(tc.id); got != tc.wantFmt {
			t.Fatalf("formatModelWithBenchmark(%q) = %q, want %q", tc.id, got, tc.wantFmt)
		}
	}

	// Verify notices include AA scores when benchmarks are cached
	cfg := defaultPluginConfig()
	notice := buildGroupNotice(cfg, modelGroup{ID: "groups/heavy-thinkers"}, nil, "claude-fable-5-2", "", true, nil, nil)
	if !strings.Contains(notice, "`claude-fable-5-2` (AA 58.5)") {
		t.Fatalf("start notice = %q, want AA score included", notice)
	}
	switchNotice := buildGroupNotice(cfg, modelGroup{ID: "groups/heavy-thinkers"}, nil, "gemini-4-neon-xhigh", "claude-fable-5-2", false, nil, nil)
	if !strings.Contains(switchNotice, "`claude-fable-5-2` (AA 58.5) → `gemini-4-neon-xhigh` (AA 58.6)") {
		t.Fatalf("switch notice = %q, want AA scores included", switchNotice)
	}
}
