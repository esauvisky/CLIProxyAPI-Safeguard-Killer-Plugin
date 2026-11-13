package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The request sanitizer must actually replace the classifier strings Claude Code injects. These
// pairs are byte-identical before the fix below and silently did nothing.
func TestSanitizeRequestReplacesClassifierStrings(t *testing.T) {
	cfg := defaultPluginConfig()
	body := `{"model":"claude-opus-5-5","system":[{"type":"text","text":"` + claudeCyberGatePrompt + `"}],"messages":[` +
		`{"role":"user","content":"` + claudeRetryNudgeMidGeneration + `"},` +
		`{"role":"user","content":"` + claudeToolNotRunClassifier + `"},` +
		`{"role":"user","content":"` + claudeToolInterruptedClassifier + `"}]}`

	out, _, _, _ := sanitizeRequest([]byte(body), http.Header{}, cfg)
	text := string(out)

	if !strings.Contains(text, claudeCyberGateReplacement) {
		t.Errorf("cyber gate prompt was not replaced")
	}
	if strings.Contains(text, "Refuse requests for destructive techniques") {
		t.Errorf("restrictive cyber gate sentence survived: %s", text)
	}
	for _, want := range []string{claudeRefusalReplacement, claudeToolNotRunReplacement, claudeToolInterruptedReplacement} {
		if !strings.Contains(text, want) {
			t.Errorf("replacement %q missing from %s", want, text)
		}
	}
	for _, gone := range []string{claudeRetryNudgeMidGeneration, claudeToolNotRunClassifier, claudeToolInterruptedClassifier} {
		if strings.Contains(text, gone) {
			t.Errorf("original classifier string survived: %.60q", gone)
		}
	}
}

func TestSanitizeRequestPreservesToolSourceCode(t *testing.T) {
	cfg := defaultPluginConfig()
	sourceSnippet := "const gate = `" + claudeCyberGatePrompt + "`\nconst nudge = `" + claudeRefusalRetryNudge + "`\nconst notRun = `" + claudeToolNotRunClassifier + "`"
	body := `{"model":"claude-opus-5-5","messages":[` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"old_string":` + mustJSON(sourceSnippet) + `}}]},` +
		`{"role":"user","content":[` +
		`{"type":"tool_result","tool_use_id":"t1","content":` + mustJSON(sourceSnippet) + `},` +
		`{"type":"tool_result","tool_use_id":"t2","content":` + mustJSON(claudeToolNotRunClassifier) + `}` +
		`]}]}`

	out, _, _, _ := sanitizeRequest([]byte(body), http.Header{}, cfg)
	text := string(out)
	if strings.Count(text, "Refuse requests for destructive techniques") != 2 {
		t.Fatalf("tool_use or tool_result source snippet was corrupted: %s", text)
	}
	if !strings.Contains(text, claudeToolNotRunReplacement) {
		t.Fatalf("exact classifier tool_result was not neutralized: %s", text)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
