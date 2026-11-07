package main

import (
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
