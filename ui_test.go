package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestManagementRegistrationPaths(t *testing.T) {
	reg := managementRegistrationPayload()
	wantRoutes := []struct{ method, path string }{
		{http.MethodGet, "/plugins/safeguard-killer/state"},
		{http.MethodGet, "/plugins/safeguard-killer/trail"},
		{http.MethodPost, "/plugins/safeguard-killer/drain"},
		{http.MethodGet, "/plugins/safeguard-killer/payloads"},
		{http.MethodPost, "/plugins/safeguard-killer/preview"},
	}
	if len(reg.Routes) != len(wantRoutes) {
		t.Fatalf("routes = %+v", reg.Routes)
	}
	for i, want := range wantRoutes {
		if reg.Routes[i].Method != want.method || reg.Routes[i].Path != want.path {
			t.Fatalf("routes[%d] = %+v, want %s %s", i, reg.Routes[i], want.method, want.path)
		}
	}
	if len(reg.Resources) != 1 || reg.Resources[0].Path != "/ui" || reg.Resources[0].Menu != "Safeguard Killer" {
		t.Fatalf("resources = %+v", reg.Resources)
	}
}

func callManagement(t *testing.T, method, path string) managementResponse {
	t.Helper()
	raw, errMarshal := json.Marshal(managementRequest{Method: method, Path: path})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	out, errHandle := handleManagement(raw)
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(out, &env); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if !env.OK {
		t.Fatalf("envelope not ok: %s", out)
	}
	var resp managementResponse
	if errUnmarshal := json.Unmarshal(env.Result, &resp); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	return resp
}

func TestHandleManagementState(t *testing.T) {
	hostCall = func(method string, _ any) (json.RawMessage, error) {
		if method == methodHostAuthList {
			return json.RawMessage(`{"files":[{"id":"a","auth_index":"1","provider":"claude"}]}`), nil
		}
		return json.RawMessage(`{"credentials":[{"id":"a","models":["claude-opus-4-8"]}]}`), nil
	}
	t.Cleanup(func() { hostCall = callHost })
	hostMu.Lock()
	hostCache = hostSnapshot{}
	hostMu.Unlock()
	resp := callManagement(t, http.MethodGet, "/v0/management/plugins/safeguard-killer/state")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Headers.Get("Content-Type"), "application/json") {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Headers)
	}
	var state uiState
	if errUnmarshal := json.Unmarshal(resp.Body, &state); errUnmarshal != nil {
		t.Fatalf("body is not uiState JSON: %v: %s", errUnmarshal, resp.Body)
	}
}

func TestHandleManagementUI(t *testing.T) {
	resp := callManagement(t, http.MethodGet, "/v0/resource/plugins/safeguard-killer/ui")
	if !strings.HasPrefix(resp.Headers.Get("Content-Type"), "text/html") {
		t.Fatalf("headers=%v", resp.Headers)
	}
	for _, want := range []string{"/v0/management/plugins/safeguard-killer/state", "/v8/management/config/plugins/configs/safeguard-killer"} {
		if !strings.Contains(string(resp.Body), want) {
			t.Fatalf("ui html does not reference %s", want)
		}
	}
}

func TestGroupSchemaJSONRoundtrip(t *testing.T) {
	want := modelGroup{ID: "best", Name: "General Purpose", Mode: "cost", Models: []groupModel{{ID: "claude-opus-5-5", Quality: 95, Cost: 90}, {ID: "glm-5.3", Quality: 70, Cost: 10}}}
	raw, errMarshal := json.Marshal(want)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var fields map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal(raw, &fields); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if len(fields) != 4 || fields["id"] == nil || fields["name"] == nil || fields["mode"] == nil || fields["models"] == nil {
		t.Fatalf("group fields = %s", raw)
	}
	var models []map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal(fields["models"], &models); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	for _, m := range models {
		if len(m) != 3 || m["id"] == nil || m["quality"] == nil || m["cost"] == nil {
			t.Fatalf("model fields = %s", fields["models"])
		}
	}
	var got modelGroup
	if errUnmarshal := json.Unmarshal(raw, &got); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	if got.ID != want.ID || got.Name != want.Name || got.Mode != want.Mode || len(got.Models) != len(want.Models) {
		t.Fatalf("roundtrip = %+v, want %+v", got, want)
	}
	for i := range want.Models {
		if got.Models[i] != want.Models[i] {
			t.Fatalf("roundtrip model %d = %+v, want %+v", i, got.Models[i], want.Models[i])
		}
	}
}

func TestUIUsesRatedGroupSchema(t *testing.T) {
	for _, want := range []string{`data-gfield="mode"`, `data-mfield="quality"`, `data-mfield="cost"`, "Quality first", "Lower cost first", "model_scores"} {
		if !strings.Contains(uiHTML, want) {
			t.Fatalf("ui html does not contain %s", want)
		}
	}
	for _, gone := range []string{"strategy", "cheap_models", "cheap_first", "cheap_probe", "tier_up_after", "tier_ups"} {
		if strings.Contains(uiHTML, gone) {
			t.Fatalf("ui html still references %s", gone)
		}
	}
}

func TestHandleManagementRejectsMalformed(t *testing.T) {
	if _, errHandle := handleManagement([]byte("{")); errHandle == nil {
		t.Fatal("malformed request accepted")
	}
	raw, _ := json.Marshal(managementRequest{Method: http.MethodGet, Path: "/v0/management/plugins/safeguard-killer/other"})
	if _, errHandle := handleManagement(raw); errHandle == nil {
		t.Fatal("unknown path accepted")
	}
}

func TestHandleManagementPayloadCaptureAndPreview(t *testing.T) {
	reqBody := `{"model":"claude-fable-5-2","messages":[{"role":"user","content":"start"},{"role":"system","content":"<total_tokens>100 tokens left</total_tokens>"},{"role":"assistant","content":[{"type":"text","text":"STOP AND LOOK AT THAT!"},{"type":"tool_use","id":"cpa_gemini_1234567890abcdef1234567890abcdef","name":"Bash","input":{"command":"ls"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"cpa_gemini_1234567890abcdef1234567890abcdef","content":"ok"},{"type":"text","text":"continue"}]}]}`
	interceptRaw, _ := json.Marshal(requestInterceptRequest{Stream: true, Headers: http.Header{}, Body: []byte(reqBody)})
	if _, err := handleRequestIntercept(interceptRaw); err != nil {
		t.Fatalf("handleRequestIntercept: %v", err)
	}

	rawGet, _ := json.Marshal(managementRequest{Method: http.MethodGet, Path: "/v0/management/plugins/safeguard-killer/payloads"})
	outGet, errGet := handleManagement(rawGet)
	if errGet != nil {
		t.Fatalf("handleManagement(payloads): %v", errGet)
	}
	var envGet envelope
	_ = json.Unmarshal(outGet, &envGet)
	var respGet managementResponse
	_ = json.Unmarshal(envGet.Result, &respGet)
	var captured capturedPayload
	if err := json.Unmarshal(respGet.Body, &captured); err != nil {
		t.Fatalf("decode captured payload: %v", err)
	}
	if captured.RawMessages != 4 || captured.SanitizedMessages != 3 {
		t.Fatalf("captured messages = %d -> %d, want 4 -> 3", captured.RawMessages, captured.SanitizedMessages)
	}
	if strings.Contains(string(captured.SanitizedBody), "STOP AND LOOK AT THAT") {
		t.Fatalf("CoT narration survived in sanitized capture: %s", captured.SanitizedBody)
	}

	rawPreview, _ := json.Marshal(managementRequest{
		Method: http.MethodPost,
		Path:   "/v0/management/plugins/safeguard-killer/preview",
		Body:   []byte(reqBody),
	})
	outPrev, errPrev := handleManagement(rawPreview)
	if errPrev != nil {
		t.Fatalf("handleManagement(preview): %v", errPrev)
	}
	var envPrev envelope
	_ = json.Unmarshal(outPrev, &envPrev)
	var respPrev managementResponse
	_ = json.Unmarshal(envPrev.Result, &respPrev)
	var preview capturedPayload
	if err := json.Unmarshal(respPrev.Body, &preview); err != nil {
		t.Fatalf("decode preview payload: %v", err)
	}
	if preview.ID != "preview" || preview.SanitizedMessages != 3 {
		t.Fatalf("preview = %+v", preview.capturedPayloadMeta)
	}
}

