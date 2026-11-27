package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type streamInterceptRequest struct {
	RequestID    string
	SourceFormat string
	ChunkIndex   int
	Body         []byte
}

type streamInterceptResponse struct {
	Body      []byte
	DropChunk bool
}

type claudeStreamBlock struct {
	kind   string
	index  int
	output int
	frames []map[string]json.RawMessage
	text   strings.Builder
	sealed bool
}

type claudeStreamState struct {
	pending         []byte
	frame           []byte
	active          *claudeStreamBlock
	segment         []*claudeStreamBlock
	next            int
	preserve        bool
	signed          bool
	salvagedToolUse bool
}

var claudeStreams = struct {
	sync.Mutex
	states map[string]*claudeStreamState
}{states: make(map[string]*claudeStreamState)}

func handleStreamIntercept(request []byte) ([]byte, error) {
	var req streamInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode stream intercept: %w", err)
	}
	if req.SourceFormat != "claude" || req.ChunkIndex == -1 {
		return okEnvelope(streamInterceptResponse{Body: req.Body})
	}
	body, err := normalizeClaudeStream(req.RequestID, req.Body)
	if err != nil {
		return nil, err
	}
	return okEnvelope(streamInterceptResponse{Body: body, DropChunk: len(body) == 0})
}

func handleStreamCompletion(request []byte) ([]byte, error) {
	var req struct{ RequestID string }
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("decode request completion: %w", err)
	}
	cleanupClaudeStream(req.RequestID)
	return okEnvelope(struct{}{})
}

func cleanupClaudeStream(requestID string) {
	claudeStreams.Lock()
	defer claudeStreams.Unlock()
	delete(claudeStreams.states, requestID)
}

func normalizeClaudeStream(requestID string, body []byte) ([]byte, error) {
	if requestID == "" {
		return nil, fmt.Errorf("Claude stream normalization requires a request ID")
	}
	claudeStreams.Lock()
	defer claudeStreams.Unlock()
	state, exists := claudeStreams.states[requestID]
	if !exists {
		state = &claudeStreamState{}
		claudeStreams.states[requestID] = state
	}
	state.pending = append(state.pending, body...)
	var out bytes.Buffer
	for {
		end := bytes.IndexByte(state.pending, '\n')
		if end < 0 {
			break
		}
		line := bytes.TrimSuffix(state.pending[:end], []byte("\r"))
		if len(line) == 0 {
			if err := state.processFrame(state.frame, &out); err != nil {
				delete(claudeStreams.states, requestID)
				return nil, fmt.Errorf("normalize Claude stream %s: %w", requestID, err)
			}
			state.frame = nil
		} else {
			state.frame = append(state.frame, line...)
			state.frame = append(state.frame, '\n')
		}
		state.pending = state.pending[end+1:]
	}
	if len(state.pending) == 0 {
		state.pending = nil
	}
	return out.Bytes(), nil
}

func (s *claudeStreamState) processFrame(frame []byte, out *bytes.Buffer) error {
	var data [][]byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("data:")) {
			data = append(data, bytes.TrimPrefix(line[5:], []byte(" ")))
		}
	}
	if len(data) == 0 {
		if len(frame) > 0 {
			out.Write(frame)
			out.WriteByte('\n')
		}
		return nil
	}
	payload := bytes.Join(data, []byte("\n"))
	var event map[string]json.RawMessage
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("decode SSE data: %w", err)
	}
	var fields struct {
		Type         string
		Index        int
		ContentBlock struct {
			Type      string
			Text      string
			Signature string
			Citations []json.RawMessage
		} `json:"content_block"`
		Delta struct {
			Type string
			Text string
		}
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return fmt.Errorf("decode Claude event: %w", err)
	}
	switch fields.Type {
	case "content_block_start":
		if s.active != nil {
			return fmt.Errorf("content block %d started before previous block stopped", fields.Index)
		}
		kind := fields.ContentBlock.Type
		buffered := !s.signed && (kind == "text" || (kind == "thinking" && len(s.segment) > 0))
		if fields.ContentBlock.Signature != "" {
			s.signed = true
		}
		if !buffered {
			if err := s.flush(out); err != nil {
				return err
			}
		}
		block := &claudeStreamBlock{kind: kind, index: fields.Index}
		s.active = block
		if buffered {
			block.frames = append(block.frames, event)
			block.text.WriteString(fields.ContentBlock.Text)
			s.segment = append(s.segment, block)
			// Signed thinking and annotated text must retain their original block boundaries.
			s.preserve = s.preserve || fields.ContentBlock.Signature != "" || len(fields.ContentBlock.Citations) > 0
			return nil
		}
		block.output = s.next
		s.next++
		return emitClaudeStreamEvent(out, event, block.output)
	case "content_block_delta", "content_block_stop":
		if s.active == nil {
			// Mid-stream plugin reload or late stream attachment can join a stream after
			// content_block_start was already forwarded. Pass orphan frames through untouched
			// instead of failing every delta in the stream.
			if s.next == 0 && len(s.segment) == 0 {
				out.Write(frame)
				out.WriteByte('\n')
				return nil
			}
			return fmt.Errorf("%s received without an active block", fields.Type)
		}
		block := s.active
		if fields.Index != block.index {
			return fmt.Errorf("content block index %d does not match active block %d", fields.Index, block.index)
		}
		if fields.Delta.Type == "signature_delta" {
			s.signed = true
		}
		buffered := len(block.frames) > 0
		if buffered {
			block.frames = append(block.frames, event)
			if fields.Type == "content_block_delta" {
				if block.kind == "text" && fields.Delta.Type == "text_delta" {
					block.text.WriteString(fields.Delta.Text)
				} else if block.kind == "text" || fields.Delta.Type == "signature_delta" {
					s.preserve = true
				}
			}
		} else if err := emitClaudeStreamEvent(out, event, block.output); err != nil {
			return err
		}
		if fields.Type == "content_block_stop" {
			block.sealed = true
			s.active = nil
		}
		return nil
	case "message_delta", "message_stop", "error":
		if s.active != nil && fields.Type != "error" {
			return fmt.Errorf("%s received before content block stopped", fields.Type)
		}
		if err := s.flush(out); err != nil {
			return err
		}
		if fields.Type == "message_delta" && s.salvagedToolUse {
			var delta map[string]json.RawMessage
			if json.Unmarshal(event["delta"], &delta) == nil {
				delta["stop_reason"] = json.RawMessage(`"tool_use"`)
				if encodedDelta, err := json.Marshal(delta); err == nil {
					event["delta"] = encodedDelta
					if encodedEvent, err := json.Marshal(event); err == nil {
						out.WriteString("event: message_delta\ndata: ")
						out.Write(encodedEvent)
						out.WriteString("\n\n")
						return nil
					}
				}
			}
		}
	}
	out.Write(frame)
	out.WriteByte('\n')
	return nil
}

func (s *claudeStreamState) flush(out *bytes.Buffer) error {
	if len(s.segment) == 0 {
		return nil
	}
	for _, block := range s.segment {
		if !block.sealed {
			s.preserve = true
		}
	}
	if s.preserve {
		for _, block := range s.segment {
			if block.kind == "text" && block.sealed && len(block.frames) > 0 && strings.Contains(block.text.String(), "```tool_calls") {
				if calls, prefix, suffix, ok := extractFencedToolCalls(block.text.String()); ok {
					if err := s.emitSalvagedToolCalls(out, block.frames[0], calls, prefix, suffix); err != nil {
						return err
					}
					continue
				}
			}
			for _, event := range block.frames {
				if err := emitClaudeStreamEvent(out, event, s.next); err != nil {
					return err
				}
			}
			s.next++
		}
	} else {
		var text strings.Builder
		var firstText map[string]json.RawMessage
		for _, block := range s.segment {
			if block.kind == "text" {
				if firstText == nil {
					firstText = block.frames[0]
				}
				text.WriteString(block.text.String())
				continue
			}
			for _, event := range block.frames {
				if err := emitClaudeStreamEvent(out, event, s.next); err != nil {
					return err
				}
			}
			s.next++
		}
		combined := text.String()
		if calls, prefix, suffix, ok := extractFencedToolCalls(combined); ok {
			if err := s.emitSalvagedToolCalls(out, firstText, calls, prefix, suffix); err != nil {
				return err
			}
		} else {
			if err := s.emitMergedTextBlock(out, firstText, combined); err != nil {
				return err
			}
		}
	}
	s.segment = nil
	s.preserve = false
	return nil
}

func (s *claudeStreamState) emitSalvagedToolCalls(out *bytes.Buffer, firstText map[string]json.RawMessage, calls []salvagedToolCall, prefix, suffix string) error {
	if strings.TrimSpace(prefix) != "" {
		if err := s.emitMergedTextBlock(out, firstText, strings.TrimRight(prefix, " \t\r\n")); err != nil {
			return err
		}
	}
	for i, call := range calls {
		callID := call.ID
		if callID == "" {
			callID = fmt.Sprintf("toolu_salvaged_%d_%d", s.next, i)
		}
		startBlock, err := json.Marshal(struct {
			Type  string         `json:"type"`
			ID    string         `json:"id"`
			Name  string         `json:"name"`
			Input map[string]any `json:"input"`
		}{Type: "tool_use", ID: callID, Name: call.Name, Input: map[string]any{}})
		if err != nil {
			return err
		}
		if err := emitClaudeStreamEvent(out, map[string]json.RawMessage{"type": json.RawMessage(`"content_block_start"`), "content_block": startBlock}, s.next); err != nil {
			return err
		}
		partialJSON := string(bytes.TrimSpace(call.Arguments))
		if partialJSON == "" {
			partialJSON = "{}"
		}
		delta, err := json.Marshal(struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		}{Type: "input_json_delta", PartialJSON: partialJSON})
		if err != nil {
			return err
		}
		if err := emitClaudeStreamEvent(out, map[string]json.RawMessage{"type": json.RawMessage(`"content_block_delta"`), "delta": delta}, s.next); err != nil {
			return err
		}
		if err := emitClaudeStreamEvent(out, map[string]json.RawMessage{"type": json.RawMessage(`"content_block_stop"`)}, s.next); err != nil {
			return err
		}
		s.next++
	}
	if strings.TrimSpace(suffix) != "" {
		if err := s.emitMergedTextBlock(out, firstText, strings.TrimLeft(suffix, " \t\r\n")); err != nil {
			return err
		}
	}
	s.salvagedToolUse = true
	return nil
}

func (s *claudeStreamState) emitMergedTextBlock(out *bytes.Buffer, firstText map[string]json.RawMessage, text string) error {
	var content map[string]json.RawMessage
	if err := json.Unmarshal(firstText["content_block"], &content); err != nil {
		return fmt.Errorf("decode text block: %w", err)
	}
	content["text"] = json.RawMessage(`""`)
	encoded, err := json.Marshal(content)
	if err != nil {
		return err
	}
	startEvent := make(map[string]json.RawMessage, len(firstText))
	for k, v := range firstText {
		startEvent[k] = v
	}
	startEvent["content_block"] = encoded
	if err := emitClaudeStreamEvent(out, startEvent, s.next); err != nil {
		return err
	}
	delta, err := json.Marshal(struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{Type: "text_delta", Text: text})
	if err != nil {
		return err
	}
	if err := emitClaudeStreamEvent(out, map[string]json.RawMessage{"type": json.RawMessage(`"content_block_delta"`), "delta": delta}, s.next); err != nil {
		return err
	}
	if err := emitClaudeStreamEvent(out, map[string]json.RawMessage{"type": json.RawMessage(`"content_block_stop"`)}, s.next); err != nil {
		return err
	}
	s.next++
	return nil
}

func emitClaudeStreamEvent(out *bytes.Buffer, event map[string]json.RawMessage, index int) error {
	event["index"] = json.RawMessage(fmt.Sprintf("%d", index))
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode Claude event: %w", err)
	}
	var kind string
	if err := json.Unmarshal(event["type"], &kind); err != nil {
		return fmt.Errorf("decode Claude event type: %w", err)
	}
	out.WriteString("event: ")
	out.WriteString(kind)
	out.WriteString("\ndata: ")
	out.Write(payload)
	out.WriteString("\n\n")
	return nil
}

type salvagedToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// extractFencedToolCalls detects a ```tool_calls JSON block inside text, repairs invalid JSON
// string escapes emitted by Gemini/Antigravity models (e.g. \', \|, \x27), and returns the
// parsed tool calls alongside any surrounding text.
func extractFencedToolCalls(text string) (calls []salvagedToolCall, prefix, suffix string, ok bool) {
	const openFence = "```tool_calls"
	start := strings.Index(text, openFence)
	if start < 0 {
		return nil, "", "", false
	}
	lineStart := start == 0 || text[start-1] == '\n' || text[start-1] == '\r'
	if !lineStart {
		return nil, "", "", false
	}
	afterOpen := start + len(openFence)
	if afterOpen < len(text) && text[afterOpen] == '\r' {
		afterOpen++
	}
	if afterOpen >= len(text) || text[afterOpen] != '\n' {
		return nil, "", "", false
	}
	afterOpen++
	rest := text[afterOpen:]
	closeOffset := -1
	searchFrom := 0
	for {
		pos := strings.Index(rest[searchFrom:], "```")
		if pos < 0 {
			return nil, "", "", false
		}
		pos += searchFrom
		atLineStart := pos == 0 || rest[pos-1] == '\n' || rest[pos-1] == '\r'
		afterClose := pos + 3
		atLineEnd := afterClose == len(rest) || rest[afterClose] == '\n' || rest[afterClose] == '\r' || rest[afterClose] == ' ' || rest[afterClose] == '\t'
		if atLineStart && atLineEnd {
			closeOffset = pos
			break
		}
		searchFrom = pos + 3
	}
	rawJSON := strings.TrimSpace(rest[:closeOffset])
	parsed, ok := parseFencedToolCallsJSON(rawJSON)
	if !ok || len(parsed) == 0 {
		return nil, "", "", false
	}
	endOfClose := afterOpen + closeOffset + 3
	for endOfClose < len(text) && (text[endOfClose] == ' ' || text[endOfClose] == '\t') {
		endOfClose++
	}
	if endOfClose < len(text) && text[endOfClose] == '\r' {
		endOfClose++
	}
	if endOfClose < len(text) && text[endOfClose] == '\n' {
		endOfClose++
	}
	return parsed, text[:start], text[endOfClose:], true
}

func parseFencedToolCallsJSON(raw string) ([]salvagedToolCall, bool) {
	for _, candidate := range []string{raw, repairInvalidJSONStringEscapes(raw)} {
		var rawList []struct {
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Input     json.RawMessage `json:"input"`
			Function  *struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"function"`
		}
		if err := json.Unmarshal([]byte(candidate), &rawList); err != nil || len(rawList) == 0 {
			continue
		}
		out := make([]salvagedToolCall, 0, len(rawList))
		valid := true
		for _, item := range rawList {
			name := strings.TrimSpace(item.Name)
			args := item.Arguments
			if len(args) == 0 {
				args = item.Input
			}
			if item.Function != nil {
				if name == "" {
					name = strings.TrimSpace(item.Function.Name)
				}
				if len(args) == 0 {
					args = item.Function.Arguments
				}
			}
			if name == "" {
				valid = false
				break
			}
			trimmedArgs := bytes.TrimSpace(args)
			if len(trimmedArgs) == 0 || bytes.Equal(trimmedArgs, []byte("null")) {
				trimmedArgs = []byte("{}")
			} else if trimmedArgs[0] == '"' {
				var unquoted string
				if json.Unmarshal(trimmedArgs, &unquoted) == nil {
					repairedInner := repairInvalidJSONStringEscapes(strings.TrimSpace(unquoted))
					if json.Valid([]byte(repairedInner)) {
						trimmedArgs = []byte(repairedInner)
					} else {
						valid = false
						break
					}
				}
			}
			if len(trimmedArgs) == 0 || trimmedArgs[0] != '{' || !json.Valid(trimmedArgs) {
				valid = false
				break
			}
			out = append(out, salvagedToolCall{
				ID:        strings.TrimSpace(item.ID),
				Name:      name,
				Arguments: append(json.RawMessage(nil), trimmedArgs...),
			})
		}
		if valid && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// repairInvalidJSONStringEscapes fixes non-standard escape sequences inside JSON double-quoted
// string literals: \' -> ', \xHH -> \u00HH, unescaped control bytes -> \u00HH, and any other
// invalid \c -> \\c.
func repairInvalidJSONStringEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	inString := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !inString {
			if ch == '"' {
				inString = true
			}
			b.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inString = false
			b.WriteByte(ch)
			continue
		}
		if ch < 0x20 {
			switch ch {
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				b.WriteString(fmt.Sprintf(`\u%04x`, ch))
			}
			continue
		}
		if ch != '\\' {
			b.WriteByte(ch)
			continue
		}
		if i+1 >= len(s) {
			b.WriteString(`\\`)
			continue
		}
		next := s[i+1]
		switch next {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			b.WriteByte('\\')
			b.WriteByte(next)
			i++
		case 'u':
			if i+5 < len(s) && isHex4(s[i+2:i+6]) {
				b.WriteString(s[i : i+6])
				i += 5
			} else {
				b.WriteString(`\\u`)
				i++
			}
		case 'x':
			if i+3 < len(s) && isHex2(s[i+2:i+4]) {
				b.WriteString(`\u00`)
				b.WriteString(s[i+2 : i+4])
				i += 3
			} else {
				b.WriteString(`\\x`)
				i++
			}
		case '\'':
			b.WriteByte('\'')
			i++
		default:
			b.WriteString(`\\`)
			b.WriteByte(next)
			i++
		}
	}
	return b.String()
}

func isHex2(s string) bool {
	return len(s) == 2 && isHexByte(s[0]) && isHexByte(s[1])
}

func isHex4(s string) bool {
	return len(s) == 4 && isHexByte(s[0]) && isHexByte(s[1]) && isHexByte(s[2]) && isHexByte(s[3])
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// salvageFencedToolCallsNonStream converts leaked ```tool_calls blocks in a non-streaming
// Claude or OpenAI response body into structured tool calls when the response has no native tool calls.
func salvageFencedToolCallsNonStream(body []byte, format string) []byte {
	if !bytes.Contains(body, []byte("```tool_calls")) {
		return body
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return body
	}
	if rawContent, ok := root["content"]; ok {
		var blocks []map[string]json.RawMessage
		if json.Unmarshal(rawContent, &blocks) == nil {
			for _, block := range blocks {
				var typ string
				_ = json.Unmarshal(block["type"], &typ)
				if typ == "tool_use" || typ == "server_tool_use" {
					return body
				}
			}
			var newBlocks []map[string]json.RawMessage
			salvaged := false
			toolSeq := 0
			for _, block := range blocks {
				var typ, txt string
				_ = json.Unmarshal(block["type"], &typ)
				_ = json.Unmarshal(block["text"], &txt)
				if typ != "text" || !strings.Contains(txt, "```tool_calls") {
					newBlocks = append(newBlocks, block)
					continue
				}
				calls, prefix, suffix, ok := extractFencedToolCalls(txt)
				if !ok {
					newBlocks = append(newBlocks, block)
					continue
				}
				salvaged = true
				if trimmed := strings.TrimRight(prefix, " \t\r\n"); strings.TrimSpace(trimmed) != "" {
					textBytes, _ := json.Marshal(trimmed)
					newBlocks = append(newBlocks, map[string]json.RawMessage{
						"type": json.RawMessage(`"text"`),
						"text": textBytes,
					})
				}
				for _, call := range calls {
					callID := call.ID
					if callID == "" {
						callID = fmt.Sprintf("toolu_salvaged_%d", toolSeq)
					}
					toolSeq++
					idBytes, _ := json.Marshal(callID)
					nameBytes, _ := json.Marshal(call.Name)
					newBlocks = append(newBlocks, map[string]json.RawMessage{
						"type":  json.RawMessage(`"tool_use"`),
						"id":    idBytes,
						"name":  nameBytes,
						"input": call.Arguments,
					})
				}
				if trimmed := strings.TrimLeft(suffix, " \t\r\n"); strings.TrimSpace(trimmed) != "" {
					textBytes, _ := json.Marshal(trimmed)
					newBlocks = append(newBlocks, map[string]json.RawMessage{
						"type": json.RawMessage(`"text"`),
						"text": textBytes,
					})
				}
			}
			if salvaged {
				root["content"], _ = json.Marshal(newBlocks)
				root["stop_reason"] = json.RawMessage(`"tool_use"`)
				if out, err := json.Marshal(root); err == nil {
					return out
				}
			}
		}
	}
	_ = format
	return body
}
