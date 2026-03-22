package main

import (
	"os"
	"testing"
)

func TestDetectClaude(t *testing.T) {
	data, err := os.ReadFile("testdata/claude_pretool.json")
	if err != nil {
		t.Fatal(err)
	}

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}

	if agent != AgentClaude {
		t.Errorf("expected AgentClaude, got %v", agent)
	}
	if event.Tool != "Bash" {
		t.Errorf("expected tool Bash, got %q", event.Tool)
	}
	if event.SessionID != "test-session-123" {
		t.Errorf("expected session test-session-123, got %q", event.SessionID)
	}
	if event.EventType != "pre_tool" {
		t.Errorf("expected pre_tool, got %q", event.EventType)
	}
	if cmd, ok := event.Input["command"].(string); !ok || cmd != "python -c \"print('hello')\"" {
		t.Errorf("unexpected command: %v", event.Input["command"])
	}
}

func TestDetectGemini(t *testing.T) {
	data, err := os.ReadFile("testdata/gemini_beforetool.json")
	if err != nil {
		t.Fatal(err)
	}

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}

	if agent != AgentGemini {
		t.Errorf("expected AgentGemini, got %v", agent)
	}
	if event.Tool != "Bash" {
		t.Errorf("expected tool Bash, got %q", event.Tool)
	}
	if event.SessionID != "gemini-session-456" {
		t.Errorf("expected session gemini-session-456, got %q", event.SessionID)
	}
	if event.EventType != "pre_tool" {
		t.Errorf("expected pre_tool, got %q", event.EventType)
	}
}

func TestDetectCodex(t *testing.T) {
	data, err := os.ReadFile("testdata/codex_aftertool.json")
	if err != nil {
		t.Fatal(err)
	}

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}

	if agent != AgentCodex {
		t.Errorf("expected AgentCodex, got %v", agent)
	}
	if event.Tool != "local_shell" {
		t.Errorf("expected tool local_shell, got %q", event.Tool)
	}
	if event.SessionID != "codex-session-789" {
		t.Errorf("expected session codex-session-789, got %q", event.SessionID)
	}
	if event.EventType != "post_tool" {
		t.Errorf("expected post_tool, got %q", event.EventType)
	}
	// Codex command should be flattened from []string to string
	if cmd, ok := event.Input["command"].(string); !ok || cmd != "python -c print('hello')" {
		t.Errorf("unexpected codex command: %v", event.Input["command"])
	}
}

func TestDetectInvalidJSON(t *testing.T) {
	_, _, err := DetectAndParse([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDetectUnknownFormat(t *testing.T) {
	_, _, err := DetectAndParse([]byte(`{"foo": "bar"}`))
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestFormatClaudeDeny(t *testing.T) {
	result := &Result{Action: "deny", Message: "blocked"}
	resp := FormatResponse(AgentClaude, result)

	hook, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatal("expected hookSpecificOutput")
	}
	if hook["permissionDecision"] != "deny" {
		t.Errorf("expected deny, got %v", hook["permissionDecision"])
	}
	if hook["permissionDecisionReason"] != "blocked" {
		t.Errorf("expected blocked, got %v", hook["permissionDecisionReason"])
	}
}

func TestFormatGeminiDeny(t *testing.T) {
	result := &Result{Action: "deny", Message: "blocked"}
	resp := FormatResponse(AgentGemini, result)

	if resp["decision"] != "deny" {
		t.Errorf("expected deny, got %v", resp["decision"])
	}
	if resp["reason"] != "blocked" {
		t.Errorf("expected blocked, got %v", resp["reason"])
	}
}

func TestFormatCodexReturnsNil(t *testing.T) {
	result := &Result{Action: "deny", Message: "blocked"}
	resp := FormatResponse(AgentCodex, result)
	if resp != nil {
		t.Errorf("expected nil for codex, got %v", resp)
	}
}
