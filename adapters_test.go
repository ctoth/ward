package main

import (
	"encoding/json"
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

func TestDetectClaudePreservesTaskIdentity(t *testing.T) {
	data := []byte(`{
		"hook_event_name":"PreToolUse",
		"session_id":"shared-session",
		"agent_id":"agent-7f3a",
		"agent_type":"scout",
		"cwd":"C:/repo",
		"tool_name":"Read",
		"tool_input":{"file_path":"prompts/scout.md"}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentClaude {
		t.Fatalf("expected AgentClaude, got %v", agent)
	}
	if event.AgentID != "agent-7f3a" {
		t.Fatalf("AgentID = %q, want agent-7f3a", event.AgentID)
	}
	if event.AgentType != "scout" {
		t.Fatalf("AgentType = %q, want scout", event.AgentType)
	}
}

func TestDetectClaudeOldPayloadUsesMainActor(t *testing.T) {
	data := []byte(`{
		"hook_event_name":"PreToolUse",
		"session_id":"legacy-session",
		"cwd":"C:/repo",
		"tool_name":"Read",
		"tool_input":{}
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if event.AgentID != "" || event.AgentType != "" {
		t.Fatalf("old payload identity = (%q, %q), want empty values", event.AgentID, event.AgentType)
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

	commands, ok := event.Input["commands"].([]any)
	if !ok {
		t.Fatalf("expected parsed commands on codex event, got %T", event.Input["commands"])
	}
	if len(commands) != 1 {
		t.Fatalf("expected 1 parsed command, got %d", len(commands))
	}
	first, ok := commands[0].(map[string]any)
	if !ok {
		t.Fatalf("expected command map, got %T", commands[0])
	}
	if first["name"] != "python" {
		t.Errorf("expected parsed command name python, got %v", first["name"])
	}
	if first["full"] != "python -c print('hello')" {
		t.Errorf("expected parsed command full string, got %v", first["full"])
	}
}

func TestDetectCodexTreatsArgvAsSingleCommand(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-session-argv",
		"cwd":"C:/tmp",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"local_shell",
			"tool_input":{
				"params":{
					"command":["echo",";","git","stash"]
				}
			}
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentCodex {
		t.Fatalf("expected AgentCodex, got %v", agent)
	}

	commands, ok := event.Input["commands"].([]any)
	if !ok {
		t.Fatalf("expected parsed commands on codex event, got %T", event.Input["commands"])
	}
	if len(commands) != 1 {
		t.Fatalf("expected literal argv to stay one command, got %d commands: %#v", len(commands), commands)
	}
	first, ok := commands[0].(map[string]any)
	if !ok {
		t.Fatalf("expected command map, got %T", commands[0])
	}
	if first["name"] != "echo" {
		t.Errorf("expected argv command name echo, got %v", first["name"])
	}
	if first["full"] != "echo ; git stash" {
		t.Errorf("expected argv command full string preserved literally, got %v", first["full"])
	}
}

func TestDetectCodexPreservesExplicitActor(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-session",
		"agent_id":"codex-worker-2",
		"cwd":"C:/tmp",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"local_shell",
			"tool_input":{"params":{"command":["go","test","./..."]}}
		}
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if event.AgentID != "codex-worker-2" {
		t.Fatalf("AgentID = %q, want codex-worker-2", event.AgentID)
	}
}

func TestParsedCommandMapsExposeGitMetadata(t *testing.T) {
	parsed := parseArgvCommand([]string{"git", "checkout", "--", "src/main.go"})
	commands := parsedCommandMaps(parsed)
	if len(commands) != 1 {
		t.Fatalf("expected 1 command map, got %d", len(commands))
	}
	first := commands[0].(map[string]any)
	if first["git_subcommand"] != "checkout" {
		t.Fatalf("expected git_subcommand checkout, got %v", first["git_subcommand"])
	}
	if first["git_category"] != "restore" {
		t.Fatalf("expected git_category restore, got %v", first["git_category"])
	}
	args, ok := first["git_args"].([]any)
	if !ok || len(args) == 0 || args[0] != "--" {
		t.Fatalf("expected git_args with -- separator, got %#v", first["git_args"])
	}
	paths, ok := first["git_paths"].([]any)
	if !ok || len(paths) != 1 || paths[0] != "src/main.go" {
		t.Fatalf("expected git_paths with src/main.go, got %#v", first["git_paths"])
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
	resp := FormatResponse(AgentClaude, "pre_tool", result)

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
	resp := FormatResponse(AgentGemini, "pre_tool", result)

	if resp["decision"] != "deny" {
		t.Errorf("expected deny, got %v", resp["decision"])
	}
	if resp["reason"] != "blocked" {
		t.Errorf("expected blocked, got %v", resp["reason"])
	}
}

func TestFormatCodexReturnsNil(t *testing.T) {
	result := &Result{Action: "deny", Message: "blocked"}
	resp := FormatResponse(AgentCodex, "post_tool", result)
	if resp != nil {
		t.Errorf("expected nil for codex, got %v", resp)
	}
}

func TestFormatGeminiAfterToolContext(t *testing.T) {
	result := &Result{Action: "context", Message: "extra context"}
	resp := FormatResponse(AgentGemini, "post_tool", result)

	if _, exists := resp["systemMessage"]; exists {
		t.Fatalf("expected after-tool context to avoid systemMessage, got %v", resp)
	}
	hook, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("expected hookSpecificOutput, got %T", resp["hookSpecificOutput"])
	}
	if hook["hookEventName"] != "AfterTool" {
		t.Errorf("expected AfterTool hook name, got %v", hook["hookEventName"])
	}
	if hook["additionalContext"] != "extra context" {
		t.Errorf("expected additionalContext, got %v", hook["additionalContext"])
	}
}

func TestEncodeResponseSkipsNilCodexOutput(t *testing.T) {
	result := &Result{Action: "deny", Message: "blocked"}
	out, err := EncodeResponse(AgentCodex, "post_tool", result)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("expected nil output for codex, got %q", string(out))
	}
}

func TestEncodeResponseMarshalsGeminiContext(t *testing.T) {
	result := &Result{Action: "context", Message: "extra context"}
	out, err := EncodeResponse(AgentGemini, "post_tool", result)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected encoded output")
	}

	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	hook, ok := decoded["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("expected hookSpecificOutput, got %T", decoded["hookSpecificOutput"])
	}
	if hook["additionalContext"] != "extra context" {
		t.Errorf("expected additionalContext, got %v", hook["additionalContext"])
	}
}
