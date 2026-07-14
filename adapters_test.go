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

func TestDetectCodexClaudeCompatiblePayload(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-session",
		"turn_id":"codex-turn",
		"cwd":"C:/repo",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_input":{"command":"git status"},
		"tool_use_id":"tool-1"
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentClaude {
		t.Fatalf("agent = %v, want Claude-compatible", agent)
	}
	if event.Tool != "Bash" || event.EventType != "pre_tool" {
		t.Fatalf("event = (%q, %q), want Bash pre_tool", event.Tool, event.EventType)
	}
	if event.SessionID != "codex-session" {
		t.Fatalf("session = %q, want codex-session", event.SessionID)
	}
	if event.ToolUseID != "tool-1" {
		t.Fatalf("tool use id = %q, want tool-1", event.ToolUseID)
	}
	commands, ok := event.Input["commands"].([]any)
	if !ok || len(commands) != 1 {
		t.Fatalf("commands = %#v, want one parsed command", event.Input["commands"])
	}
}

func TestDetectCodexPostToolUsePreservesCorrelation(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-session",
		"turn_id":"codex-turn",
		"cwd":"C:/repo",
		"hook_event_name":"PostToolUse",
		"tool_name":"Bash",
		"tool_input":{"command":"uv run generator.py"},
		"tool_use_id":"tool-2"
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentClaude {
		t.Fatalf("agent = %v, want Claude-compatible", agent)
	}
	if event.EventType != "post_tool" || event.ToolUseID != "tool-2" || event.ToolFailed {
		t.Fatalf("post event = %#v, want correlated successful post_tool", event)
	}
}

func TestDetectClaudePostToolUseFailurePreservesCorrelation(t *testing.T) {
	data := []byte(`{
		"session_id":"claude-session",
		"cwd":"C:/repo",
		"hook_event_name":"PostToolUseFailure",
		"tool_name":"Bash",
		"tool_input":{"command":"uv run generator.py"},
		"tool_use_id":"tool-3"
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventType != "post_tool" || event.ToolUseID != "tool-3" || !event.ToolFailed {
		t.Fatalf("failure event = %#v, want correlated failed post_tool", event)
	}
}

func TestEffectiveRepoDirUsesActiveRepoWhenCodexOmitsWorkdir(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-multi-repo-session",
		"cwd":"C:/repo-a",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_input":{"command":"git add -- spec/tasks.md"}
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	resolveStatus := func(path string) (*RepoStatus, error) {
		return &RepoStatus{InGit: true, Root: NormalizePath(path)}, nil
	}
	if got := effectiveRepoDirWithStatus(event, "C:/repo-b", resolveStatus); got != "C:/repo-b" {
		t.Fatalf("effective repo dir = %q, want active repo fallback", got)
	}
}

func TestDetectCodexPreservesExplicitActor(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-session",
		"agent_id":"codex-worker-2",
		"agent_type":"worker",
		"cwd":"C:/tmp",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_input":{"command":"go test ./..."}
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if event.AgentID != "codex-worker-2" {
		t.Fatalf("AgentID = %q, want codex-worker-2", event.AgentID)
	}
}

func TestDetectCodexApplyPatchExtractsTouchedPaths(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-patch-session",
		"cwd":"C:/repo-a",
		"hook_event_name":"PreToolUse",
		"tool_name":"apply_patch",
		"tool_input":{
			"command":"*** Begin Patch\n*** Update File: C:\\repo-b\\old name.txt\n*** Move to: C:\\repo-b\\new name.txt\n@@\n-old\n+new\n*** Add File: C:\\repo-b\\added.txt\n+added\n*** Delete File: C:\\repo-b\\deleted.txt\n*** End Patch"
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentClaude {
		t.Fatalf("agent = %v, want Claude-compatible", agent)
	}
	if event.Input["file_path"] != "C:/repo-b/old name.txt" {
		t.Fatalf("file_path = %#v, want first patched path", event.Input["file_path"])
	}
	paths, ok := event.Input["file_paths"].([]string)
	if !ok {
		t.Fatalf("file_paths type = %T, want []string", event.Input["file_paths"])
	}
	want := []string{
		"C:/repo-b/old name.txt",
		"C:/repo-b/new name.txt",
		"C:/repo-b/added.txt",
		"C:/repo-b/deleted.txt",
	}
	if len(paths) != len(want) {
		t.Fatalf("file_paths = %#v, want %#v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("file_paths = %#v, want %#v", paths, want)
		}
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

func TestParsedCommandMapsExposeReadOnlyClassification(t *testing.T) {
	commands := parsedCommandMaps(ParseCommands("Get-Content -Raw AGENTS.md"))
	if len(commands) != 1 {
		t.Fatalf("expected 1 command map, got %d", len(commands))
	}
	first := commands[0].(map[string]any)
	if first["read_only"] != true {
		t.Fatalf("read_only = %#v, want true", first["read_only"])
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

func TestParsedCommandMapsExposeVia(t *testing.T) {
	commands := parsedCommandMaps(ParseCommands("uv run python app.py"))
	if len(commands) != 1 {
		t.Fatalf("expected 1 command map, got %d", len(commands))
	}
	first := commands[0].(map[string]any)
	via, ok := first["via"].([]any)
	if !ok || len(via) != 1 || via[0] != "uv" {
		t.Fatalf("expected via [uv], got %#v", first["via"])
	}

	bare := parsedCommandMaps(ParseCommands("python app.py"))
	firstBare := bare[0].(map[string]any)
	viaBare, ok := firstBare["via"].([]any)
	if !ok || len(viaBare) != 0 {
		t.Fatalf("expected empty via list for bare command, got %#v", firstBare["via"])
	}
}
