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

func TestDetectCodexCompatiblePreToolCmdAlias(t *testing.T) {
	data := []byte(`{
		"hook_event_name":"PreToolUse",
		"session_id":"codex-pretool-session",
		"cwd":"C:/repo-a",
		"tool_name":"Bash",
		"tool_input":{
			"cmd":"ward enter adversary",
			"workdir":"C:/repo-b"
		}
	}`)

	event, _, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := event.Input["command"]; got != "ward enter adversary" {
		t.Fatalf("normalized command = %#v, want ward enter adversary", got)
	}
	if event.CWD != "C:/repo-b" {
		t.Fatalf("CWD = %q, want cmd workdir", event.CWD)
	}
	if !isWardControlPlaneCommand(event.Input) {
		t.Fatalf("cmd alias was not recognized as an exact Ward control-plane command: %#v", event.Input)
	}
}

func TestDetectCodexExecCommandCmdAlias(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-exec-session",
		"cwd":"C:/repo-a",
		"hook_event":{
			"event_type":"before_tool_use",
			"tool_name":"exec_command",
			"tool_input":{
				"params":{
					"cmd":"Get-Content -Raw AGENTS.md",
					"workdir":"C:/repo-b"
				}
			}
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentCodex {
		t.Fatalf("agent = %v, want Codex", agent)
	}
	if canonicalToolName(event.Tool) != "Bash" {
		t.Fatalf("canonical tool = %q, want Bash", canonicalToolName(event.Tool))
	}
	if event.EventType != "pre_tool" {
		t.Fatalf("event type = %q, want pre_tool", event.EventType)
	}
	if got := event.Input["command"]; got != "Get-Content -Raw AGENTS.md" {
		t.Fatalf("normalized command = %#v, want Get-Content command", got)
	}
	commands, ok := event.Input["commands"].([]any)
	if !ok || len(commands) != 1 {
		t.Fatalf("parsed commands = %#v, want one command", event.Input["commands"])
	}
}

func TestDetectCodexLocalShellUsesWorkdirAsCWD(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-workdir-session",
		"cwd":"C:/repo-a",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"local_shell",
			"tool_input":{
				"params":{
					"command":["git","add","--","owned.txt"],
					"workdir":"C:/repo-b"
				}
			}
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentCodex {
		t.Fatalf("agent = %v, want Codex", agent)
	}
	if event.CWD != "C:/repo-b" {
		t.Fatalf("CWD = %q, want local shell workdir", event.CWD)
	}
	if got := EffectiveRepoDir(event, "C:/repo-c"); got != "C:/repo-b" {
		t.Fatalf("effective repo dir = %q, want local shell workdir", got)
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

func TestDetectCodexApplyPatchExtractsTouchedPaths(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-patch-session",
		"cwd":"C:/repo-a",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"apply_patch",
			"tool_input":{
				"input_type":"custom",
				"input":"*** Begin Patch\n*** Update File: C:\\repo-b\\old name.txt\n*** Move to: C:\\repo-b\\new name.txt\n@@\n-old\n+new\n*** Add File: C:\\repo-b\\added.txt\n+added\n*** Delete File: C:\\repo-b\\deleted.txt\n*** End Patch"
			}
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentCodex {
		t.Fatalf("agent = %v, want Codex", agent)
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

func TestDetectCodexApplyPatchExtractsTouchedPathsFromHookCommand(t *testing.T) {
	data := []byte(`{
		"session_id":"codex-patch-command-session",
		"cwd":"C:/repo-a",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"apply_patch",
			"tool_input":{
				"command":"*** Begin Patch\n*** Update File: C:\\repo-b\\owned.txt\n@@\n-old\n+new\n*** End Patch"
			}
		}
	}`)

	event, agent, err := DetectAndParse(data)
	if err != nil {
		t.Fatal(err)
	}
	if agent != AgentCodex {
		t.Fatalf("agent = %v, want Codex", agent)
	}
	if event.Input["file_path"] != "C:/repo-b/owned.txt" {
		t.Fatalf("file_path = %#v, want command-shaped patched path", event.Input["file_path"])
	}
	if got := EffectiveRepoDir(event, "C:/repo-c"); got != "C:/repo-b" {
		t.Fatalf("effective repo dir = %q, want patched file repo", got)
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
