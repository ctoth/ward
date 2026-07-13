package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func loadTestGuard(t *testing.T) *Guard {
	t.Helper()
	facts, err := LoadFactsFromDir("testdata/facts")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFromDir("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(facts, rules)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestSessionFromArgsUsesCodexThreadID(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"ward", "adopt", "src/example.go"}
	t.Setenv(envSession, "")
	t.Setenv(envCodexThread, "codex-thread-123")

	if got := sessionFromArgs(); got != "codex-thread-123" {
		t.Fatalf("sessionFromArgs() = %q, want Codex thread ID", got)
	}
}

func TestSessionFromArgsPrefersWardSessionOverCodexThreadID(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"ward", "adopt", "src/example.go"}
	t.Setenv(envSession, "explicit-session")
	t.Setenv(envCodexThread, "codex-thread-123")

	if got := sessionFromArgs(); got != "explicit-session" {
		t.Fatalf("sessionFromArgs() = %q, want WARD_SESSION", got)
	}
}

func TestLoadFact(t *testing.T) {
	name, fact, err := LoadFact("testdata/facts/git_branch.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if name != "git_branch" {
		t.Errorf("expected name git_branch, got %q", name)
	}
	if fact.Command != "echo main" {
		t.Errorf("expected command 'echo main', got %q", fact.Command)
	}
}

func TestLoadFactMissingCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := writeFile(path, "type: bool\n"); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadFact(path)
	if err == nil {
		t.Error("expected error for missing 'command'")
	}
}

func TestLoadFactsFromDir(t *testing.T) {
	facts, err := LoadFactsFromDir("testdata/facts")
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Errorf("expected 2 facts, got %d", len(facts))
	}
	if facts["git_branch"].Command != "echo main" {
		t.Errorf("expected git_branch command 'echo main', got %q", facts["git_branch"].Command)
	}
	if facts["has_pyproject"].Type != "bool" {
		t.Errorf("expected has_pyproject type 'bool', got %q", facts["has_pyproject"].Type)
	}
}

func TestLoadFactsFromDirMissing(t *testing.T) {
	facts, err := LoadFactsFromDir("testdata/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if facts != nil {
		t.Errorf("expected nil from missing dir, got %v", facts)
	}
}

func TestNewGuardInvalidCEL(t *testing.T) {
	// Write a rule file with bad CEL
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(rulesDir, "bad.yaml"), `
when: 'this is not valid CEL %%% !!!'
action: deny
message: test
`); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromDir(rulesDir)
	if err != nil {
		t.Fatal(err) // parse error
	}

	_, err = NewGuard(nil, rules)
	if err == nil {
		t.Error("expected error for invalid CEL")
	}
}

func TestLoadRulesFromDir(t *testing.T) {
	rules, err := LoadRulesFromDir("testdata/rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 9 {
		t.Errorf("expected 9 rules, got %d", len(rules))
	}
}

func TestLoadRulesFromDirMissing(t *testing.T) {
	rules, err := LoadRulesFromDir("testdata/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from missing dir, got %d", len(rules))
	}
}

func TestLoadRuleMissingWhen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := writeFile(path, "action: deny\nmessage: test\n"); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRule(path)
	if err == nil {
		t.Error("expected error for missing 'when'")
	}
}

func TestMergeFacts(t *testing.T) {
	global := map[string]Fact{
		"a": {Command: "echo a"},
		"b": {Command: "echo b"},
	}
	project := map[string]Fact{
		"b": {Command: "echo B-override"},
		"c": {Command: "echo c"},
	}
	merged := MergeFacts(global, project)

	if merged["a"].Command != "echo a" {
		t.Error("expected global fact 'a' preserved")
	}
	if merged["b"].Command != "echo B-override" {
		t.Error("expected project fact 'b' to override global")
	}
	if merged["c"].Command != "echo c" {
		t.Error("expected project fact 'c' present")
	}
}

func TestNewState(t *testing.T) {
	s := NewState("planning")
	if s.Phase != "planning" {
		t.Errorf("expected planning, got %q", s.Phase)
	}
	if len(s.History) != 0 {
		t.Errorf("expected empty history, got %d entries", len(s.History))
	}
}

func TestStateHistory(t *testing.T) {
	s := NewState("implementing")

	s.Update("Read", nil)
	s.Update("Read", nil)
	s.Update("Read", nil)

	if len(s.History) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(s.History))
	}
	for i, h := range s.History {
		if h != "Read" {
			t.Errorf("history[%d] = %q, want Read", i, h)
		}
	}

	s.Update("Bash", map[string]any{"command": "ls"})
	if len(s.History) != 4 {
		t.Errorf("expected 4 history entries, got %d", len(s.History))
	}
	if s.History[3] != "Bash" {
		t.Errorf("expected Bash at end, got %q", s.History[3])
	}
}

func TestStateCommitMarker(t *testing.T) {
	s := NewState("implementing")

	s.Update("Edit", nil)
	s.Update("Write", nil)
	s.Update("Bash", map[string]any{"command": "git commit -m 'test'"})

	// Should have: Edit, Write, _commit, Bash
	expected := []string{"Edit", "Write", "_commit", "Bash"}
	if len(s.History) != len(expected) {
		t.Fatalf("expected %d history entries, got %d: %v", len(expected), len(s.History), s.History)
	}
	for i, want := range expected {
		if s.History[i] != want {
			t.Errorf("history[%d] = %q, want %q", i, s.History[i], want)
		}
	}
}

func TestStateCommitMarkerIgnoresRawMention(t *testing.T) {
	s := NewState("implementing")

	s.Update("Edit", nil)
	s.Update("Bash", map[string]any{"command": "echo git commit"})
	s.Update("Edit", nil)

	expected := []string{"Edit", "Bash", "Edit"}
	if len(s.History) != len(expected) {
		t.Fatalf("expected %d history entries, got %d: %v", len(expected), len(s.History), s.History)
	}
	for i, want := range expected {
		if s.History[i] != want {
			t.Errorf("history[%d] = %q, want %q", i, s.History[i], want)
		}
	}
}

func TestStateHistoryCap(t *testing.T) {
	s := NewState("implementing")
	for i := 0; i < 110; i++ {
		s.Update("Read", nil)
	}
	if len(s.History) != maxHistory {
		t.Errorf("expected history capped at %d, got %d", maxHistory, len(s.History))
	}
}

// bashEvent creates a Bash ToolEvent with parsed commands enrichment.
func bashEvent(t *testing.T, command string) ToolEvent {
	t.Helper()
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": command},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	enrichBashCommands(&event)
	return event
}

func TestEvaluatePythonCDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "python -c \"print('hello')\"")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateGitStashDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "git stash")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateEditInPlanningDeny(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("planning")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateEditInImplementingAllow(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow), got %v", result)
	}
}

func TestEvaluateFlailingContext(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	// Build up 4 reads in history; the 5th (the event itself) will be added by Update
	// But Evaluate doesn't call Update — we need 5 reads already in history
	// so the rule sees last 5 are all reads
	for i := 0; i < 5; i++ {
		state.History = append(state.History, "Read")
	}

	event := ToolEvent{
		Tool:      "Read",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected context result, got nil")
	}
	if result.Action != "context" {
		t.Errorf("expected context, got %q", result.Action)
	}
}

func TestEvaluateSafeCommandAllow(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "ls -la")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil (allow) for safe command, got %v", result)
	}
}

// gitBashEvent builds a Bash ToolEvent whose CWD is a real git repo, so
// repoActivation computes live git status for that tree.
func gitBashEvent(t *testing.T, dir, command string) ToolEvent {
	t.Helper()
	event := ToolEvent{
		Tool:      "Bash",
		Input:     map[string]any{"command": command},
		SessionID: "test",
		CWD:       dir,
	}
	enrichBashCommands(&event)
	return event
}

// A tree with ONLY untracked files is safe to switch/pull/rebase — git carries
// untracked files across a switch. The no-dirty-tree-switch guard must not fire.
func TestEvaluateDirtyTreeSwitchUntrackedAllow(t *testing.T) {
	guard := loadTestGuard(t)
	repo := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "tracked.txt")
	gitRun(t, repo, "commit", "-m", "initial")
	// Only an untracked file remains — no staged/unstaged tracked changes.
	if err := os.WriteFile(filepath.Join(repo, "notes.md"), []byte("scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := gitBashEvent(t, repo, "git checkout other-branch")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected allow (nil) switching with only untracked files, got %+v", result)
	}
}

// A tree with an unstaged modification to a tracked file IS unsafe to switch —
// the guard must still deny.
func TestEvaluateDirtyTreeSwitchUnstagedDeny(t *testing.T) {
	guard := loadTestGuard(t)
	repo := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "tracked.txt")
	gitRun(t, repo, "commit", "-m", "initial")
	// Unstaged modification to a tracked file.
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	event := gitBashEvent(t, repo, "git checkout other-branch")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("expected deny switching with unstaged tracked changes, got %+v", result)
	}
}

func TestEvaluateDirtyTreeSwitchSignalAllowsExplicitOverride(t *testing.T) {
	guard := loadTestGuard(t)
	repo := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "tracked.txt")
	gitRun(t, repo, "commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	state.Signals["dirty-tree-switch"] = Signal{OneTimeUse: true}
	event := gitBashEvent(t, repo, "git switch main")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected explicit dirty-tree-switch signal to allow switch, got %+v", result)
	}
}

func TestEvaluateCodexLocalShellMatchesBashRules(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	raw := []byte(`{
		"session_id":"codex-session-789",
		"cwd":"C:/tmp",
		"hook_event":{
			"event_type":"after_tool_use",
			"tool_name":"local_shell",
			"tool_input":{
				"params":{
					"command":["python","-c","print(1)"]
				}
			}
		}
	}`)

	event, _, err := DetectAndParse(raw)
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("expected deny, got %q", result.Action)
	}
}

func TestEvaluateDenyVetoesContext(t *testing.T) {
	// Create a guard with both a deny and context rule that match
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `tool == "Bash" && input.commands.exists(c, c.full.matches("^python[3]?\\s+-c"))`, Action: "deny", Message: "no python -c"},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	for i := 0; i < 5; i++ {
		state.History = append(state.History, "Read")
	}
	event := bashEvent(t, "python -c 'x'")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected deny, got nil")
	}
	if result.Action != "deny" {
		t.Errorf("deny should veto context; got %q", result.Action)
	}
}

func TestEvaluateContextAccumulates(t *testing.T) {
	rules := []Rule{
		{When: `size(last(session.history, 5)) == 5 && last(session.history, 5).all(t, t in ["Read", "Glob", "Grep"])`, Action: "context", Message: "flailing"},
		{When: `since(session.history, "_commit").filter(t, t in ["Edit", "Write"]).size() >= 2`, Action: "context", Message: "uncommitted"},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	// History: Edit, Write, Edit, Read x5 — triggers both rules
	state.History = []string{"Edit", "Write", "Edit", "Read", "Read", "Read", "Read", "Read"}
	event := ToolEvent{
		Tool:      "Read",
		Input:     map[string]any{"file_path": "/tmp/foo.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected context, got nil")
	}
	if result.Action != "context" {
		t.Errorf("expected context, got %q", result.Action)
	}
	// Both messages should be present
	if result.Message != "flailing\nuncommitted" {
		t.Errorf("expected both messages joined, got %q", result.Message)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`C:\Users\Q\foo`, "C:/Users/Q/foo"},
		{"C:/Users/Q/foo", "C:/Users/Q/foo"},
		{"/tmp/foo", "/tmp/foo"},
		{`a\b\c`, "a/b/c"},
	}
	for _, tt := range tests {
		got := NormalizePath(tt.in)
		if got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeInput(t *testing.T) {
	input := map[string]any{
		"file_path": `C:\Users\Q\foo.go`,
		"command":   `echo hello`,
	}
	norm := NormalizeInput(input)
	if norm["file_path"] != "C:/Users/Q/foo.go" {
		t.Errorf("expected normalized file_path, got %q", norm["file_path"])
	}
	// command should NOT be normalized (not a path field)
	if norm["command"] != "echo hello" {
		t.Errorf("command should be unchanged, got %q", norm["command"])
	}
}

func TestEvaluateWithScope(t *testing.T) {
	rules := []Rule{
		{
			Scope:   "output/**",
			When:    `tool in ["Edit", "Write"]`,
			Action:  "deny",
			Message: "Fix upstream, not generated files.",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")

	// Edit in output/ — should be denied
	event := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "output/generated.html"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("expected deny for output/ file, got %v", result)
	}

	// Edit outside output/ — should be allowed
	event2 := ToolEvent{
		Tool:      "Edit",
		Input:     map[string]any{"file_path": "src/main.go"},
		SessionID: "test",
		CWD:       t.TempDir(),
	}
	result2, _, err := Evaluate(guard, state, event2)
	if err != nil {
		t.Fatal(err)
	}
	if result2 != nil {
		t.Errorf("expected allow for src/ file, got %v", result2)
	}
}

func TestStatePersistence(t *testing.T) {
	key := StateKey{SessionKey: "test-persist-" + t.Name(), ActorKey: MainActorKey}
	t.Cleanup(func() { _ = DeleteSessionFamily(key.SessionKey) })
	state := NewState("implementing")
	state.History = []string{"Read", "Bash", "Edit", "Bash", "Read"}

	if err := SaveState(key, state); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(key)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Phase != "implementing" {
		t.Errorf("expected implementing, got %q", loaded.Phase)
	}
	if len(loaded.History) != 5 {
		t.Errorf("expected 5 history entries, got %d", len(loaded.History))
	}
	if loaded.History[2] != "Edit" {
		t.Errorf("expected Edit at index 2, got %q", loaded.History[2])
	}
}

func TestActorStateIsolationWithinSessionFamily(t *testing.T) {
	session := "actor-isolation-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	scoutKey := StateKey{SessionKey: session, ActorKey: "worker-a"}
	experimentKey := StateKey{SessionKey: session, ActorKey: "worker-b"}

	mainState := NewState("foreman")
	mainState.History = []string{"Read"}
	mainState.Signals["manager-only"] = Signal{OneTimeUse: true}
	mainState.AdoptedPaths = []string{"prompts/manager.md"}
	if err := SaveState(mainKey, mainState); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadState(scoutKey); !os.IsNotExist(err) {
		t.Fatalf("uninitialized worker inherited state: %v", err)
	}

	scoutState := NewState("scout")
	scoutState.History = []string{"Read", "Bash"}
	scoutState.TouchedFiles = []string{"reports/scout.md"}
	if err := SaveState(scoutKey, scoutState); err != nil {
		t.Fatal(err)
	}

	experimentState := NewState("experiment-worker")
	experimentState.Signals["experiment-only"] = Signal{OneTimeUse: false}
	experimentState.DiscardablePaths = []string{"scratch/result.txt"}
	if err := SaveState(experimentKey, experimentState); err != nil {
		t.Fatal(err)
	}

	loadedMain, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	loadedScout, err := LoadState(scoutKey)
	if err != nil {
		t.Fatal(err)
	}
	loadedExperiment, err := LoadState(experimentKey)
	if err != nil {
		t.Fatal(err)
	}

	if loadedMain.Phase != "foreman" || len(loadedMain.History) != 1 || len(loadedMain.Signals) != 1 || len(loadedMain.AdoptedPaths) != 1 {
		t.Fatalf("main state contaminated: %#v", loadedMain)
	}
	if loadedScout.Phase != "scout" || len(loadedScout.History) != 2 || len(loadedScout.TouchedFiles) != 1 || len(loadedScout.Signals) != 0 {
		t.Fatalf("scout state contaminated: %#v", loadedScout)
	}
	if loadedExperiment.Phase != "experiment-worker" || len(loadedExperiment.Signals) != 1 || len(loadedExperiment.DiscardablePaths) != 1 || len(loadedExperiment.History) != 0 {
		t.Fatalf("experiment state contaminated: %#v", loadedExperiment)
	}
	if statePath(mainKey) == statePath(scoutKey) || statePath(scoutKey) == statePath(experimentKey) {
		t.Fatal("actors must have separate state files")
	}
}

func TestLegacyMigrationOnlyToMainIsCompleteAndIdempotent(t *testing.T) {
	session := "legacy-migration-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	legacy := NewState("foreman")
	legacy.History = []string{"Read", "Bash"}
	legacy.Signals["legacy-signal"] = Signal{OneTimeUse: false}
	legacy.RepoRoot = "C:/repo"
	legacy.BaselineDirtyPaths = []string{"old.txt"}
	legacy.TouchedFiles = []string{"new.txt"}
	legacy.TouchedSinceCommit = []string{"new.txt"}
	legacy.AdoptedPaths = []string{"adopted.txt"}
	legacy.DiscardablePaths = []string{"discard.txt"}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyStatePath(session), data, 0o644); err != nil {
		t.Fatal(err)
	}

	workerKey := StateKey{SessionKey: session, ActorKey: "worker-before-start"}
	if _, err := LoadState(workerKey); !os.IsNotExist(err) {
		t.Fatalf("worker must not migrate legacy state: %v", err)
	}
	if _, err := os.Stat(legacyStatePath(session)); err != nil {
		t.Fatalf("worker load changed legacy state: %v", err)
	}

	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	migrated, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Phase != "foreman" || len(migrated.History) != 2 || len(migrated.Signals) != 1 || len(migrated.AdoptedPaths) != 1 || len(migrated.DiscardablePaths) != 1 {
		t.Fatalf("migration lost state: %#v", migrated)
	}
	if migrated.SchemaVersion != CurrentStateSchemaVersion || migrated.SessionKey != session || migrated.ActorKey != MainActorKey {
		t.Fatalf("migration identity metadata is wrong: %#v", migrated)
	}
	if _, err := os.Stat(legacyStatePath(session)); !os.IsNotExist(err) {
		t.Fatalf("legacy state still exists after migration: %v", err)
	}

	// Simulate interruption after the actor file was atomically installed but
	// before the legacy file was removed. A retry must keep the actor record and
	// finish cleanup without duplicating or resetting it.
	migrated.History = append(migrated.History, "Edit")
	if err := SaveState(mainKey, migrated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyStatePath(session), data, 0o644); err != nil {
		t.Fatal(err)
	}
	retried, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(retried.History) != 3 || retried.History[2] != "Edit" {
		t.Fatalf("retry replaced the migrated actor record: %#v", retried.History)
	}
	if _, err := os.Stat(legacyStatePath(session)); !os.IsNotExist(err) {
		t.Fatalf("retry did not finish legacy cleanup: %v", err)
	}
}

func TestActorStateRejectsMalformedOrCollidingIdentity(t *testing.T) {
	session := "identity-validation-" + t.Name()
	key := StateKey{SessionKey: session, ActorKey: "worker-a"}
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	if err := os.MkdirAll(filepath.Dir(statePath(key)), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"schema_version":1,"session_key":"other-session","actor_key":"worker-a","phase":"scout"}`)
	if err := os.WriteFile(statePath(key), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(key); err == nil {
		t.Fatal("expected colliding identity diagnostic")
	}

	missingIdentity := []byte(`{"phase":"scout"}`)
	if err := os.WriteFile(statePath(key), missingIdentity, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(key); err == nil {
		t.Fatal("expected missing identity diagnostic")
	}
}

func TestActorUpdatesAreRaceSafeAndSameActorIsSerialized(t *testing.T) {
	session := "actor-race-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	keys := []StateKey{
		{SessionKey: session, ActorKey: "worker-a"},
		{SessionKey: session, ActorKey: "worker-b"},
	}
	var wg sync.WaitGroup
	for _, key := range keys {
		key := key
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := UpdateState(key, "scout", func(state *State) error {
					state.Update("Bash", map[string]any{})
					state.Signals[key.ActorKey] = Signal{OneTimeUse: false}
					state.AdoptedPaths = appendUniquePath(state.AdoptedPaths, key.ActorKey+".txt")
					return nil
				}); err != nil {
					t.Errorf("UpdateState(%s): %v", key.ActorKey, err)
				}
			}()
		}
	}
	wg.Wait()

	for _, key := range keys {
		state, err := LoadState(key)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.History) != 25 {
			t.Fatalf("%s history length = %d, want 25", key.ActorKey, len(state.History))
		}
		if len(state.Signals) != 1 || len(state.AdoptedPaths) != 1 {
			t.Fatalf("%s mutable state lost updates: %#v", key.ActorKey, state)
		}
	}

	serializedKey := StateKey{SessionKey: session, ActorKey: "serialized-worker"}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondLaunched := make(chan struct{})
	errors := make(chan error, 2)
	go func() {
		errors <- UpdateState(serializedKey, "scout", func(state *State) error {
			close(firstEntered)
			<-releaseFirst
			state.Update("Read", map[string]any{})
			return nil
		})
	}()
	<-firstEntered
	go func() {
		close(secondLaunched)
		errors <- UpdateState(serializedKey, "scout", func(state *State) error {
			state.Update("Bash", map[string]any{})
			return nil
		})
	}()
	<-secondLaunched
	close(releaseFirst)
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	serialized, err := LoadState(serializedKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized.History) != 2 || serialized.History[0] != "Read" || serialized.History[1] != "Bash" {
		t.Fatalf("same-actor updates were not serialized: %#v", serialized.History)
	}
}

func TestCompileRule(t *testing.T) {
	good := &Rule{When: `tool == "Bash"`, Action: "deny"}
	if err := CompileRule(good); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	bad := &Rule{When: `this is not valid CEL %%% !!!`, Action: "deny"}
	if err := CompileRule(bad); err == nil {
		t.Error("expected error for invalid CEL")
	}
}

// --- Shell parsing integration tests ---

func TestHeredocFalsePositive(t *testing.T) {
	// git commit with "python -c" in heredoc message should NOT trigger no-python-c
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "git commit -m \"$(cat <<'EOF'\npython -c blah\nEOF\n)\"")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("heredoc content should not trigger deny, got: %s", result.Message)
	}
}

func TestPipeChainTriggers(t *testing.T) {
	// python -c in a pipe should still trigger
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "echo foo | python -c \"import sys\"")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("python -c in pipe should trigger deny, got: %v", result)
	}
}

func TestAndChainTriggers(t *testing.T) {
	// python -c in && chain should still trigger
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "cd /tmp && python -c \"print(1)\"")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("python -c in && chain should trigger deny, got: %v", result)
	}
}

func TestSafeArgsNoFalsePositive(t *testing.T) {
	// echo "git stash is bad" should NOT trigger no-git-stash
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, `echo "git stash is bad"`)

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("echo with 'git stash' in args should not trigger deny, got: %s", result.Message)
	}
}

func TestGitCommitMessageNoFalsePositive(t *testing.T) {
	// git commit -m "python -c is forbidden" should NOT trigger no-python-c
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, `git commit -m "python -c is forbidden"`)

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("commit message with 'python -c' should not trigger deny, got: %s", result.Message)
	}
}

// --- Structured python-rule tests (no-python-c / no-bare-python) ---
// These lock in the conversion from "^python" Full-regex matching to structured
// c.name/c.args matching, including the parser's path/wrapper normalization.

func TestPythonCViaPathDeny(t *testing.T) {
	// no-python-c must see through an absolute interpreter path.
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, `/usr/bin/python3 -c "import sys"`)

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("python -c via absolute path should deny, got: %v", result)
	}
}

func TestBarePythonWithPyprojectDeny(t *testing.T) {
	// no-bare-python (testdata has_pyproject fact = echo true) must fire for a
	// bare interpreter, including the REPL form with no arguments.
	guard := loadTestGuard(t)
	state := NewState("implementing")
	for _, cmd := range []string{"python app.py", "python", "python3 app.py"} {
		event := bashEvent(t, cmd)
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("bare python %q with pyproject should deny, got: %v", cmd, result)
		}
	}
}

func TestUvRunPythonAllowed(t *testing.T) {
	// "uv run python" is the recommended form; the command name is uv, not
	// python, so neither python rule should fire.
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "uv run python app.py")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Errorf("uv run python should not deny, got: %s", result.Message)
	}
}

// TestRunWrapperPythonCDenied is the end-to-end regression for the run-wrapper
// evasion: prefixing "uv run" (or uvx/poetry run/npx/...) must NOT let a
// forbidden inner command slip past a name-based rule. After parser unwrapping,
// "uv run python -c ..." resolves to name=python, so no-python-c fires.
func TestRunWrapperPythonCDenied(t *testing.T) {
	guard := loadTestGuard(t)
	for _, cmd := range []string{
		`uv run python -c "import sys"`,
		`uvx python -c "import sys"`,
		`poetry run python -c "import sys"`,
		`sudo uv run python -c "import sys"`,
	} {
		state := NewState("implementing")
		event := bashEvent(t, cmd)
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("%q should be denied (run-wrapper evasion of no-python-c), got: %v", cmd, result)
		}
	}
}

// --- Phase-gating tests ---

func TestPhaseGatingBasic(t *testing.T) {
	// Rule: deny Bash/Edit/Write when session.phase == "foreman"
	rules := []Rule{
		{
			When:    `session.phase == "foreman" && tool in ["Bash", "Edit", "Write"]`,
			Action:  "deny",
			Message: "foreman cannot use code-editing tools",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	makeEvent := func(toolName string) ToolEvent {
		return ToolEvent{
			Tool:      toolName,
			Input:     map[string]any{},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
	}

	// phase=foreman, tool=Bash → denied
	t.Run("foreman_bash_denied", func(t *testing.T) {
		state := NewState("foreman")
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman phase, got %v", result)
		}
	})

	// phase=foreman, tool=Read → allowed
	t.Run("foreman_read_allowed", func(t *testing.T) {
		state := NewState("foreman")
		result, _, err := Evaluate(guard, state, makeEvent("Read"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Read in foreman phase, got %v", result)
		}
	})

	// phase="" (empty, defaults to planning) → Bash allowed (not foreman)
	t.Run("no_phase_bash_allowed", func(t *testing.T) {
		state := NewState("") // defaults to "planning"
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash with no foreman phase, got %v", result)
		}
	})

	// phase=implementing → Bash allowed
	t.Run("implementing_bash_allowed", func(t *testing.T) {
		state := NewState("implementing")
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash in implementing phase, got %v", result)
		}
	})
}

func TestPhaseGatingFilePathWhitelist(t *testing.T) {
	// Rule: deny Write in foreman EXCEPT when path contains "/prompts/" or "notes-"
	// CEL: deny when foreman + Write + path does NOT match whitelist
	// We use "file_path" in input to safely check for key existence.
	rules := []Rule{
		{
			When: `session.phase == "foreman" && tool == "Write" &&
				(!("file_path" in input) ||
				 !(input.file_path.contains("prompts/") || input.file_path.contains("notes-")))`,
			Action:  "deny",
			Message: "foreman can only write to prompts/ or notes- files",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	// Write to src/foo.py → denied
	t.Run("foreman_write_src_denied", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "src/foo.py"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Write to src/foo.py in foreman, got %v", result)
		}
	})

	// Write to prompts/task.md → allowed
	t.Run("foreman_write_prompts_allowed", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "prompts/task.md"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Write to prompts/task.md in foreman, got %v", result)
		}
	})

	// Write to notes-session.md → allowed
	t.Run("foreman_write_notes_allowed", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "notes-session.md"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Write to notes-session.md in foreman, got %v", result)
		}
	})

	// Write with NO file_path in input → denied (not error)
	t.Run("foreman_write_no_filepath_denied", func(t *testing.T) {
		state := NewState("foreman")
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"content": "hello"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Write with no file_path in foreman, got %v", result)
		}
	})
}

func TestPhaseGatingCELMapKeyAccess(t *testing.T) {
	// Document the correct pattern for checking map keys in CEL.
	//
	// CORRECT: "file_path" in input
	//   The `in` operator checks for key existence in a map. This is the
	//   standard CEL idiom for optional fields.
	//
	// INCORRECT: has(input.file_path)
	//   has() is for protocol buffer field presence checks. On a plain map,
	//   it either errors or returns false — it does NOT check key existence.
	//   When the CEL eval errors, ward silently skips the rule (guard.go ~line 497).

	// Test 1: "file_path" in input works correctly
	t.Run("in_operator_works", func(t *testing.T) {
		rules := []Rule{
			{
				When:    `"file_path" in input && input.file_path.contains("secret")`,
				Action:  "deny",
				Message: "no secret files",
			},
		}
		guard, err := NewGuard(nil, rules)
		if err != nil {
			t.Fatal(err)
		}
		state := NewState("implementing")

		// With file_path containing "secret" → denied
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "secret.txt"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny when file_path contains 'secret', got %v", result)
		}

		// Without file_path → allowed (key not in map, short-circuits safely)
		event2 := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"content": "hello"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result2, _, err := Evaluate(guard, state, event2)
		if err != nil {
			t.Fatal(err)
		}
		if result2 != nil {
			t.Errorf("expected allow when file_path key is absent, got %v", result2)
		}
	})

	// Test 2: has(input.file_path) does NOT work for map key checking.
	// On a plain CEL map, has() with a dotted field access either errors
	// or returns false. When the CEL eval errors, the rule is silently skipped.
	t.Run("has_does_not_work_for_maps", func(t *testing.T) {
		rules := []Rule{
			{
				When:    `has(input.file_path) && input.file_path.contains("secret")`,
				Action:  "deny",
				Message: "no secret files",
			},
		}
		guard, err := NewGuard(nil, rules)
		if err != nil {
			t.Fatal(err)
		}
		state := NewState("implementing")

		// Even with file_path present and containing "secret", has() on a plain
		// map may not behave as expected — it may error or return false,
		// causing the rule to silently not fire.
		event := ToolEvent{
			Tool:      "Write",
			Input:     map[string]any{"file_path": "secret.txt"},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		// has(input.file_path) on a CEL map type may actually work in some
		// CEL-Go versions. We document the behavior here: if has() works,
		// that's fine, but "key" in map is the canonical and reliable pattern.
		// The important thing is: this test documents the pattern.
		// If has() works → result is deny. If has() silently fails → result is nil.
		// Either way, use "key" in map for reliability.
		_ = result // behavior documented; see "in_operator_works" for the correct pattern
	})
}

func TestPhaseGatingCompoundPhaseMatch(t *testing.T) {
	// Rule using startsWith to match "foreman", "foreman:planning", etc.
	rules := []Rule{
		{
			When:    `session.phase.startsWith("foreman") && tool in ["Bash", "Edit", "Write"]`,
			Action:  "deny",
			Message: "foreman modes cannot use code-editing tools",
		},
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}

	makeEvent := func(toolName string) ToolEvent {
		return ToolEvent{
			Tool:      toolName,
			Input:     map[string]any{},
			SessionID: "test",
			CWD:       t.TempDir(),
		}
	}

	// phase="foreman:planning", tool=Bash → denied
	t.Run("foreman_planning_bash_denied", func(t *testing.T) {
		state := &State{Phase: "foreman:planning", History: []string{}}
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman:planning phase, got %v", result)
		}
	})

	// phase="foreman", tool=Bash → denied
	t.Run("foreman_bash_denied", func(t *testing.T) {
		state := NewState("foreman")
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result == nil || result.Action != "deny" {
			t.Errorf("expected deny for Bash in foreman phase, got %v", result)
		}
	})

	// phase="implementing", tool=Bash → allowed
	t.Run("implementing_bash_allowed", func(t *testing.T) {
		state := NewState("implementing")
		result, _, err := Evaluate(guard, state, makeEvent("Bash"))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Errorf("expected allow for Bash in implementing phase, got %v", result)
		}
	})
}

// --- WARD_RULES_PATH / WARD_FACTS_PATH tests ---

func TestEnvPathDirsSingle(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(rulesDir, "env-rule.yaml"), `
when: 'tool == "Bash"'
action: deny
message: env rule fired
`); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WARD_RULES_PATH", rulesDir)

	dirs := envPathDirs("WARD_RULES_PATH")
	if len(dirs) != 1 || dirs[0] != rulesDir {
		t.Fatalf("expected [%s], got %v", rulesDir, dirs)
	}

	rules, err := LoadRulesFromDir(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule from env path dir, got %d", len(rules))
	}
}

func TestEnvPathDirsMultiple(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	if err := writeFile(filepath.Join(dir1, "rule1.yaml"), `
when: 'tool == "Bash"'
action: deny
message: rule1
`); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir2, "rule2.yaml"), `
when: 'tool == "Edit"'
action: context
message: rule2
`); err != nil {
		t.Fatal(err)
	}

	sep := string(os.PathListSeparator)
	t.Setenv("WARD_RULES_PATH", dir1+sep+dir2)

	dirs := envPathDirs("WARD_RULES_PATH")
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d: %v", len(dirs), dirs)
	}

	// Load rules from both
	var allRules []Rule
	for _, d := range dirs {
		rules, err := LoadRulesFromDir(d)
		if err != nil {
			t.Fatal(err)
		}
		allRules = append(allRules, rules...)
	}
	if len(allRules) != 2 {
		t.Errorf("expected 2 rules from two env path dirs, got %d", len(allRules))
	}
}

func TestEnvPathDirsNonexistent(t *testing.T) {
	t.Setenv("WARD_RULES_PATH", "/nonexistent/ward/rules/dir")

	dirs := envPathDirs("WARD_RULES_PATH")
	if len(dirs) != 1 {
		t.Fatalf("expected 1 dir entry, got %d", len(dirs))
	}

	// LoadRulesFromDir should handle nonexistent gracefully
	rules, err := LoadRulesFromDir(dirs[0])
	if err != nil {
		t.Fatalf("expected no error for nonexistent dir, got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from nonexistent dir, got %d", len(rules))
	}
}

func TestEnvPathDirsEmpty(t *testing.T) {
	t.Setenv("WARD_RULES_PATH", "")

	dirs := envPathDirs("WARD_RULES_PATH")
	if len(dirs) != 0 {
		t.Errorf("expected 0 dirs for empty env var, got %d: %v", len(dirs), dirs)
	}
}

func TestEnvPathDirsUnset(t *testing.T) {
	// t.Setenv not called — env var not set
	dirs := envPathDirs("WARD_RULES_PATH")
	if len(dirs) != 0 {
		t.Errorf("expected 0 dirs for unset env var, got %d: %v", len(dirs), dirs)
	}
}

func TestEnvFactsPathSingle(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "env_fact.yaml"), `
command: echo env-fact-value
`); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WARD_FACTS_PATH", dir)

	dirs := envPathDirs("WARD_FACTS_PATH")
	if len(dirs) != 1 || dirs[0] != dir {
		t.Fatalf("expected [%s], got %v", dir, dirs)
	}

	facts, err := LoadFactsFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Errorf("expected 1 fact from env path dir, got %d", len(facts))
	}
	if facts["env_fact"].Command != "echo env-fact-value" {
		t.Errorf("unexpected command: %q", facts["env_fact"].Command)
	}
}

func TestEnvFactsPathNonexistent(t *testing.T) {
	t.Setenv("WARD_FACTS_PATH", "/nonexistent/ward/facts/dir")

	dirs := envPathDirs("WARD_FACTS_PATH")
	facts, err := LoadFactsFromDir(dirs[0])
	if err != nil {
		t.Fatalf("expected no error for nonexistent dir, got %v", err)
	}
	if facts != nil {
		t.Errorf("expected nil from nonexistent dir, got %v", facts)
	}
}

func TestLoadGuardWithEnvRulesPath(t *testing.T) {
	// Create a temp dir with a rule, set WARD_RULES_PATH, and verify loadGuard picks it up
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "env-test-rule.yaml"), `
when: 'tool == "Bash" && input.command == "env-test-sentinel"'
action: deny
message: env rule loaded
`); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WARD_RULES_PATH", dir)

	guard, err := loadGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// The env rule should be among the guard's rules
	found := false
	for _, r := range guard.Rules {
		if r.Message == "env rule loaded" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected env rule to be loaded via WARD_RULES_PATH, but it was not found")
	}
}

// helper
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// TestMixedChainBarePythonStillDenied closes the regex-exemption hole: a
// blessed "uv run python" in the same command string must NOT exempt a bare
// python sibling. The rule must check the wrapper chain per command (c.via),
// not a substring of the whole command line.
func TestMixedChainBarePythonStillDenied(t *testing.T) {
	guard := loadTestGuard(t)
	state := NewState("implementing")
	event := bashEvent(t, "uv run python ok.py && python evil.py")

	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Errorf("bare python beside a uv-run sibling should deny, got: %v", result)
	}
}

// TestUvRunPythonAllowedViaWrapperChain locks the exemption to the parsed
// wrapper chain for each supported run wrapper.
func TestUvRunPythonAllowedViaWrapperChain(t *testing.T) {
	guard := loadTestGuard(t)
	for _, cmd := range []string{
		"uv run python app.py",
		"poetry run python app.py",
		"pdm run python app.py",
		"sudo uv run python app.py",
	} {
		state := NewState("implementing")
		event := bashEvent(t, cmd)
		result, _, err := Evaluate(guard, state, event)
		if err != nil {
			t.Fatal(err)
		}
		if result != nil && result.Action == "deny" {
			t.Errorf("%q should not deny, got: %s", cmd, result.Message)
		}
	}
}

// The no-stage-unowned builtin must fire for a direct unowned add (positive)
// and must ALSO fire when the pathspec is a shell variable inside a loop —
// observed in the field: `for f in ...; do git add "$f"; done` staged 18
// unowned paths without a deny.
func TestNoStageUnownedBuiltinCatchesDirectAndLoopVariableAdds(t *testing.T) {
	rules, err := LoadRulesFromDir("builtin_profiles/git-discipline/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	repo := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "unowned.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	state.TouchedFiles = []string{"owned.txt"}

	direct := gitBashEvent(t, repo, "git add unowned.txt")
	result, _, err := Evaluate(guard, state, direct)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("direct unowned add must deny, got %+v", result)
	}

	loop := gitBashEvent(t, repo, `for f in unowned.txt; do git add "$f" 2>/dev/null || echo "BLOCKED: $f"; done`)
	result, _, err = Evaluate(guard, state, loop)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("loop-variable unowned add must deny, got %+v", result)
	}

	owned := gitBashEvent(t, repo, "git add owned.txt")
	result, _, err = Evaluate(guard, state, owned)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Fatalf("owned add must not deny, got %+v", result)
	}
}

// A cd-prefixed git command must be evaluated against the repo it TARGETS,
// not the shell's cwd. Before EffectiveRepoDir, `cd repo && git add ...`
// issued from outside any repository ran with repo.in_git == false and every
// git-discipline rule silently skipped (a full bypass); and the same command
// issued from a DIFFERENT repo was judged against that repo's scope (false
// positives on legitimately-owned files).
func TestCdPrefixedGitEvaluatesAgainstTargetRepo(t *testing.T) {
	rules, err := LoadRulesFromDir("builtin_profiles/git-discipline/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	repo := initTestRepo(t)
	// unowned.txt exists before the baseline snapshot: pre-existing dirt.
	// owned.txt never touches the baseline — it stands for a file the agent
	// created after the session started (the rule is list-based, so it need
	// not exist on disk).
	if err := os.WriteFile(filepath.Join(repo, "unowned.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir() // NOT a git repo
	repoFwd := NormalizePath(repo)

	// Mimic the production hook: repo status comes from the effective dir.
	prepare := func(command string) (*State, ToolEvent) {
		event := gitBashEvent(t, outside, command)
		state := NewState("implementing")
		status, _ := ComputeRepoStatus(EffectiveRepoDir(event))
		state.SyncRepo(status)
		state.TouchedFiles = appendUniquePath(state.TouchedFiles, "owned.txt")
		return state, event
	}

	// Bypass closed: staging an unowned file through a cd prefix denies.
	state, event := prepare(`cd ` + repoFwd + ` && git add unowned.txt`)
	result, _, err := Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("cd-prefixed unowned add must deny, got %+v", result)
	}

	// Same through git -C.
	state, event = prepare(`git -C ` + repoFwd + ` add unowned.txt`)
	result, _, err = Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("git -C unowned add must deny, got %+v", result)
	}

	// False positive closed: a touched file stages fine through a cd prefix.
	state, event = prepare(`cd ` + repoFwd + ` && git add owned.txt`)
	result, _, err = Evaluate(guard, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Fatalf("cd-prefixed owned add must not deny, got %+v", result)
	}
}
