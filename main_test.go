package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestStatusCLIReadsActorStateWithoutMutation(t *testing.T) {
	session := "status-read-only-" + t.Name()
	key := StateKey{SessionKey: session, ActorKey: "worker-a"}
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	state := NewState("implementing")
	state.EnterPhase("testing")
	state.Signals["approved"] = Signal{OneTimeUse: true}
	state.RepoRoot = "C:/repo"
	state.TouchedFiles = []string{"generated.txt"}
	state.PendingTools["internal-tool"] = ToolSnapshot{RepoRoot: "C:/repo"}
	if err := SaveState(key, state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath(key))
	if err != nil {
		t.Fatal(err)
	}

	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testBinary, "status", "--session", session, "--agent", key.ActorKey, "--json")
	cmd.Env = append(os.Environ(), testCLIEnv+"=1", envActorID+"=")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ward status: %v\n%s", err, output)
	}
	var got map[string]any
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("decode status output %q: %v", output, err)
	}
	if got["session_key"] != session || got["actor_key"] != key.ActorKey || got["phase"] != "testing" {
		t.Fatalf("status = %#v, want selected actor in testing phase", got)
	}
	phaseStack, phaseStackOK := got["phase_stack"].([]any)
	if !phaseStackOK || len(phaseStack) != 1 || phaseStack[0] != "implementing" {
		t.Fatalf("phase stack = %#v, want implementing", phaseStack)
	}
	signals, signalsOK := got["signals"].([]any)
	if !signalsOK || len(signals) != 1 || signals[0] != "approved" {
		t.Fatalf("signals = %#v, want approved", signals)
	}
	owned, ownedOK := got["session_owned_paths"].([]any)
	if !ownedOK || len(owned) != 1 || owned[0] != "generated.txt" {
		t.Fatalf("session owned paths = %#v, want generated.txt", owned)
	}
	if got["pending_tool_count"] != float64(1) {
		t.Fatalf("pending tool count = %#v, want 1", got["pending_tool_count"])
	}
	if _, exposed := got["pending_tools"]; exposed {
		t.Fatal("ward status exposed internal pending tool snapshots")
	}

	after, err := os.ReadFile(statePath(key))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("ward status mutated actor state")
	}
	if _, err := os.Stat(activeActorBindingPath(session)); !os.IsNotExist(err) {
		t.Fatalf("ward status created an active actor binding: %v", err)
	}
}

func TestHookAndCommandResolveIdenticalStateKeys(t *testing.T) {
	t.Setenv(envActorID, "environment-worker")

	hookKey, err := stateKeyFromHook(ToolEvent{
		SessionID: "shared-session",
		AgentID:   "worker-a",
		AgentType: "scout",
	})
	if err != nil {
		t.Fatal(err)
	}
	commandKey, err := stateKeyFromCommandArgs(
		[]string{"ward", "set", "scout", "--session", "shared-session", "--agent", "worker-a"},
		"process-session",
		"C:/repo",
	)
	if err != nil {
		t.Fatal(err)
	}
	if hookKey != commandKey {
		t.Fatalf("hook key %#v != command key %#v", hookKey, commandKey)
	}
	if hookKey.ActorKey != "worker-a" {
		t.Fatalf("agent_type became identity: %#v", hookKey)
	}
}

func TestActorResolutionPrecedence(t *testing.T) {
	t.Setenv(envActorID, "environment-worker")
	t.Setenv(envSession, "wrong-environment-session")

	hookKey, err := stateKeyFromHook(ToolEvent{SessionID: "session", AgentID: "event-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if hookKey.ActorKey != "event-worker" {
		t.Fatalf("hook actor = %q, want event agent_id", hookKey.ActorKey)
	}
	if hookKey.SessionKey != "session" {
		t.Fatalf("hook session = %q, want event session_id", hookKey.SessionKey)
	}

	commandKey, err := stateKeyFromCommandArgs(
		[]string{"ward", "set", "scout", "--session", "session", "--agent", "explicit-worker"},
		"",
		"C:/repo",
	)
	if err != nil {
		t.Fatal(err)
	}
	if commandKey.ActorKey != "explicit-worker" {
		t.Fatalf("command actor = %q, want explicit --agent", commandKey.ActorKey)
	}

	hookEnvKey, err := stateKeyFromHook(ToolEvent{SessionID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	if hookEnvKey.ActorKey != "environment-worker" {
		t.Fatalf("hook environment actor = %q", hookEnvKey.ActorKey)
	}
	commandEnvKey, err := stateKeyFromCommandArgs(
		[]string{"ward", "set", "scout", "--session", "session"},
		"",
		"C:/repo",
	)
	if err != nil {
		t.Fatal(err)
	}
	if commandEnvKey.ActorKey != "environment-worker" {
		t.Fatalf("command environment actor = %q", commandEnvKey.ActorKey)
	}
}

func TestMainActorCompatibilityWhenNoActorIsSupplied(t *testing.T) {
	t.Setenv(envActorID, "")

	hookKey, err := stateKeyFromHook(ToolEvent{SessionID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	commandKey, err := stateKeyFromCommandArgs(
		[]string{"ward", "set", "foreman", "--session", "session"},
		"",
		"C:/repo",
	)
	if err != nil {
		t.Fatal(err)
	}
	if hookKey.ActorKey != MainActorKey || commandKey.ActorKey != MainActorKey {
		t.Fatalf("main compatibility failed: hook=%#v command=%#v", hookKey, commandKey)
	}
}

func TestCommandActorBindingCarriesIntoActorlessHook(t *testing.T) {
	session := "command-hook-binding-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	t.Setenv(envActorID, "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{
		"ward", "set", "integrator", "--session", session, "--agent", "cli-worker",
	}
	commandKey, err := commandStateKey()
	if err != nil {
		t.Fatal(err)
	}
	if commandKey.ActorKey != "cli-worker" {
		t.Fatalf("command actor = %q, want cli-worker", commandKey.ActorKey)
	}

	hookKey, err := stateKeyFromHook(ToolEvent{SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	if hookKey != commandKey {
		t.Fatalf("actor-less hook key %#v != preceding command key %#v", hookKey, commandKey)
	}
	os.Args = []string{"ward", "allow", "approved", "--session", session}
	inheritedCommandKey, err := commandStateKey()
	if err != nil {
		t.Fatal(err)
	}
	if inheritedCommandKey != commandKey {
		t.Fatalf("actor-less command key %#v != active command key %#v", inheritedCommandKey, commandKey)
	}

	os.Args = []string{
		"ward", "set", "foreman", "--session", session, "--agent", MainActorKey,
	}
	if _, err := commandStateKey(); err != nil {
		t.Fatal(err)
	}
	hookKey, err = stateKeyFromHook(ToolEvent{SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	if hookKey.ActorKey != MainActorKey {
		t.Fatalf("main rebind resolved actor %q", hookKey.ActorKey)
	}
}

func TestHookInputInitializationUsesRealClaudeIdentity(t *testing.T) {
	session := "hook-init-" + t.Name()
	key := StateKey{SessionKey: session, ActorKey: "agent-real"}
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	t.Setenv(envActorID, "environment-worker")

	input := []byte(`{"hook_event_name":"SubagentStart","session_id":"` + session + `","agent_id":"agent-real","agent_type":"scout"}`)
	resolved, err := SetPhaseFromHookInput(input, "scout")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != key {
		t.Fatalf("initialized key = %#v, want %#v", resolved, key)
	}
	state, err := LoadState(key)
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != "scout" || state.AgentType != "scout" {
		t.Fatalf("initialized state = %#v, want scout phase and metadata", state)
	}
}

func TestHookInputInitializationCannotFallBackToMain(t *testing.T) {
	session := "hook-init-main-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	t.Setenv(envActorID, "")

	input := []byte(`{"hook_event_name":"SubagentStart","session_id":"` + session + `","agent_type":"scout"}`)
	if _, err := SetPhaseFromHookInput(input, "scout"); err == nil {
		t.Fatal("expected missing worker identity to fail")
	}
	if _, err := LoadState(StateKey{SessionKey: session, ActorKey: MainActorKey}); !os.IsNotExist(err) {
		t.Fatalf("missing worker identity mutated main: %v", err)
	}
}

func TestSubagentStartInitializesRealWorkerIdempotentlyWithoutMutatingOtherActors(t *testing.T) {
	session := "subagent-start-" + t.Name()
	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	workerKey := StateKey{SessionKey: session, ActorKey: "worker-a"}
	siblingKey := StateKey{SessionKey: session, ActorKey: "worker-b"}
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	t.Setenv(envActorID, "")

	mainState := NewState("foreman")
	mainState.History = []string{"Read"}
	siblingState := NewState("experiment-worker")
	siblingState.Signals["approved"] = Signal{}
	if err := SaveState(mainKey, mainState); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(siblingKey, siblingState); err != nil {
		t.Fatal(err)
	}
	mainBefore, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	siblingBefore, err := LoadState(siblingKey)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte(`{"hook_event_name":"SubagentStart","session_id":"` + session + `","agent_id":"worker-a","agent_type":"scout"}`)
	for range 2 {
		resolved, err := InitializeActorFromHookInput(input)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != workerKey {
			t.Fatalf("initialized key = %#v, want %#v", resolved, workerKey)
		}
	}

	workerState, err := LoadState(workerKey)
	if err != nil {
		t.Fatal(err)
	}
	if workerState.Phase != UninitializedPhase || workerState.AgentType != "scout" {
		t.Fatalf("worker state = %#v, want uninitialized scout", workerState)
	}
	loadedMain, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	loadedSibling, err := LoadState(siblingKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loadedMain, mainBefore) {
		t.Fatalf("SubagentStart mutated main: got %#v, want %#v", loadedMain, mainBefore)
	}
	if !reflect.DeepEqual(loadedSibling, siblingBefore) {
		t.Fatalf("SubagentStart mutated sibling: got %#v, want %#v", loadedSibling, siblingBefore)
	}

	workerState.Phase = "scout"
	if err := SaveState(workerKey, workerState); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeActorFromHookInput(input); err != nil {
		t.Fatal(err)
	}
	workerState, err = LoadState(workerKey)
	if err != nil {
		t.Fatal(err)
	}
	if workerState.Phase != "scout" {
		t.Fatalf("idempotent SubagentStart reset initialized phase to %q", workerState.Phase)
	}
}

func TestSubagentStopDeletesOnlyWorkerAndSessionEndDeletesFamily(t *testing.T) {
	session := "lifecycle-" + t.Name()
	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	workerA := StateKey{SessionKey: session, ActorKey: "worker-a"}
	workerB := StateKey{SessionKey: session, ActorKey: "worker-b"}
	t.Cleanup(func() {
		_ = PurgeSessionFamily(session)
		_ = os.RemoveAll(endedFamilyPath(session))
	})

	for key, phase := range map[StateKey]string{
		mainKey: "foreman", workerA: "scout", workerB: "experiment-worker",
	} {
		if err := SaveState(key, NewState(phase)); err != nil {
			t.Fatal(err)
		}
	}
	legacyData := []byte(`{"phase":"planning"}`)
	if err := os.WriteFile(legacyStatePath(session), legacyData, 0o644); err != nil {
		t.Fatal(err)
	}
	const registryPID uint32 = 42001
	if err := registerSession(registryPID, session, "C:/repo"); err != nil {
		t.Fatal(err)
	}
	if err := bindActiveActor(workerA); err != nil {
		t.Fatal(err)
	}

	stopInput := []byte(`{"hook_event_name":"SubagentStop","session_id":"` + session + `","agent_id":"worker-a"}`)
	if err := DeleteActorFromHookInput(stopInput); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(workerA); !os.IsNotExist(err) {
		t.Fatalf("worker A still exists: %v", err)
	}
	if _, err := loadActiveActor(session); !os.IsNotExist(err) {
		t.Fatalf("SubagentStop retained worker A binding: %v", err)
	}
	for _, key := range []StateKey{mainKey, workerB} {
		if _, err := LoadState(key); err != nil {
			t.Fatalf("SubagentStop deleted %#v: %v", key, err)
		}
	}
	if err := bindActiveActor(workerB); err != nil {
		t.Fatal(err)
	}

	endInput := []byte(`{"hook_event_name":"SessionEnd","session_id":"` + session + `"}`)
	if err := DeleteSessionFromHookInput(endInput); err != nil {
		t.Fatal(err)
	}
	// SessionEnd retires the family to a tombstone: the live family dir is
	// gone, but a resumed session (same id) resurrects it on the next load.
	if _, err := os.Stat(sessionFamilyPath(session)); !os.IsNotExist(err) {
		t.Fatalf("SessionEnd left live family in place: %v", err)
	}
	if _, err := os.Stat(endedFamilyPath(session)); err != nil {
		t.Fatalf("SessionEnd did not leave a tombstone: %v", err)
	}
	if _, err := os.Stat(legacyStatePath(session)); !os.IsNotExist(err) {
		t.Fatalf("SessionEnd retained legacy state: %v", err)
	}
	if _, err := lookupSessionByPID(registryPID); err == nil {
		t.Fatal("SessionEnd retained PID registry entry")
	}

	// Resume: loading any actor state resurrects the retired family intact.
	resumed, err := LoadState(mainKey)
	if err != nil {
		t.Fatalf("resume after SessionEnd failed to resurrect state: %v", err)
	}
	if resumed.Phase != "foreman" {
		t.Fatalf("resurrected state lost phase, got %q", resumed.Phase)
	}
	if _, err := os.Stat(endedFamilyPath(session)); !os.IsNotExist(err) {
		t.Fatalf("tombstone survived resurrection: %v", err)
	}
	if _, err := LoadState(workerB); err != nil {
		t.Fatalf("resurrection lost sibling actor: %v", err)
	}
	hookKey, err := stateKeyFromHook(ToolEvent{SessionID: session})
	if err != nil {
		t.Fatalf("resurrection lost active actor binding: %v", err)
	}
	if hookKey.ActorKey != workerB.ActorKey {
		t.Fatalf("resurrected hook actor = %q, want %q", hookKey.ActorKey, workerB.ActorKey)
	}
}

func TestEndedFamilySweepPurgesExpiredTombstones(t *testing.T) {
	session := "sweep-" + t.Name()
	key := StateKey{SessionKey: session, ActorKey: MainActorKey}
	t.Cleanup(func() {
		_ = PurgeSessionFamily(session)
		_ = os.RemoveAll(endedFamilyPath(session))
	})
	if err := SaveState(key, NewState("planning")); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSessionFamily(session); err != nil {
		t.Fatal(err)
	}
	ended := endedFamilyPath(session)
	expired := time.Now().Add(-endedFamilyTTL - time.Hour)
	if err := os.Chtimes(ended, expired, expired); err != nil {
		t.Fatal(err)
	}
	sweepEndedFamilies()
	if _, err := os.Stat(ended); !os.IsNotExist(err) {
		t.Fatalf("expired tombstone survived sweep: %v", err)
	}
}

func TestUninitializedWorkerCannotMutateMain(t *testing.T) {
	session := "uninitialized-" + t.Name()
	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	workerKey := StateKey{SessionKey: session, ActorKey: "missing-worker"}
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })

	if err := SaveState(mainKey, NewState("foreman")); err != nil {
		t.Fatal(err)
	}
	if err := UpdateState(workerKey, UninitializedPhase, func(state *State) error {
		state.UpdateEvent(ToolEvent{Tool: "Bash", Input: map[string]any{}, EventType: "pre_tool"}, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mainState, err := LoadState(mainKey)
	if err != nil {
		t.Fatal(err)
	}
	workerState, err := LoadState(workerKey)
	if err != nil {
		t.Fatal(err)
	}
	if mainState.Phase != "foreman" || len(mainState.History) != 0 {
		t.Fatalf("worker mutated main: %#v", mainState)
	}
	if workerState.Phase != UninitializedPhase || len(workerState.History) != 1 {
		t.Fatalf("worker did not remain isolated/uninitialized: %#v", workerState)
	}
}

func TestResolveCommandSessionPrefersClaudeCodeEnv(t *testing.T) {
	// Claude Code exports CLAUDE_CODE_SESSION_ID into tool subshells; `ward
	// allow` must use it instead of falling back to the fragile process-tree
	// walk (broken under msys bash on Windows) and then a cwd hash.
	t.Setenv(envSession, "")
	t.Setenv(envCodexThread, "")
	t.Setenv(envClaudeSession, "claude-env-session")

	session, source := resolveCommandSessionWithSource(nil, "", "C:/repo")
	if session != "claude-env-session" {
		t.Fatalf("session = %q, want claude-env-session", session)
	}
	if source != "CLAUDE_CODE_SESSION_ID" {
		t.Fatalf("source = %q, want CLAUDE_CODE_SESSION_ID", source)
	}
}

func TestResolveCommandSessionPrecedence(t *testing.T) {
	t.Setenv(envSession, "ward-session")
	t.Setenv(envCodexThread, "codex-thread")
	t.Setenv(envClaudeSession, "claude-env-session")

	// Explicit --session outranks everything.
	session, source := resolveCommandSessionWithSource(
		[]string{"ward", "allow", "x", "--session", "explicit"}, "proc", "C:/repo")
	if session != "explicit" || source != "--session" {
		t.Fatalf("got (%q, %q), want (explicit, --session)", session, source)
	}

	// WARD_SESSION outranks the Claude env.
	session, source = resolveCommandSessionWithSource(nil, "proc", "C:/repo")
	if session != "ward-session" || source != envSession {
		t.Fatalf("got (%q, %q), want (ward-session, %s)", session, source, envSession)
	}

	// The Codex thread (innermost agent when nested) outranks the Claude env,
	// which in turn outranks the process walk.
	t.Setenv(envSession, "")
	session, source = resolveCommandSessionWithSource(nil, "proc", "C:/repo")
	if session != "codex-thread" || source != envCodexThread {
		t.Fatalf("got (%q, %q), want (codex-thread, %s)", session, source, envCodexThread)
	}
	t.Setenv(envCodexThread, "")
	session, source = resolveCommandSessionWithSource(nil, "proc", "C:/repo")
	if session != "claude-env-session" || source != envClaudeSession {
		t.Fatalf("got (%q, %q), want (claude-env-session, %s)", session, source, envClaudeSession)
	}

	// With no env at all: process walk, then cwd fallback.
	t.Setenv(envClaudeSession, "")
	session, source = resolveCommandSessionWithSource(nil, "proc", "C:/repo")
	if session != "proc" || source != "process-tree" {
		t.Fatalf("got (%q, %q), want (proc, process-tree)", session, source)
	}
	session, source = resolveCommandSessionWithSource(nil, "", "C:/repo")
	if source != "cwd-fallback" || len(session) == 0 || session[:3] != "wd-" {
		t.Fatalf("got (%q, %q), want wd- fallback", session, source)
	}
}
