package main

import (
	"os"
	"testing"
)

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

func TestHookInputInitializationUsesRealClaudeIdentity(t *testing.T) {
	session := "hook-init-" + t.Name()
	key := StateKey{SessionKey: session, ActorKey: "agent-real"}
	t.Cleanup(func() { _ = DeleteSessionFamily(session) })
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
	t.Cleanup(func() { _ = DeleteSessionFamily(session) })
	t.Setenv(envActorID, "")

	input := []byte(`{"hook_event_name":"SubagentStart","session_id":"` + session + `","agent_type":"scout"}`)
	if _, err := SetPhaseFromHookInput(input, "scout"); err == nil {
		t.Fatal("expected missing worker identity to fail")
	}
	if _, err := LoadState(StateKey{SessionKey: session, ActorKey: MainActorKey}); !os.IsNotExist(err) {
		t.Fatalf("missing worker identity mutated main: %v", err)
	}
}

func TestSubagentStopDeletesOnlyWorkerAndSessionEndDeletesFamily(t *testing.T) {
	session := "lifecycle-" + t.Name()
	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	workerA := StateKey{SessionKey: session, ActorKey: "worker-a"}
	workerB := StateKey{SessionKey: session, ActorKey: "worker-b"}
	t.Cleanup(func() { _ = DeleteSessionFamily(session) })

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

	stopInput := []byte(`{"hook_event_name":"SubagentStop","session_id":"` + session + `","agent_id":"worker-a"}`)
	if err := DeleteActorFromHookInput(stopInput); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(workerA); !os.IsNotExist(err) {
		t.Fatalf("worker A still exists: %v", err)
	}
	for _, key := range []StateKey{mainKey, workerB} {
		if _, err := LoadState(key); err != nil {
			t.Fatalf("SubagentStop deleted %#v: %v", key, err)
		}
	}

	endInput := []byte(`{"hook_event_name":"SessionEnd","session_id":"` + session + `"}`)
	if err := DeleteSessionFromHookInput(endInput); err != nil {
		t.Fatal(err)
	}
	for _, key := range []StateKey{mainKey, workerB} {
		if _, err := LoadState(key); !os.IsNotExist(err) {
			t.Fatalf("SessionEnd retained %#v: %v", key, err)
		}
	}
	if _, err := os.Stat(legacyStatePath(session)); !os.IsNotExist(err) {
		t.Fatalf("SessionEnd retained legacy state: %v", err)
	}
	if _, err := lookupSessionByPID(registryPID); err == nil {
		t.Fatal("SessionEnd retained PID registry entry")
	}
}

func TestUninitializedWorkerCannotMutateMain(t *testing.T) {
	session := "uninitialized-" + t.Name()
	mainKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	workerKey := StateKey{SessionKey: session, ActorKey: "missing-worker"}
	t.Cleanup(func() { _ = DeleteSessionFamily(session) })

	if err := SaveState(mainKey, NewState("foreman")); err != nil {
		t.Fatal(err)
	}
	if err := UpdateState(workerKey, UninitializedPhase, func(state *State) error {
		state.Update("Bash", map[string]any{})
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
