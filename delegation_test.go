package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseDelegationRequest(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantPhase string
		wantBody  string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "valid",
			message:   "WARD-DELEGATE/1 phase=researcher\nInspect the parser.",
			wantPhase: "researcher",
			wantBody:  "Inspect the parser.",
			wantFound: true,
		},
		{
			name:    "ordinary task",
			message: "Inspect the parser.",
		},
		{
			name:      "header must be first",
			message:   "Inspect first.\nWARD-DELEGATE/1 phase=researcher",
			wantFound: false,
		},
		{
			name:      "missing phase",
			message:   "WARD-DELEGATE/1\nInspect the parser.",
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "invalid phase",
			message:   "WARD-DELEGATE/1 phase=Researcher!\nInspect the parser.",
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "missing task",
			message:   "WARD-DELEGATE/1 phase=researcher",
			wantFound: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := ToolEvent{
				Tool:  "spawn_agent",
				Input: map[string]any{"message": tt.message},
			}
			got, found, err := parseDelegationRequest(event)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDelegationRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if found != tt.wantFound {
				t.Fatalf("parseDelegationRequest() found = %v, want %v", found, tt.wantFound)
			}
			if err != nil || !found {
				return
			}
			if got.Phase != tt.wantPhase || got.Message != tt.wantBody {
				t.Fatalf("parseDelegationRequest() = %#v, want phase %q body %q", got, tt.wantPhase, tt.wantBody)
			}
		})
	}
}

func TestIssueDelegationRewritesSpawnInputAndPersistsHashedGrant(t *testing.T) {
	session := "delegation-issue-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	event := ToolEvent{
		Tool:      "spawn_agent",
		SessionID: session,
		TurnID:    "parent-turn",
		EventType: "pre_tool",
		ToolUseID: "spawn-call-1",
		Input: map[string]any{
			"message":    "WARD-DELEGATE/1 phase=researcher\nInspect the parser.",
			"task_name":  "parser_review",
			"fork_turns": "none",
		},
	}
	request, found, err := parseDelegationRequest(event)
	if err != nil || !found {
		t.Fatalf("parse request: found=%v err=%v", found, err)
	}

	updatedInput, token, err := issueDelegation(
		StateKey{SessionKey: session, ActorKey: MainActorKey}, event, request, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("issueDelegation() returned an empty token")
	}
	if updatedInput["task_name"] != "parser_review" || updatedInput["fork_turns"] != "none" {
		t.Fatalf("updated input lost spawn fields: %#v", updatedInput)
	}
	message, _ := updatedInput["message"].(string)
	if !strings.HasPrefix(message, delegationInstructionHeader+"\n") {
		t.Fatalf("rewritten message = %q, want delegation instruction header", message)
	}
	if !strings.Contains(message, "ward accept-delegation "+token) {
		t.Fatalf("rewritten message does not contain exact acceptance command: %q", message)
	}
	if !strings.Contains(message, "Inspect the parser.") || strings.Contains(message, delegationRequestHeader) {
		t.Fatalf("rewritten message did not replace request header: %q", message)
	}
	if event.Input["message"] != "WARD-DELEGATE/1 phase=researcher\nInspect the parser." {
		t.Fatal("issueDelegation() mutated the original event input")
	}

	grant, err := loadDelegationGrant(token)
	if err != nil {
		t.Fatal(err)
	}
	if grant.SessionKey != session || grant.ParentActorKey != MainActorKey || grant.Phase != "researcher" {
		t.Fatalf("grant = %#v", grant)
	}
	if grant.SpawnToolUseID != "spawn-call-1" || grant.Status != delegationPending {
		t.Fatalf("grant provenance/status = %#v", grant)
	}
	if strings.Contains(delegationGrantPath(session, token), token) {
		t.Fatal("grant path exposes the bearer token")
	}
	grantData, err := os.ReadFile(delegationGrantPath(session, token))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(grantData), token) {
		t.Fatal("persisted grant exposes the bearer token")
	}
}

func TestConsumeDelegationBindsPhaseToHostActorAndRejectsReplay(t *testing.T) {
	session := "delegation-consume-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	parentKey := StateKey{SessionKey: session, ActorKey: MainActorKey}
	event := ToolEvent{
		Tool:      "spawn_agent",
		SessionID: session,
		TurnID:    "parent-turn",
		EventType: "pre_tool",
		ToolUseID: "spawn-call-1",
		Input:     map[string]any{"message": "WARD-DELEGATE/1 phase=researcher\nInspect the parser."},
	}
	request, _, err := parseDelegationRequest(event)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := issueDelegation(parentKey, event, request, now)
	if err != nil {
		t.Fatal(err)
	}

	childEvent := ToolEvent{
		Tool:      "PowerShell",
		SessionID: session,
		AgentID:   "opaque-child-a",
		AgentType: "default",
		TurnID:    "child-turn",
		EventType: "pre_tool",
		Input:     map[string]any{"command": "ward accept-delegation " + token},
	}
	enrichShellCommands(&childEvent)
	gotToken, ok := delegationAcceptanceToken(childEvent)
	if !ok || gotToken != token {
		t.Fatalf("delegationAcceptanceToken() = %q, %v", gotToken, ok)
	}
	childKey := StateKey{SessionKey: session, ActorKey: childEvent.AgentID}
	grant, err := consumeDelegation(childKey, childEvent, token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Status != delegationConsumed || grant.ConsumedByActor != childEvent.AgentID {
		t.Fatalf("consumed grant = %#v", grant)
	}
	state, err := LoadState(childKey)
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase != "researcher" || state.DelegatedByActor != MainActorKey || state.DelegationGrantID == "" {
		t.Fatalf("delegated child state = %#v", state)
	}
	if state.AgentType != "default" {
		t.Fatalf("agent type = %q, want default", state.AgentType)
	}
	if _, err := consumeDelegation(childKey, childEvent, token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("replayed delegation token was accepted")
	}
	if _, err := consumeDelegation(
		StateKey{SessionKey: session, ActorKey: "opaque-child-b"}, childEvent, token, now.Add(2*time.Minute),
	); err == nil {
		t.Fatal("consumed delegation token was accepted by another actor")
	}
}

func TestConsumeDelegationRejectsInvalidRedemptions(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		keyActor  string
		eventID   string
		session   string
		consumeAt time.Time
	}{
		{name: "missing host actor", keyActor: MainActorKey, session: "same", consumeAt: now},
		{name: "event actor mismatch", keyActor: "child-a", eventID: "child-b", session: "same", consumeAt: now},
		{name: "session mismatch", keyActor: "child-a", eventID: "child-a", session: "other", consumeAt: now},
		{name: "expired", keyActor: "child-a", eventID: "child-a", session: "same", consumeAt: now.Add(delegationTTL + time.Second)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := "delegation-invalid-" + t.Name()
			t.Cleanup(func() { _ = PurgeSessionFamily(session) })
			spawn := ToolEvent{
				Tool:      "spawn_agent",
				SessionID: session,
				TurnID:    "parent-turn",
				EventType: "pre_tool",
				ToolUseID: "spawn-call",
				Input:     map[string]any{"message": "WARD-DELEGATE/1 phase=researcher\nInspect."},
			}
			request, _, err := parseDelegationRequest(spawn)
			if err != nil {
				t.Fatal(err)
			}
			_, token, err := issueDelegation(StateKey{SessionKey: session, ActorKey: MainActorKey}, spawn, request, now)
			if err != nil {
				t.Fatal(err)
			}
			eventSession := session
			if tt.session == "other" {
				eventSession += "-other"
			}
			event := ToolEvent{SessionID: eventSession, AgentID: tt.eventID, TurnID: "child-turn", AgentType: "default", EventType: "pre_tool"}
			key := StateKey{SessionKey: eventSession, ActorKey: tt.keyActor}
			if _, err := consumeDelegation(key, event, token, tt.consumeAt); err == nil {
				t.Fatal("invalid redemption was accepted")
			}
		})
	}
}

func TestConcurrentDelegationsRemainIndependent(t *testing.T) {
	session := "delegation-concurrent-" + t.Name()
	t.Cleanup(func() { _ = PurgeSessionFamily(session) })
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	const count = 8
	tokens := make([]string, count)

	var issueWG sync.WaitGroup
	issueErrs := make(chan error, count)
	for i := range count {
		issueWG.Add(1)
		go func(i int) {
			defer issueWG.Done()
			phase := fmt.Sprintf("researcher-%d", i)
			event := ToolEvent{
				Tool:      "spawn_agent",
				SessionID: session,
				TurnID:    "parent-turn",
				EventType: "pre_tool",
				ToolUseID: fmt.Sprintf("spawn-%d", i),
				Input:     map[string]any{"message": "WARD-DELEGATE/1 phase=" + phase + "\nInspect."},
			}
			request, _, err := parseDelegationRequest(event)
			if err == nil {
				_, tokens[i], err = issueDelegation(StateKey{SessionKey: session, ActorKey: MainActorKey}, event, request, now)
			}
			if err != nil {
				issueErrs <- err
			}
		}(i)
	}
	issueWG.Wait()
	close(issueErrs)
	for err := range issueErrs {
		t.Fatal(err)
	}

	var consumeWG sync.WaitGroup
	consumeErrs := make(chan error, count)
	for i := range count {
		consumeWG.Add(1)
		go func(i int) {
			defer consumeWG.Done()
			actor := fmt.Sprintf("child-%d", i)
			event := ToolEvent{SessionID: session, AgentID: actor, AgentType: "default", TurnID: fmt.Sprintf("child-turn-%d", i), EventType: "pre_tool"}
			_, err := consumeDelegation(StateKey{SessionKey: session, ActorKey: actor}, event, tokens[i], now.Add(time.Minute))
			if err != nil {
				consumeErrs <- err
			}
		}(i)
	}
	consumeWG.Wait()
	close(consumeErrs)
	for err := range consumeErrs {
		t.Fatal(err)
	}

	for i := range count {
		actor := fmt.Sprintf("child-%d", i)
		state, err := LoadState(StateKey{SessionKey: session, ActorKey: actor})
		if err != nil {
			t.Fatal(err)
		}
		wantPhase := fmt.Sprintf("researcher-%d", i)
		if state.Phase != wantPhase {
			t.Fatalf("actor %s phase = %q, want %q", actor, state.Phase, wantPhase)
		}
	}
}

func TestDelegatedHostActorCannotSetItsOwnPhase(t *testing.T) {
	state := NewState("researcher")
	state.ActorKey = "opaque-child"
	state.AgentType = "default"
	event := ToolEvent{
		Tool:      "PowerShell",
		EventType: "pre_tool",
		Input:     map[string]any{"command": "ward set foreman"},
	}
	enrichShellCommands(&event)

	result, _, err := Evaluate(&Guard{}, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != "deny" {
		t.Fatalf("Evaluate() = %#v, want denied child phase mutation", result)
	}

	state.ActorKey = MainActorKey
	result, _, err = Evaluate(&Guard{}, state, event)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("main actor phase mutation = %#v, want allowed", result)
	}
}
