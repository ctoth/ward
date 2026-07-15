package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	delegationRequestHeader     = "WARD-DELEGATE/1"
	delegationInstructionHeader = "WARD-DELEGATION/1"
	delegationPending           = "pending"
	delegationConsumed          = "consumed"
	delegationTTL               = 5 * time.Minute
	delegationSchemaVersion     = 1
)

var validDelegationPhase = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type DelegationRequest struct {
	Phase   string
	Message string
}

type DelegationGrant struct {
	SchemaVersion   int       `json:"schema_version"`
	GrantID         string    `json:"grant_id"`
	SessionKey      string    `json:"session_key"`
	ParentActorKey  string    `json:"parent_actor_key"`
	Phase           string    `json:"phase"`
	SpawnToolUseID  string    `json:"spawn_tool_use_id"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Status          string    `json:"status"`
	ConsumedByActor string    `json:"consumed_by_actor,omitempty"`
	ConsumedAt      time.Time `json:"consumed_at,omitempty"`
}

func parseDelegationRequest(event ToolEvent) (DelegationRequest, bool, error) {
	if event.Tool != "spawn_agent" {
		return DelegationRequest{}, false, nil
	}
	message, ok := event.Input["message"].(string)
	if !ok {
		return DelegationRequest{}, false, nil
	}
	parts := strings.SplitN(message, "\n", 2)
	firstLine := strings.TrimSuffix(parts[0], "\r")
	if !strings.HasPrefix(firstLine, delegationRequestHeader) {
		return DelegationRequest{}, false, nil
	}
	fields := strings.Fields(firstLine)
	if len(fields) != 2 || fields[0] != delegationRequestHeader || !strings.HasPrefix(fields[1], "phase=") {
		return DelegationRequest{}, true, fmt.Errorf("delegation header must be %q", delegationRequestHeader+" phase=<phase>")
	}
	phase := strings.TrimPrefix(fields[1], "phase=")
	if !validDelegationPhase.MatchString(phase) {
		return DelegationRequest{}, true, fmt.Errorf("invalid delegation phase %q", phase)
	}
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return DelegationRequest{}, true, fmt.Errorf("delegation request has no task message")
	}
	return DelegationRequest{Phase: phase, Message: parts[1]}, true, nil
}

func issueDelegation(parentKey StateKey, event ToolEvent, request DelegationRequest, now time.Time) (map[string]any, string, error) {
	if err := validateStateKey(parentKey); err != nil {
		return nil, "", err
	}
	if event.SessionID != parentKey.SessionKey {
		return nil, "", fmt.Errorf("spawn session %q does not match parent session %q", event.SessionID, parentKey.SessionKey)
	}
	if event.Tool != "spawn_agent" || event.EventType != "pre_tool" || event.TurnID == "" || event.ToolUseID == "" {
		return nil, "", fmt.Errorf("delegation requires a native Codex spawn_agent PreToolUse event")
	}
	if !validDelegationPhase.MatchString(request.Phase) {
		return nil, "", fmt.Errorf("invalid delegation phase %q", request.Phase)
	}
	if strings.TrimSpace(request.Message) == "" {
		return nil, "", fmt.Errorf("delegation request has no task message")
	}

	token, err := newDelegationToken(parentKey.SessionKey)
	if err != nil {
		return nil, "", err
	}
	grant := &DelegationGrant{
		SchemaVersion:  delegationSchemaVersion,
		GrantID:        delegationGrantID(token),
		SessionKey:     parentKey.SessionKey,
		ParentActorKey: parentKey.ActorKey,
		Phase:          request.Phase,
		SpawnToolUseID: event.ToolUseID,
		IssuedAt:       now,
		ExpiresAt:      now.Add(delegationTTL),
		Status:         delegationPending,
	}
	if err := saveNewDelegationGrant(token, grant); err != nil {
		return nil, "", err
	}

	updatedInput := make(map[string]any, len(event.Input))
	for name, value := range event.Input {
		updatedInput[name] = value
	}
	updatedInput["message"] = fmt.Sprintf(
		"%s\nYour first action must be exactly:\nward accept-delegation %s\nDo not take any other action before Ward confirms it.\n\n%s",
		delegationInstructionHeader,
		token,
		request.Message,
	)
	return updatedInput, token, nil
}

func newDelegationToken(sessionKey string) (string, error) {
	if sessionKey == "" {
		return "", fmt.Errorf("empty session key")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate delegation token: %w", err)
	}
	encodedSession := base64.RawURLEncoding.EncodeToString([]byte(sessionKey))
	return encodedSession + "." + base64.RawURLEncoding.EncodeToString(random), nil
}

func delegationTokenSession(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid delegation token")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return "", fmt.Errorf("invalid delegation token")
	}
	sessionBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(sessionBytes) == 0 {
		return "", fmt.Errorf("invalid delegation token")
	}
	return string(sessionBytes), nil
}

func delegationGrantID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

func delegationGrantPath(sessionKey, token string) string {
	return filepath.Join(sessionFamilyPath(sessionKey), "delegations", delegationGrantID(token)+".json")
}

func delegationGrantLockKey(sessionKey, token string) StateKey {
	return StateKey{SessionKey: sessionKey, ActorKey: "\x00delegation:" + delegationGrantID(token)}
}

func saveNewDelegationGrant(token string, grant *DelegationGrant) error {
	unlock, err := lockActorState(delegationGrantLockKey(grant.SessionKey, token))
	if err != nil {
		return err
	}
	defer unlock()
	path := delegationGrantPath(grant.SessionKey, token)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("delegation grant already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	return saveDelegationGrantUnlocked(token, grant)
}

func saveDelegationGrantUnlocked(token string, grant *DelegationGrant) error {
	data, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	return atomicWriteFile(delegationGrantPath(grant.SessionKey, token), data, 0o600)
}

func loadDelegationGrant(token string) (*DelegationGrant, error) {
	sessionKey, err := delegationTokenSession(token)
	if err != nil {
		return nil, err
	}
	unlock, err := lockActorState(delegationGrantLockKey(sessionKey, token))
	if err != nil {
		return nil, err
	}
	defer unlock()
	return loadDelegationGrantUnlocked(sessionKey, token)
}

func loadDelegationGrantUnlocked(sessionKey, token string) (*DelegationGrant, error) {
	data, err := os.ReadFile(delegationGrantPath(sessionKey, token))
	if err != nil {
		return nil, err
	}
	var grant DelegationGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, fmt.Errorf("decode delegation grant: %w", err)
	}
	if grant.SchemaVersion != delegationSchemaVersion {
		return nil, fmt.Errorf("delegation schema version %d does not match %d", grant.SchemaVersion, delegationSchemaVersion)
	}
	if grant.GrantID != delegationGrantID(token) || grant.SessionKey != sessionKey {
		return nil, fmt.Errorf("delegation grant identity mismatch")
	}
	return &grant, nil
}

func delegationAcceptanceToken(event ToolEvent) (string, bool) {
	commands := commandsFromInput(event.Input)
	if len(commands) != 1 {
		return "", false
	}
	command := commands[0]
	if command.Name != "ward" || len(command.Args) != 2 || command.Args[0] != "accept-delegation" {
		return "", false
	}
	return command.Args[1], true
}

func consumeDelegation(key StateKey, event ToolEvent, token string, now time.Time) (*DelegationGrant, error) {
	if err := validateStateKey(key); err != nil {
		return nil, err
	}
	if event.EventType != "pre_tool" || event.TurnID == "" || event.AgentID == "" || event.AgentID == MainActorKey {
		return nil, fmt.Errorf("delegation acceptance requires a host-supplied Codex child identity")
	}
	if key.ActorKey != event.AgentID || key.SessionKey != event.SessionID {
		return nil, fmt.Errorf("delegation acceptance identity does not match hook identity")
	}
	sessionKey, err := delegationTokenSession(token)
	if err != nil {
		return nil, err
	}
	if sessionKey != key.SessionKey {
		return nil, fmt.Errorf("delegation token belongs to another session")
	}

	unlock, err := lockActorState(delegationGrantLockKey(sessionKey, token))
	if err != nil {
		return nil, err
	}
	defer unlock()
	grant, err := loadDelegationGrantUnlocked(sessionKey, token)
	if err != nil {
		return nil, err
	}
	if grant.Status != delegationPending {
		return nil, fmt.Errorf("delegation token has already been consumed")
	}
	if now.After(grant.ExpiresAt) {
		return nil, fmt.Errorf("delegation token has expired")
	}

	if err := UpdateState(key, UninitializedPhase, func(state *State) error {
		state.Phase = grant.Phase
		if event.AgentType != "" {
			state.AgentType = event.AgentType
		}
		state.DelegatedByActor = grant.ParentActorKey
		state.DelegationGrantID = grant.GrantID
		state.DelegatedAt = &now
		return nil
	}); err != nil {
		return nil, err
	}
	grant.Status = delegationConsumed
	grant.ConsumedByActor = key.ActorKey
	grant.ConsumedAt = now
	if err := saveDelegationGrantUnlocked(token, grant); err != nil {
		return nil, err
	}
	return grant, nil
}

func verifyConsumedDelegation(token string) (*DelegationGrant, error) {
	grant, err := loadDelegationGrant(token)
	if err != nil {
		return nil, err
	}
	if grant.Status != delegationConsumed || grant.ConsumedByActor == "" {
		return nil, fmt.Errorf("delegation was not accepted by the PreToolUse hook")
	}
	return grant, nil
}

func isHostChildPhaseSet(state *State, event ToolEvent) bool {
	if state.ActorKey == "" || state.ActorKey == MainActorKey || (state.AgentType == "" && state.DelegationGrantID == "") {
		return false
	}
	commands := commandsFromInput(event.Input)
	return len(commands) == 1 && commands[0].Name == "ward" && len(commands[0].Args) > 0 && commands[0].Args[0] == "set"
}
