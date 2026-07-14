package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"gopkg.in/yaml.v3"
)

// DefaultPhase is always "planning" — no config needed.
const DefaultPhase = "planning"

// Rule is a single guard rule, loaded from one YAML file.
type Rule struct {
	Scope   string `yaml:"scope"`   // optional glob for file path matching
	When    string `yaml:"when"`    // CEL expression
	Action  string `yaml:"action"`  // "deny", "allow", "context"
	Message string `yaml:"message"` // human-readable message

	// populated at compile time
	program  cel.Program
	filename string // source file for diagnostics
}

type Fact struct {
	Command string `yaml:"command"`
	Type    string `yaml:"type"` // "string" (default) or "bool"
}

// Guard holds compiled facts + rules, ready for evaluation.
type Guard struct {
	Facts      map[string]Fact
	factValues map[string]any
	repoStatus *RepoStatus
	Rules      []Rule
	env        *cel.Env
}

// LoadFact reads a single fact from a YAML file.
// The fact name is derived from the filename (minus extension).
func LoadFact(path string) (string, *Fact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read %s: %w", path, err)
	}

	var f Fact
	if err := yaml.Unmarshal(data, &f); err != nil {
		return "", nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if f.Command == "" {
		return "", nil, fmt.Errorf("%s: missing 'command' field", path)
	}

	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return name, &f, nil
}

// LoadFactsFromDir walks a directory and loads all .yaml/.yml files as facts.
// Returns empty map if directory doesn't exist.
func LoadFactsFromDir(dir string) (map[string]Fact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	facts := make(map[string]Fact)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		factName, f, err := LoadFact(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		facts[factName] = *f
	}
	return facts, nil
}

// MergeFacts merges project facts over global facts. Project wins on conflict.
func MergeFacts(global, project map[string]Fact) map[string]Fact {
	merged := make(map[string]Fact)
	for k, v := range global {
		merged[k] = v
	}
	for k, v := range project {
		merged[k] = v
	}
	return merged
}

// LoadRule reads a single rule from a YAML file.
func LoadRule(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	r.filename = path

	if r.When == "" {
		return nil, fmt.Errorf("%s: missing 'when' field", path)
	}
	if r.Action == "" {
		return nil, fmt.Errorf("%s: missing 'action' field", path)
	}

	return &r, nil
}

// LoadRulesFromDir walks a directory and loads all .yaml/.yml files as rules.
// Returns empty slice if directory doesn't exist.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		r, err := LoadRule(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		rules = append(rules, *r)
	}
	return rules, nil
}

// celEnvOptions returns the shared CEL environment options including custom functions.
func celEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("tool", cel.StringType),
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("facts", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("repo", cel.MapType(cel.StringType, cel.DynType)),

		// last(list, n) — returns the last N elements of a list
		cel.Function("last",
			cel.Overload("last_list_int",
				[]*cel.Type{cel.ListType(cel.DynType), cel.IntType},
				cel.ListType(cel.DynType),
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					list := lhs.(traits.Lister)
					n := int64(rhs.(types.Int))
					size := int64(list.Size().(types.Int))
					start := size - n
					if start < 0 {
						start = 0
					}
					result := make([]ref.Val, 0, size-start)
					for i := start; i < size; i++ {
						result = append(result, list.Get(types.Int(i)))
					}
					return types.DefaultTypeAdapter.NativeToValue(result)
				}),
			),
		),

		// since(list, marker) — returns all elements after the last occurrence of marker
		cel.Function("since",
			cel.Overload("since_list_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType},
				cel.ListType(cel.DynType),
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					list := lhs.(traits.Lister)
					marker := string(rhs.(types.String))
					size := int64(list.Size().(types.Int))

					// Find last occurrence of marker
					lastIdx := int64(-1)
					for i := int64(0); i < size; i++ {
						val := list.Get(types.Int(i))
						if s, ok := val.Value().(string); ok && s == marker {
							lastIdx = i
						}
					}

					start := lastIdx + 1 // if not found (-1), start=0 returns whole list
					result := make([]ref.Val, 0, size-start)
					for i := start; i < size; i++ {
						result = append(result, list.Get(types.Int(i)))
					}
					return types.DefaultTypeAdapter.NativeToValue(result)
				}),
			),
		),
	}
}

// NewGuard creates a Guard from facts and rules, compiling all CEL expressions.
func NewGuard(facts map[string]Fact, rules []Rule) (*Guard, error) {
	if facts == nil {
		facts = make(map[string]Fact)
	}

	env, err := cel.NewEnv(celEnvOptions()...)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}

	for i := range rules {
		ast, issues := env.Compile(rules[i].When)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q (%s): %w", rules[i].filename, rules[i].When, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %q program: %w", rules[i].filename, err)
		}
		rules[i].program = prg
	}

	return &Guard{
		Facts: facts,
		Rules: rules,
		env:   env,
	}, nil
}

// CompileRule compiles a single rule's CEL expression using the guard's environment.
// Used by the validate command.
func CompileRule(r *Rule) error {
	env, err := cel.NewEnv(celEnvOptions()...)
	if err != nil {
		return fmt.Errorf("cel env: %w", err)
	}
	ast, issues := env.Compile(r.When)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}
	_, err = env.Program(ast)
	return err
}

// Session State

const maxHistory = 100

const (
	CurrentStateSchemaVersion = 1
	MainActorKey              = "main"
	UninitializedPhase        = "uninitialized"
)

// StateKey identifies one mutable actor record within a session family.
type StateKey struct {
	SessionKey string
	ActorKey   string
}

// Signal represents a named permission stored in session state.
type Signal struct {
	OneTimeUse bool `json:"one_time_use"`
}

type State struct {
	SchemaVersion      int               `json:"schema_version"`
	SessionKey         string            `json:"session_key"`
	ActorKey           string            `json:"actor_key"`
	AgentType          string            `json:"agent_type,omitempty"`
	Phase              string            `json:"phase"`
	PhaseStack         []string          `json:"phase_stack,omitempty"`
	History            []string          `json:"history"`
	Signals            map[string]Signal `json:"signals"`
	StartedAt          time.Time         `json:"started_at"`
	RepoRoot           string            `json:"repo_root,omitempty"`
	BaselineDirtyPaths []string          `json:"baseline_dirty_paths,omitempty"`
	TouchedFiles       []string          `json:"touched_files,omitempty"`
	TouchedSinceCommit []string          `json:"touched_since_commit,omitempty"`
	AdoptedPaths       []string          `json:"adopted_paths,omitempty"`
	DiscardablePaths   []string          `json:"discardable_paths,omitempty"`
	// RepoScopes preserves per-repo tracking when the actor's tool calls move
	// between git repositories. The flat fields above always describe the
	// CURRENT RepoRoot; scopes for other roots are parked here and restored
	// when the actor returns, instead of being destroyed on every switch.
	RepoScopes map[string]*RepoScope `json:"repo_scopes,omitempty"`
}

// RepoScope is one repository's parked tracking state.
type RepoScope struct {
	BaselineDirtyPaths []string `json:"baseline_dirty_paths,omitempty"`
	TouchedFiles       []string `json:"touched_files,omitempty"`
	TouchedSinceCommit []string `json:"touched_since_commit,omitempty"`
	AdoptedPaths       []string `json:"adopted_paths,omitempty"`
	DiscardablePaths   []string `json:"discardable_paths,omitempty"`
}

func NewState(phase string) *State {
	if phase == "" {
		phase = DefaultPhase
	}
	return &State{
		Phase:              phase,
		PhaseStack:         []string{},
		History:            []string{},
		Signals:            make(map[string]Signal),
		StartedAt:          time.Now(),
		BaselineDirtyPaths: []string{},
		TouchedFiles:       []string{},
		TouchedSinceCommit: []string{},
		AdoptedPaths:       []string{},
		DiscardablePaths:   []string{},
	}
}

func (s *State) EnterPhase(phase string) {
	s.PhaseStack = append(s.PhaseStack, s.Phase)
	s.Phase = phase
}

func (s *State) LeavePhase() (string, error) {
	if len(s.PhaseStack) == 0 {
		return s.Phase, fmt.Errorf("no entered phase to leave")
	}
	last := len(s.PhaseStack) - 1
	s.Phase = s.PhaseStack[last]
	s.PhaseStack = s.PhaseStack[:last]
	return s.Phase, nil
}

func (s *State) Update(tool string, input map[string]any) {
	toolName := canonicalToolName(tool)

	if toolName == "Edit" || toolName == "Write" {
		var filePaths []string
		if filePath, ok := input["file_path"].(string); ok && filePath != "" {
			filePaths = append(filePaths, filePath)
		}
		if paths, ok := stringSlice(input["file_paths"]); ok {
			filePaths = append(filePaths, paths...)
		}
		for _, filePath := range uniquePaths(filePaths) {
			filePath = s.normalizeTrackedPath(filePath)
			s.TouchedFiles = appendUniquePath(s.TouchedFiles, filePath)
			s.TouchedSinceCommit = appendUniquePath(s.TouchedSinceCommit, filePath)
		}
	}

	// Detect git commit from parsed commands rather than raw substrings.
	if toolName == "Bash" && hasGitCommit(input) {
		s.TouchedSinceCommit = nil
		s.appendHistory("_commit")
	}
	s.appendHistory(toolName)
}

func (s *State) SyncRepo(status *RepoStatus) {
	if status == nil || !status.InGit {
		return
	}
	root := NormalizePath(status.Root)
	if s.RepoRoot == root {
		if s.BaselineDirtyPaths == nil {
			s.BaselineDirtyPaths = []string{}
		}
		return
	}

	// Park the outgoing repo's scope (if any) so returning to it later
	// restores tracking instead of rebaselining the agent's own edits as
	// pre-existing dirt.
	if s.RepoRoot != "" {
		if s.RepoScopes == nil {
			s.RepoScopes = make(map[string]*RepoScope)
		}
		s.RepoScopes[s.RepoRoot] = &RepoScope{
			BaselineDirtyPaths: s.BaselineDirtyPaths,
			TouchedFiles:       s.TouchedFiles,
			TouchedSinceCommit: s.TouchedSinceCommit,
			AdoptedPaths:       s.AdoptedPaths,
			DiscardablePaths:   s.DiscardablePaths,
		}
	}

	s.RepoRoot = root
	if parked, ok := s.RepoScopes[root]; ok {
		s.BaselineDirtyPaths = parked.BaselineDirtyPaths
		s.TouchedFiles = parked.TouchedFiles
		s.TouchedSinceCommit = parked.TouchedSinceCommit
		s.AdoptedPaths = parked.AdoptedPaths
		s.DiscardablePaths = parked.DiscardablePaths
		delete(s.RepoScopes, root)
		if s.BaselineDirtyPaths == nil {
			s.BaselineDirtyPaths = []string{}
		}
		return
	}
	s.BaselineDirtyPaths = uniquePaths(status.DirtyPaths)
	s.TouchedFiles = nil
	s.TouchedSinceCommit = nil
	s.AdoptedPaths = nil
	s.DiscardablePaths = nil
}

func (s *State) appendHistory(entry string) {
	if len(s.History) >= maxHistory {
		s.History = s.History[1:]
	}
	s.History = append(s.History, entry)
}

func (s *State) ToMap() map[string]any {
	// Convert []string to []any for CEL compatibility
	history := make([]any, len(s.History))
	for i, h := range s.History {
		history[i] = h
	}

	signals := make([]any, 0, len(s.Signals))
	for name := range s.Signals {
		signals = append(signals, name)
	}

	touchedFiles := stringListToAny(s.TouchedFiles)
	touchedSinceCommit := stringListToAny(s.TouchedSinceCommit)
	baselineDirtyPaths := stringListToAny(s.BaselineDirtyPaths)
	adoptedPaths := stringListToAny(s.AdoptedPaths)
	discardablePaths := stringListToAny(s.DiscardablePaths)
	sessionOwnedPaths := stringListToAny(pathDifference(s.TouchedFiles, s.BaselineDirtyPaths))

	return map[string]any{
		"phase":                      s.Phase,
		"history":                    history,
		"tool_count":                 int64(len(s.History)),
		"started_at":                 s.StartedAt.Format(time.RFC3339),
		"signals":                    signals,
		"repo_root":                  s.RepoRoot,
		"baseline_dirty_paths":       baselineDirtyPaths,
		"baseline_dirty_count":       int64(len(s.BaselineDirtyPaths)),
		"has_preexisting_dirty":      len(s.BaselineDirtyPaths) > 0,
		"adopted_paths":              adoptedPaths,
		"discardable_paths":          discardablePaths,
		"session_owned_paths":        sessionOwnedPaths,
		"touched_files":              touchedFiles,
		"touched_file_count":         int64(len(s.TouchedFiles)),
		"touched_since_commit":       touchedSinceCommit,
		"touched_since_commit_count": int64(len(s.TouchedSinceCommit)),
	}
}

// ConsumeSignals removes one-time-use signals that changed a rule's outcome.
func (s *State) ConsumeSignals(checked map[string]bool) {
	for name, sig := range s.Signals {
		if sig.OneTimeUse && checked[name] {
			delete(s.Signals, name)
		}
	}
}

// validSignalName matches allowed signal names.
var validSignalName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// SignalDef is a signal definition loaded from a YAML file.
type SignalDef struct {
	OneTimeUse  *bool  `yaml:"one_time_use"` // pointer to distinguish absent from false
	Description string `yaml:"description"`
}

// LoadSignalDef reads a single signal definition from a YAML file.
// The signal name is derived from the filename (minus extension).
func LoadSignalDef(path string) (string, *SignalDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var def SignalDef
	if err := yaml.Unmarshal(data, &def); err != nil {
		return "", nil, err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return name, &def, nil
}

// LoadSignalDefsFromDir walks a directory and loads all .yaml/.yml files as signal definitions.
// Returns empty map if directory doesn't exist.
func LoadSignalDefsFromDir(dir string) (map[string]SignalDef, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	defs := make(map[string]SignalDef)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		defName, def, err := LoadSignalDef(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		defs[defName] = *def
	}
	return defs, nil
}

// signalsReferencedByRules extracts all signal names referenced in rules' When expressions.
func signalsReferencedByRules(rules []Rule) map[string]bool {
	refs := make(map[string]bool)
	for _, rule := range rules {
		for _, match := range signalRefRe.FindAllStringSubmatch(rule.When, -1) {
			// Group 1: session.signals.contains("x"), Group 2: "x" in session.signals
			if match[1] != "" {
				refs[match[1]] = true
			} else if match[2] != "" {
				refs[match[2]] = true
			}
		}
	}
	return refs
}

func stateDir() string {
	tmp := os.TempDir()
	return filepath.Join(tmp, "ward")
}

func hashedStateComponent(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func sessionFamilyPath(sessionKey string) string {
	return filepath.Join(stateDir(), "families", hashedStateComponent(sessionKey))
}

func statePath(key StateKey) string {
	return filepath.Join(sessionFamilyPath(key.SessionKey), "actors", hashedStateComponent(key.ActorKey)+".json")
}

const activeActorBindingLockKey = "\x00active-actor-binding"

func activeActorBindingPath(sessionKey string) string {
	return filepath.Join(sessionFamilyPath(sessionKey), "active-actor")
}

func bindActiveActor(key StateKey) error {
	if err := validateStateKey(key); err != nil {
		return err
	}
	lockKey := StateKey{SessionKey: key.SessionKey, ActorKey: activeActorBindingLockKey}
	unlock, err := lockActorState(lockKey)
	if err != nil {
		return err
	}
	defer unlock()
	return atomicWriteFile(activeActorBindingPath(key.SessionKey), []byte(key.ActorKey+"\n"), 0o644)
}

func loadActiveActor(sessionKey string) (string, error) {
	lockKey := StateKey{SessionKey: sessionKey, ActorKey: activeActorBindingLockKey}
	if err := validateStateKey(lockKey); err != nil {
		return "", err
	}
	unlock, err := lockActorState(lockKey)
	if err != nil {
		return "", err
	}
	defer unlock()

	path := activeActorBindingPath(sessionKey)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) && restoreEndedFamily(sessionKey) {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	actorKey := strings.TrimSpace(string(data))
	if err := validateStateKey(StateKey{SessionKey: sessionKey, ActorKey: actorKey}); err != nil {
		return "", fmt.Errorf("invalid active actor binding: %w", err)
	}
	return actorKey, nil
}

func clearActiveActorBinding(key StateKey) error {
	lockKey := StateKey{SessionKey: key.SessionKey, ActorKey: activeActorBindingLockKey}
	if err := validateStateKey(lockKey); err != nil {
		return err
	}
	unlock, err := lockActorState(lockKey)
	if err != nil {
		return err
	}
	defer unlock()

	path := activeActorBindingPath(key.SessionKey)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(data)) != key.ActorKey {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func legacyStatePath(sessionKey string) string {
	return filepath.Join(stateDir(), sessionKey+".json")
}

func validateStateKey(key StateKey) error {
	if key.SessionKey == "" {
		return fmt.Errorf("empty session key")
	}
	if key.ActorKey == "" {
		return fmt.Errorf("empty actor key")
	}
	return nil
}

func validateStateIdentity(key StateKey, state *State) error {
	if state.SchemaVersion != CurrentStateSchemaVersion {
		return fmt.Errorf("state schema version %d does not match %d", state.SchemaVersion, CurrentStateSchemaVersion)
	}
	if state.SessionKey != key.SessionKey || state.ActorKey != key.ActorKey {
		return fmt.Errorf("state identity collision: stored (%q, %q), requested (%q, %q)", state.SessionKey, state.ActorKey, key.SessionKey, key.ActorKey)
	}
	return nil
}

func initializeStateCollections(s *State) {
	if s.History == nil {
		s.History = []string{}
	}
	if s.Signals == nil {
		s.Signals = make(map[string]Signal)
	}
	if s.BaselineDirtyPaths == nil {
		s.BaselineDirtyPaths = []string{}
	}
	if s.TouchedFiles == nil {
		s.TouchedFiles = []string{}
	}
	if s.TouchedSinceCommit == nil {
		s.TouchedSinceCommit = []string{}
	}
	if s.AdoptedPaths == nil {
		s.AdoptedPaths = []string{}
	}
	if s.DiscardablePaths == nil {
		s.DiscardablePaths = []string{}
	}
}

func readActorState(key StateKey) (*State, error) {
	data, err := os.ReadFile(statePath(key))
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode actor state: %w", err)
	}
	if err := validateStateIdentity(key, &state); err != nil {
		return nil, err
	}
	initializeStateCollections(&state)
	return &state, nil
}

func legacyPathIsSafe(sessionKey string) bool {
	return sessionKey != "" && sessionKey != "." && filepath.Base(sessionKey) == sessionKey
}

func loadStateUnlocked(key StateKey) (*State, error) {
	if err := validateStateKey(key); err != nil {
		return nil, err
	}

	state, err := readActorState(key)
	if os.IsNotExist(err) && restoreEndedFamily(key.SessionKey) {
		state, err = readActorState(key)
	}
	if err == nil {
		if key.ActorKey == MainActorKey && legacyPathIsSafe(key.SessionKey) {
			if removeErr := os.Remove(legacyStatePath(key.SessionKey)); removeErr != nil && !os.IsNotExist(removeErr) {
				return nil, fmt.Errorf("finish legacy cleanup: %w", removeErr)
			}
		}
		return state, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if key.ActorKey != MainActorKey || !legacyPathIsSafe(key.SessionKey) {
		return nil, os.ErrNotExist
	}

	data, legacyErr := os.ReadFile(legacyStatePath(key.SessionKey))
	if legacyErr != nil {
		return nil, legacyErr
	}
	var migrated State
	if err := json.Unmarshal(data, &migrated); err != nil {
		return nil, fmt.Errorf("decode legacy state: %w", err)
	}
	if migrated.SchemaVersion != 0 || migrated.SessionKey != "" || migrated.ActorKey != "" {
		return nil, fmt.Errorf("legacy state contains unexpected actor identity metadata")
	}
	initializeStateCollections(&migrated)
	if err := saveStateUnlocked(key, &migrated); err != nil {
		return nil, fmt.Errorf("migrate legacy state: %w", err)
	}
	if err := os.Remove(legacyStatePath(key.SessionKey)); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove migrated legacy state: %w", err)
	}
	return &migrated, nil
}

var actorStateLocks sync.Map

func actorStateLock(key StateKey) *sync.Mutex {
	lockKey := key.SessionKey + "\x00" + key.ActorKey
	lock, _ := actorStateLocks.LoadOrStore(lockKey, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func actorStateLockPath(key StateKey) string {
	return filepath.Join(stateDir(), "locks", hashedStateComponent(key.SessionKey), hashedStateComponent(key.ActorKey)+".lock")
}

func lockActorState(key StateKey) (func(), error) {
	if err := validateStateKey(key); err != nil {
		return nil, err
	}
	localLock := actorStateLock(key)
	localLock.Lock()
	lockPath := actorStateLockPath(key)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		localLock.Unlock()
		return nil, err
	}

	deadline := time.Now().Add(4 * time.Second)
	for {
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			return func() {
				_ = os.Remove(lockPath)
				localLock.Unlock()
			}, nil
		}
		if !os.IsExist(err) {
			localLock.Unlock()
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			localLock.Unlock()
			return nil, fmt.Errorf("timed out locking actor state (%q, %q)", key.SessionKey, key.ActorKey)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func LoadState(key StateKey) (*State, error) {
	unlock, err := lockActorState(key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return loadStateUnlocked(key)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func saveStateUnlocked(key StateKey, state *State) error {
	if err := validateStateKey(key); err != nil {
		return err
	}
	state.SchemaVersion = CurrentStateSchemaVersion
	state.SessionKey = key.SessionKey
	state.ActorKey = key.ActorKey
	initializeStateCollections(state)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(statePath(key), data, 0o644)
}

func SaveState(key StateKey, state *State) error {
	unlock, err := lockActorState(key)
	if err != nil {
		return err
	}
	defer unlock()
	return saveStateUnlocked(key, state)
}

// UpdateState serializes a complete actor read/modify/write transaction.
func UpdateState(key StateKey, initialPhase string, update func(*State) error) error {
	unlock, err := lockActorState(key)
	if err != nil {
		return err
	}
	defer unlock()

	state, err := loadStateUnlocked(key)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		state = NewState(initialPhase)
	}
	if err := update(state); err != nil {
		return err
	}
	return saveStateUnlocked(key, state)
}

func DeleteActorState(key StateKey) error {
	unlock, err := lockActorState(key)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := readActorState(key); err != nil {
		if os.IsNotExist(err) {
			return clearActiveActorBinding(key)
		}
		return err
	}
	if err := os.Remove(statePath(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := clearActiveActorBinding(key); err != nil {
		return err
	}
	_ = os.Remove(filepath.Dir(statePath(key)))
	return nil
}

const (
	// endedFamilySuffix marks a session family retired by SessionEnd. The
	// family is kept (renamed) rather than deleted so a resumed session —
	// context compaction restarts fire SessionEnd + SessionStart with the
	// same session id — recovers its touched/adopted tracking instead of
	// misclassifying its own in-flight edits as pre-existing dirt.
	endedFamilySuffix = ".ended"
	// endedFamilyTTL is how long a retired family survives before the sweep
	// in DeleteSessionFamily purges it.
	endedFamilyTTL = 7 * 24 * time.Hour
)

func endedFamilyPath(sessionKey string) string {
	return sessionFamilyPath(sessionKey) + endedFamilySuffix
}

// restoreEndedFamily revives a retired session family in place, if present.
// Returns true when a tombstone was restored.
func restoreEndedFamily(sessionKey string) bool {
	ended := endedFamilyPath(sessionKey)
	if _, err := os.Stat(ended); err != nil {
		return false
	}
	family := sessionFamilyPath(sessionKey)
	if _, err := os.Stat(family); err == nil {
		return false // live family exists; leave the tombstone alone
	}
	return os.Rename(ended, family) == nil
}

// sweepEndedFamilies removes retired families older than endedFamilyTTL.
func sweepEndedFamilies() {
	familiesDir := filepath.Join(stateDir(), "families")
	entries, err := os.ReadDir(familiesDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-endedFamilyTTL)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), endedFamilySuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(familiesDir, entry.Name()))
	}
}

// PurgeSessionFamily removes a session family AND its tombstone — a terminal
// delete with no resume path. Tests and explicit cleanup use this; the
// SessionEnd hook uses DeleteSessionFamily, which retires instead.
func PurgeSessionFamily(sessionKey string) error {
	if err := DeleteSessionFamily(sessionKey); err != nil {
		return err
	}
	return os.RemoveAll(endedFamilyPath(sessionKey))
}

func DeleteSessionFamily(sessionKey string) error {
	if sessionKey == "" {
		return fmt.Errorf("empty session key")
	}
	family := sessionFamilyPath(sessionKey)
	actorDir := filepath.Join(family, "actors")
	entries, err := os.ReadDir(actorDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(actorDir, entry.Name()))
		if err != nil {
			return err
		}
		var state State
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode actor state during session cleanup: %w", err)
		}
		if state.SchemaVersion != CurrentStateSchemaVersion || state.SessionKey != sessionKey || state.ActorKey == "" {
			return fmt.Errorf("state identity collision during session cleanup")
		}
	}
	// Retire rather than delete: a compaction restart resumes the same
	// session id moments later and must find its tracking intact.
	if _, statErr := os.Stat(family); statErr == nil {
		ended := endedFamilyPath(sessionKey)
		if err := os.RemoveAll(ended); err != nil {
			return err
		}
		if err := os.Rename(family, ended); err != nil {
			return err
		}
		_ = os.Chtimes(ended, time.Now(), time.Now())
	}
	sweepEndedFamilies()
	if legacyPathIsSafe(sessionKey) {
		if err := os.Remove(legacyStatePath(sessionKey)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Path normalization: convert backslashes to forward slashes.
func NormalizePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// NormalizeInput normalizes path fields in tool input to forward slashes.
func NormalizeInput(input map[string]any) map[string]any {
	normalized := make(map[string]any, len(input))
	for k, v := range input {
		if !isPathField(k) {
			normalized[k] = v
			continue
		}
		if s, ok := v.(string); ok {
			normalized[k] = NormalizePath(s)
			continue
		}
		if paths, ok := stringSlice(v); ok {
			normalizedPaths := make([]string, len(paths))
			for i, path := range paths {
				normalizedPaths[i] = NormalizePath(path)
			}
			normalized[k] = normalizedPaths
			continue
		}
		normalized[k] = v
	}
	return normalized
}

func appendUniquePath(paths []string, path string) []string {
	path = NormalizePath(path)
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func (s *State) normalizeTrackedPath(path string) string {
	path = NormalizePath(path)
	if s.RepoRoot == "" {
		return path
	}
	rel, err := filepath.Rel(filepath.FromSlash(s.RepoRoot), filepath.FromSlash(path))
	if err != nil {
		return path
	}
	rel = NormalizePath(rel)
	if rel == "." || strings.HasPrefix(rel, "../") {
		return path
	}
	return rel
}

func stringListToAny(items []string) []any {
	if len(items) == 0 {
		return []any{}
	}
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = item
	}
	return out
}

func isPathField(name string) bool {
	switch name {
	case "file_path", "file_paths", "path", "directory", "cwd":
		return true
	default:
		return false
	}
}

// Evaluation — deny-is-veto semantics.

type Result struct {
	Action  string
	Message string
}

var factsRefRe = regexp.MustCompile(`facts\.(\w+)`)

// signalRefRe matches both session.signals.contains("x") and "x" in session.signals
var signalRefRe = regexp.MustCompile(`(?:session\.signals\.contains\("([^"]+)"\)|"([^"]+)"\s+in\s+session\.signals)`)

// Evaluate checks all rules against the event. Deny-is-veto:
// - Any deny → denied (first deny message used)
// - No denies, some context → all context messages joined
// - Nothing matches → allowed (nil)
// Returns the result, the one-time signals that changed a rule's outcome, and any error.
func Evaluate(guard *Guard, state *State, event ToolEvent) (*Result, map[string]bool, error) {
	return EvaluateVerbose(guard, state, event, guard.repoStatus, nil)
}

// EvaluateVerbose is like Evaluate but writes debug info to verbose when non-nil.
// Returns the result, the set of signal names referenced by matched rules, and any error.
func EvaluateVerbose(guard *Guard, state *State, event ToolEvent, repoStatus *RepoStatus, verbose io.Writer) (*Result, map[string]bool, error) {
	// Ward's runtime control plane must remain reachable from every phase.
	// Otherwise a phase rule that denies its shell transport can trap the actor
	// in that phase and also deny the signal/ownership commands needed to obey
	// the policy. Only a single, exact Ward invocation is exempt; command chains
	// continue through normal rule evaluation.
	if isWardControlPlaneCommand(event.Input) {
		if verbose != nil {
			fmt.Fprintln(verbose, "ward: control-plane command allowed")
		}
		return nil, map[string]bool{}, nil
	}

	if repoStatus == nil {
		repoStatus = &RepoStatus{Clean: true}
		for _, rule := range guard.Rules {
			if strings.Contains(rule.When, "repo.") {
				repoStatus, _ = ComputeRepoStatus(EffectiveRepoDir(event))
				break
			}
		}
	}

	sessionMap := state.ToMap()

	if verbose != nil {
		fmt.Fprintf(verbose, "ward: eval tool=%s  phase=%s  history_len=%d\n",
			canonicalToolName(event.Tool), state.Phase, len(state.History))
	}

	// Normalize input paths. Repo context follows the directory the event's
	// git commands actually target (cd prefixes / git -C), not the shell cwd.
	normalizedInput := NormalizeInput(event.Input)
	enrichCommandRepoContext(normalizedInput, repoStatus)

	// Determine which facts are referenced by any rule
	neededFacts := make(map[string]bool)
	for _, rule := range guard.Rules {
		for _, match := range factsRefRe.FindAllStringSubmatch(rule.When, -1) {
			neededFacts[match[1]] = true
		}
	}

	// Compute only needed facts
	factsMap := make(map[string]any)
	for name := range neededFacts {
		fact, ok := guard.Facts[name]
		if !ok {
			continue
		}
		if val, ok := guard.factValues[name]; ok {
			factsMap[name] = val
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   fact %s = %v\n", name, val)
			}
			continue
		}
		val, err := computeFact(fact, event.CWD)
		if err != nil {
			factsMap[name] = ""
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   fact %s: error: %v\n", name, err)
			}
			continue
		}
		factsMap[name] = val
		if verbose != nil {
			fmt.Fprintf(verbose, "ward:   fact %s = %v\n", name, val)
		}
	}

	activation := map[string]any{
		"tool":    canonicalToolName(event.Tool),
		"input":   normalizedInput,
		"session": sessionMap,
		"facts":   factsMap,
		"repo":    repoActivation(repoStatus, state, verbose),
	}

	// Collect all matching results: deny-is-veto, context accumulates
	matchedSignals := make(map[string]bool)
	var contextMessages []string
	for _, rule := range guard.Rules {
		ruleLabel := rule.filename
		if ruleLabel == "" {
			ruleLabel = "(inline)"
		}

		// Check scope if present
		if rule.Scope != "" {
			filePath := ""
			if fp, ok := normalizedInput["file_path"].(string); ok {
				filePath = fp
			}
			if filePath == "" {
				if verbose != nil {
					fmt.Fprintf(verbose, "ward:   rule %s: scope=%q skip (no file_path)\n", ruleLabel, rule.Scope)
				}
				continue // scope requires a file path
			}
			matched, _ := filepath.Match(NormalizePath(rule.Scope), filePath)
			if !matched {
				// Also try matching just the relative part
				matched, _ = filepath.Match(NormalizePath(rule.Scope), filepath.Base(filePath))
				if !matched {
					// Try prefix match for directory scopes like "output/**"
					scope := NormalizePath(rule.Scope)
					if strings.HasSuffix(scope, "/**") {
						prefix := strings.TrimSuffix(scope, "/**")
						if !strings.HasPrefix(filePath, prefix+"/") && !strings.HasPrefix(filePath, prefix) {
							if verbose != nil {
								fmt.Fprintf(verbose, "ward:   rule %s: scope=%q skip (path %q not matched)\n", ruleLabel, rule.Scope, filePath)
							}
							continue
						}
					} else {
						if verbose != nil {
							fmt.Fprintf(verbose, "ward:   rule %s: scope=%q skip (path %q not matched)\n", ruleLabel, rule.Scope, filePath)
						}
						continue
					}
				}
			}
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   rule %s: scope=%q matched path %q\n", ruleLabel, rule.Scope, filePath)
			}
		}

		out, _, err := rule.program.Eval(activation)
		if err != nil {
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   rule %s: eval ERROR: %v\n", ruleLabel, err)
			}
			continue // rule doesn't apply (e.g., missing field)
		}
		matches := out.Type() == types.BoolType && out.Value().(bool)
		oneTimeRefs := make(map[string]bool)
		for _, match := range signalRefRe.FindAllStringSubmatch(rule.When, -1) {
			name := match[1]
			if name == "" {
				name = match[2]
			}
			if signal, ok := state.Signals[name]; ok && signal.OneTimeUse {
				oneTimeRefs[name] = true
			}
		}
		if out.Type() == types.BoolType && len(oneTimeRefs) > 0 {
			sessionWithoutSignals := make(map[string]any, len(sessionMap))
			for name, value := range sessionMap {
				sessionWithoutSignals[name] = value
			}
			remainingSignals := make([]any, 0, len(state.Signals)-len(oneTimeRefs))
			for name := range state.Signals {
				if !oneTimeRefs[name] {
					remainingSignals = append(remainingSignals, name)
				}
			}
			sessionWithoutSignals["signals"] = remainingSignals
			activationWithoutSignals := make(map[string]any, len(activation))
			for name, value := range activation {
				activationWithoutSignals[name] = value
			}
			activationWithoutSignals["session"] = sessionWithoutSignals
			withoutSignals, _, withoutErr := rule.program.Eval(activationWithoutSignals)
			if withoutErr == nil && withoutSignals.Type() == types.BoolType && withoutSignals.Value().(bool) != matches {
				for name := range oneTimeRefs {
					matchedSignals[name] = true
				}
			}
		}
		if !matches {
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   rule %s: eval=false\n", ruleLabel)
			}
			continue
		}

		if verbose != nil {
			fmt.Fprintf(verbose, "ward:   rule %s: eval=true → %s\n", ruleLabel, rule.Action)
		}

		switch rule.Action {
		case "deny":
			if verbose != nil {
				fmt.Fprintf(verbose, "ward: DECISION: deny (%s)\n", rule.Message)
			}
			return &Result{
				Action:  "deny",
				Message: rule.Message,
			}, matchedSignals, nil
		case "context":
			contextMessages = append(contextMessages, rule.Message)
		case "allow":
			// allow doesn't block other rules in deny-is-veto
		}
	}

	if len(contextMessages) > 0 {
		if verbose != nil {
			fmt.Fprintf(verbose, "ward: DECISION: context (%d messages)\n", len(contextMessages))
		}
		return &Result{
			Action:  "context",
			Message: strings.Join(contextMessages, "\n"),
		}, matchedSignals, nil
	}

	if verbose != nil {
		fmt.Fprintf(verbose, "ward: DECISION: allow (no rules matched)\n")
	}
	return nil, matchedSignals, nil // no rule matched — allow
}

func repoActivation(status *RepoStatus, state *State, verbose io.Writer) map[string]any {
	if status == nil {
		return map[string]any{
			"in_git": false,
			"clean":  true,
		}
	}

	preexistingDirty := pathIntersection(status.DirtyPaths, state.BaselineDirtyPaths)
	preexistingStaged := pathIntersection(status.StagedPaths, state.BaselineDirtyPaths)
	touchedDirty := pathIntersection(status.DirtyPaths, state.TouchedFiles)
	stagedTouched := pathIntersection(status.StagedPaths, state.TouchedSinceCommit)
	nonTouchedStaged := pathDifference(status.StagedPaths, state.TouchedSinceCommit)

	if verbose != nil && status.InGit {
		fmt.Fprintf(verbose, "ward:   repo branch=%s clean=%t staged=%d unstaged=%d untracked=%d\n",
			status.Branch, status.Clean, len(status.StagedPaths), len(status.UnstagedPaths), len(status.UntrackedPaths))
	}

	return map[string]any{
		"in_git":                   status.InGit,
		"root":                     status.Root,
		"branch":                   status.Branch,
		"clean":                    status.Clean,
		"has_staged":               status.HasStaged,
		"has_unstaged":             status.HasUnstaged,
		"has_untracked":            status.HasUntracked,
		"dirty_paths":              stringListToAny(status.DirtyPaths),
		"staged_paths":             stringListToAny(status.StagedPaths),
		"unstaged_paths":           stringListToAny(status.UnstagedPaths),
		"untracked_paths":          stringListToAny(status.UntrackedPaths),
		"preexisting_dirty_paths":  stringListToAny(preexistingDirty),
		"preexisting_staged_paths": stringListToAny(preexistingStaged),
		"touched_dirty_paths":      stringListToAny(touchedDirty),
		"staged_touched_paths":     stringListToAny(stagedTouched),
		"non_touched_staged_paths": stringListToAny(nonTouchedStaged),
		"has_preexisting_dirty":    len(preexistingDirty) > 0,
		"has_preexisting_staged":   len(preexistingStaged) > 0,
		"has_non_touched_staged":   len(nonTouchedStaged) > 0,
	}
}

func enrichCommandRepoContext(input map[string]any, status *RepoStatus) {
	if status == nil || !status.InGit {
		return
	}

	commands, ok := input["commands"].([]any)
	if !ok {
		return
	}

	for _, raw := range commands {
		cmd, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		paths, _ := stringSlice(cmd["git_paths"])
		if len(paths) == 0 {
			cmd["git_has_directory_path"] = false
			cmd["git_has_dot_path"] = false
			continue
		}

		hasDir := false
		hasDot := false
		normalizedPaths := make([]string, 0, len(paths))
		for _, path := range paths {
			if isAbsShellPath(path) {
				relative, err := filepath.Rel(
					filepath.FromSlash(status.Root),
					filepath.FromSlash(path),
				)
				if err == nil {
					relative = NormalizePath(relative)
					if relative != ".." && !strings.HasPrefix(relative, "../") {
						path = relative
					}
				}
			}
			normalizedPaths = append(normalizedPaths, path)
			if path == "." {
				hasDot = true
			}
			fullPath := filepath.Join(filepath.FromSlash(status.Root), filepath.FromSlash(path))
			if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
				hasDir = true
			}
		}
		cmd["git_paths"] = stringListToAny(uniquePaths(normalizedPaths))
		cmd["git_has_directory_path"] = hasDir
		cmd["git_has_dot_path"] = hasDot
	}
}

func computeFact(fact Fact, cwd string) (any, error) {
	cmd := exec.Command("bash", "-c", fact.Command)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	val := strings.TrimSpace(string(out))

	switch fact.Type {
	case "bool":
		return val == "true" || val == "1", nil
	default:
		return val, nil
	}
}

func canonicalToolName(tool string) string {
	switch tool {
	case "local_shell", "exec_command", "functions.exec_command":
		return "Bash"
	case "apply_patch":
		return "Edit"
	default:
		return tool
	}
}

var wardControlPlaneCommands = map[string]bool{
	"set":         true,
	"enter":       true,
	"leave":       true,
	"allow":       true,
	"adopt":       true,
	"discard":     true,
	"revoke":      true,
	"validate":    true,
	"end-session": true,
	"start-actor": true,
	"end-actor":   true,
}

func isWardControlPlaneCommand(input map[string]any) bool {
	commands := commandsFromInput(input)
	if len(commands) != 1 {
		return false
	}
	command := commands[0]
	if command.Name != "ward" {
		return false
	}
	if len(command.Args) == 1 && (command.Args[0] == "--help" || command.Args[0] == "-h") {
		return true
	}
	return len(command.Args) > 0 && wardControlPlaneCommands[command.Args[0]]
}

func hasGitCommit(input map[string]any) bool {
	for _, cmd := range commandsFromInput(input) {
		if cmd.Name == "git" && strings.HasPrefix(cmd.Full, "git commit") {
			return true
		}
	}
	return false
}

func commandsFromInput(input map[string]any) []ParsedCommand {
	if input == nil {
		return nil
	}
	if commands, ok := input["commands"].([]any); ok {
		parsed := make([]ParsedCommand, 0, len(commands))
		for _, raw := range commands {
			cmd, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := cmd["name"].(string)
			full, _ := cmd["full"].(string)
			if name == "" && full == "" {
				continue
			}
			args, _ := stringSlice(cmd["args"])
			via, _ := stringSlice(cmd["via"])
			gitArgs, _ := stringSlice(cmd["git_args"])
			gitPaths, _ := stringSlice(cmd["git_paths"])
			gitSubcommand, _ := cmd["git_subcommand"].(string)
			gitCategory, _ := cmd["git_category"].(string)
			readOnly, _ := cmd["read_only"].(bool)
			parsed = append(parsed, ParsedCommand{
				Name:          name,
				Args:          args,
				Via:           via,
				Full:          full,
				GitSubcommand: gitSubcommand,
				GitArgs:       gitArgs,
				GitCategory:   gitCategory,
				GitPaths:      gitPaths,
				ReadOnly:      readOnly,
			})
		}
		if len(parsed) > 0 {
			return parsed
		}
	}
	if parts, ok := stringSlice(input["command_argv"]); ok && len(parts) > 0 {
		return parseArgvCommand(parts)
	}
	if cmd, ok := input["command"].(string); ok && cmd != "" {
		return ParseCommands(cmd)
	}
	return nil
}
