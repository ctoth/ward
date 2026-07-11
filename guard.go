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
	Facts map[string]Fact
	Rules []Rule
	env   *cel.Env
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
	History            []string          `json:"history"`
	Signals            map[string]Signal `json:"signals"`
	StartedAt          time.Time         `json:"started_at"`
	RepoRoot           string            `json:"repo_root,omitempty"`
	BaselineDirtyPaths []string          `json:"baseline_dirty_paths,omitempty"`
	TouchedFiles       []string          `json:"touched_files,omitempty"`
	TouchedSinceCommit []string          `json:"touched_since_commit,omitempty"`
	AdoptedPaths       []string          `json:"adopted_paths,omitempty"`
	DiscardablePaths   []string          `json:"discardable_paths,omitempty"`
}

func NewState(phase string) *State {
	if phase == "" {
		phase = DefaultPhase
	}
	return &State{
		Phase:              phase,
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

func (s *State) Update(tool string, input map[string]any) {
	toolName := canonicalToolName(tool)

	if toolName == "Edit" || toolName == "Write" {
		if filePath, ok := input["file_path"].(string); ok && filePath != "" {
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
	if s.RepoRoot == "" || s.RepoRoot != root {
		s.RepoRoot = root
		s.BaselineDirtyPaths = uniquePaths(status.DirtyPaths)
		s.TouchedFiles = nil
		s.TouchedSinceCommit = nil
		return
	}
	if s.BaselineDirtyPaths == nil {
		s.BaselineDirtyPaths = []string{}
	}
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

// ConsumeSignals removes one-time-use signals that were checked by matched rules.
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
			return nil
		}
		return err
	}
	if err := os.Remove(statePath(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(filepath.Dir(statePath(key)))
	return nil
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
	if err := os.RemoveAll(family); err != nil {
		return err
	}
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
		if s, ok := v.(string); ok && isPathField(k) {
			normalized[k] = NormalizePath(s)
		} else {
			normalized[k] = v
		}
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
	case "file_path", "path", "directory", "cwd":
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
// Returns the result, the set of signal names referenced by matched rules, and any error.
func Evaluate(guard *Guard, state *State, event ToolEvent) (*Result, map[string]bool, error) {
	return EvaluateVerbose(guard, state, event, nil)
}

// EvaluateVerbose is like Evaluate but writes debug info to verbose when non-nil.
// Returns the result, the set of signal names referenced by matched rules, and any error.
func EvaluateVerbose(guard *Guard, state *State, event ToolEvent, verbose io.Writer) (*Result, map[string]bool, error) {
	sessionMap := state.ToMap()

	if verbose != nil {
		fmt.Fprintf(verbose, "ward: eval tool=%s  phase=%s  history_len=%d\n",
			canonicalToolName(event.Tool), state.Phase, len(state.History))
	}

	// Normalize input paths
	normalizedInput := NormalizeInput(event.Input)
	enrichCommandRepoContext(normalizedInput, event.CWD)

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
		"repo":    repoActivation(event.CWD, state, verbose),
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
		if out.Type() != types.BoolType || !out.Value().(bool) {
			if verbose != nil {
				fmt.Fprintf(verbose, "ward:   rule %s: eval=false\n", ruleLabel)
			}
			continue
		}

		if verbose != nil {
			fmt.Fprintf(verbose, "ward:   rule %s: eval=true → %s\n", ruleLabel, rule.Action)
		}

		// Rule matched — extract signal references from this rule
		for _, match := range signalRefRe.FindAllStringSubmatch(rule.When, -1) {
			matchedSignals[match[1]] = true
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

func repoActivation(cwd string, state *State, verbose io.Writer) map[string]any {
	status, err := ComputeRepoStatus(cwd)
	if err != nil {
		if verbose != nil {
			fmt.Fprintf(verbose, "ward:   repo status: error: %v\n", err)
		}
		return map[string]any{
			"in_git": false,
			"clean":  true,
		}
	}

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

func enrichCommandRepoContext(input map[string]any, cwd string) {
	status, err := ComputeRepoStatus(cwd)
	if err != nil || status == nil || !status.InGit {
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
		for _, path := range paths {
			if path == "." {
				hasDot = true
			}
			fullPath := filepath.Join(filepath.FromSlash(status.Root), filepath.FromSlash(path))
			if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
				hasDir = true
			}
		}
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
	case "local_shell":
		return "Bash"
	default:
		return tool
	}
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
			parsed = append(parsed, ParsedCommand{Name: name, Full: full})
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
