package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"gopkg.in/yaml.v3"
)

// Config holds non-rule settings: default phase and facts.
// Loaded from ~/.ward/config.yaml (global) and .ward/config.yaml (project override).
type Config struct {
	DefaultPhase string          `yaml:"default_phase"`
	Facts        map[string]Fact `yaml:"facts"`
}

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

// Guard holds compiled config + rules, ready for evaluation.
type Guard struct {
	Config Config
	Rules  []Rule
	env    *cel.Env
}

// LoadConfig reads a config YAML (no rules). Missing file returns defaults.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{DefaultPhase: "planning"}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.DefaultPhase == "" {
		cfg.DefaultPhase = "planning"
	}
	return &cfg, nil
}

// MergeConfigs merges project config over global config.
// Project overrides default_phase if set; facts are merged (project wins on conflict).
func MergeConfigs(global, project *Config) *Config {
	merged := &Config{
		DefaultPhase: global.DefaultPhase,
		Facts:        make(map[string]Fact),
	}
	for k, v := range global.Facts {
		merged.Facts[k] = v
	}
	if project.DefaultPhase != "" && project.DefaultPhase != "planning" {
		merged.DefaultPhase = project.DefaultPhase
	}
	for k, v := range project.Facts {
		merged.Facts[k] = v
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

// NewGuard creates a Guard from config and rules, compiling all CEL expressions.
func NewGuard(cfg *Config, rules []Rule) (*Guard, error) {
	env, err := cel.NewEnv(
		cel.Variable("tool", cel.StringType),
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("facts", cel.MapType(cel.StringType, cel.DynType)),
	)
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
		Config: *cfg,
		Rules:  rules,
		env:    env,
	}, nil
}

// CompileRule compiles a single rule's CEL expression using the guard's environment.
// Used by the validate command.
func CompileRule(r *Rule) error {
	env, err := cel.NewEnv(
		cel.Variable("tool", cel.StringType),
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("facts", cel.MapType(cel.StringType, cel.DynType)),
	)
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

type State struct {
	Phase            string         `json:"phase"`
	ToolCount        int            `json:"tool_count"`
	ToolCounts       map[string]int `json:"tool_counts"`
	LastTool         string         `json:"last_tool"`
	ReadsSinceBash   int            `json:"reads_since_bash"`
	EditsSinceCommit int            `json:"edits_since_commit"`
	StartedAt        time.Time      `json:"started_at"`
}

func NewState(defaultPhase string) *State {
	return &State{
		Phase:      defaultPhase,
		ToolCounts: make(map[string]int),
		StartedAt:  time.Now(),
	}
}

func (s *State) Update(tool string, input map[string]any) {
	s.ToolCount++
	s.ToolCounts[tool]++
	s.LastTool = tool

	if tool == "Bash" {
		s.ReadsSinceBash = 0
	}
	if tool == "Read" || tool == "Glob" || tool == "Grep" {
		s.ReadsSinceBash++
	}

	if tool == "Bash" {
		if cmd, ok := input["command"].(string); ok {
			if strings.Contains(cmd, "git commit") {
				s.EditsSinceCommit = 0
			}
		}
	}
	if tool == "Edit" || tool == "Write" {
		s.EditsSinceCommit++
	}
}

func (s *State) ToMap() map[string]any {
	toolCounts := make(map[string]any, len(s.ToolCounts))
	for k, v := range s.ToolCounts {
		toolCounts[k] = int64(v)
	}
	return map[string]any{
		"phase":              s.Phase,
		"tool_count":         int64(s.ToolCount),
		"tool_counts":        toolCounts,
		"last_tool":          s.LastTool,
		"reads_since_bash":   int64(s.ReadsSinceBash),
		"edits_since_commit": int64(s.EditsSinceCommit),
		"started_at":         s.StartedAt.Format(time.RFC3339),
	}
}

func stateDir() string {
	tmp := os.TempDir()
	return filepath.Join(tmp, "ward")
}

func statePath(sessionID string) string {
	return filepath.Join(stateDir(), sessionID+".json")
}

func LoadState(sessionID string) (*State, error) {
	data, err := os.ReadFile(statePath(sessionID))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.ToolCounts == nil {
		s.ToolCounts = make(map[string]int)
	}
	return &s, nil
}

func SaveState(sessionID string, s *State) error {
	dir := stateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(sessionID), data, 0o644)
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

// Evaluate checks all rules against the event. Deny-is-veto:
// - Any deny → denied (first deny message used)
// - No denies, some context → all context messages joined
// - Nothing matches → allowed (nil)
func Evaluate(guard *Guard, state *State, event ToolEvent) (*Result, error) {
	sessionMap := state.ToMap()

	// Normalize input paths
	normalizedInput := NormalizeInput(event.Input)

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
		fact, ok := guard.Config.Facts[name]
		if !ok {
			continue
		}
		val, err := computeFact(fact, event.CWD)
		if err != nil {
			factsMap[name] = ""
			continue
		}
		factsMap[name] = val
	}

	activation := map[string]any{
		"tool":    event.Tool,
		"input":   normalizedInput,
		"session": sessionMap,
		"facts":   factsMap,
	}

	// Collect all matching results: deny-is-veto, context accumulates
	var contextMessages []string
	for _, rule := range guard.Rules {
		// Check scope if present
		if rule.Scope != "" {
			filePath := ""
			if fp, ok := normalizedInput["file_path"].(string); ok {
				filePath = fp
			}
			if filePath == "" {
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
							continue
						}
					} else {
						continue
					}
				}
			}
		}

		out, _, err := rule.program.Eval(activation)
		if err != nil {
			continue // rule doesn't apply (e.g., missing field)
		}
		if out.Type() != types.BoolType || !out.Value().(bool) {
			continue
		}

		switch rule.Action {
		case "deny":
			return &Result{
				Action:  "deny",
				Message: rule.Message,
			}, nil
		case "context":
			contextMessages = append(contextMessages, rule.Message)
		case "allow":
			// allow doesn't block other rules in deny-is-veto
		}
	}

	if len(contextMessages) > 0 {
		return &Result{
			Action:  "context",
			Message: strings.Join(contextMessages, "\n"),
		}, nil
	}

	return nil, nil // no rule matched — allow
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
