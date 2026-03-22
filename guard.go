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

// Config

type Config struct {
	DefaultPhase string          `yaml:"default_phase"`
	Facts        map[string]Fact `yaml:"facts"`
	Rules        []Rule          `yaml:"rules"`

	// compiled CEL programs, populated at load time
	programs []cel.Program
	env      *cel.Env
}

type Fact struct {
	Command string `yaml:"command"`
	Type    string `yaml:"type"` // "string" (default) or "bool"
}

type Rule struct {
	When    string `yaml:"when"`
	Action  string `yaml:"action"`  // "deny", "allow", "context"
	Message string `yaml:"message"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.DefaultPhase == "" {
		cfg.DefaultPhase = "planning"
	}

	// Build CEL environment
	env, err := cel.NewEnv(
		cel.Variable("tool", cel.StringType),
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("facts", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	cfg.env = env

	// Compile all rules
	cfg.programs = make([]cel.Program, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		ast, issues := env.Compile(rule.When)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i, rule.When, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %d program: %w", i, err)
		}
		cfg.programs[i] = prg
	}

	return &cfg, nil
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

	// Reset reads_since_bash when Bash is called
	if tool == "Bash" {
		s.ReadsSinceBash = 0
	}
	if tool == "Read" || tool == "Glob" || tool == "Grep" {
		s.ReadsSinceBash++
	}

	// Reset edits_since_commit when git commit detected
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

// Evaluation

type Result struct {
	Action  string
	Message string
}

var factsRefRe = regexp.MustCompile(`facts\.(\w+)`)

func Evaluate(cfg *Config, state *State, event ToolEvent) (*Result, error) {
	sessionMap := state.ToMap()

	// Determine which facts are referenced by any rule
	neededFacts := make(map[string]bool)
	for _, rule := range cfg.Rules {
		for _, match := range factsRefRe.FindAllStringSubmatch(rule.When, -1) {
			neededFacts[match[1]] = true
		}
	}

	// Compute only needed facts
	factsMap := make(map[string]any)
	for name := range neededFacts {
		fact, ok := cfg.Facts[name]
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

	// Build CEL activation
	activation := map[string]any{
		"tool":    event.Tool,
		"input":   event.Input,
		"session": sessionMap,
		"facts":   factsMap,
	}

	// Evaluate rules in order, first match wins
	for i, prg := range cfg.programs {
		out, _, err := prg.Eval(activation)
		if err != nil {
			continue // rule doesn't apply (e.g., missing field)
		}
		if out.Type() == types.BoolType && out.Value().(bool) {
			return &Result{
				Action:  cfg.Rules[i].Action,
				Message: cfg.Rules[i].Message,
			}, nil
		}
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

