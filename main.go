package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const envSession = "WARD_SESSION"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ward <eval|set|validate> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "eval":
		cmdEval()
	case "set":
		cmdSet()
	case "validate":
		cmdValidate()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdEval() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: read stdin: %v\n", err)
		os.Exit(1)
	}

	guard, err := loadGuard()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load config: %v\n", err)
		os.Exit(1)
	}

	event, agent, err := DetectAndParse(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: parse input: %v\n", err)
		os.Exit(1)
	}

	state, err := LoadState(event.SessionID)
	if err != nil {
		state = NewState(guard.Config.DefaultPhase)
	}

	state.Update(event.Tool, event.Input)

	result, err := Evaluate(guard, state, event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: evaluate: %v\n", err)
		os.Exit(1)
	}

	if err := SaveState(event.SessionID, state); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
	}

	if result == nil {
		return // allow — no output
	}

	response := FormatResponse(agent, result)
	out, _ := json.Marshal(response)
	fmt.Println(string(out))
}

func cmdSet() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward set <phase> [--session ID]")
		os.Exit(1)
	}
	phase := os.Args[2]
	sessionID := sessionFromArgs()
	if sessionID == "" {
		fmt.Fprintln(os.Stderr, "ward: session ID required (--session or WARD_SESSION env var)")
		os.Exit(1)
	}

	state, err := LoadState(sessionID)
	if err != nil {
		state = NewState(phase)
	}
	state.Phase = phase

	if err := SaveState(sessionID, state); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: phase → %s\n", phase)
}

func cmdValidate() {
	globalRulesDir, projectRulesDir := ruleDirs()
	dirs := []string{globalRulesDir, projectRulesDir}

	totalFiles := 0
	totalErrors := 0

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "  %s (not found, skipping)\n", dir)
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s: %v\n", dir, err)
			totalErrors++
			continue
		}

		fmt.Fprintf(os.Stderr, "  %s\n", dir)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isYAML(name) {
				continue
			}
			totalFiles++
			path := filepath.Join(dir, name)
			r, err := LoadRule(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    FAIL  %s: %v\n", name, err)
				totalErrors++
				continue
			}
			if err := CompileRule(r); err != nil {
				fmt.Fprintf(os.Stderr, "    FAIL  %s: CEL error: %v\n", name, err)
				totalErrors++
				continue
			}
			fmt.Fprintf(os.Stderr, "    OK    %s  [%s]\n", name, r.Action)
		}
	}

	fmt.Fprintf(os.Stderr, "\n%d rule files scanned, %d errors\n", totalFiles, totalErrors)
	if totalErrors > 0 {
		os.Exit(1)
	}
}

func isYAML(name string) bool {
	return filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml"
}

func sessionFromArgs() string {
	for i, arg := range os.Args {
		if arg == "--session" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return os.Getenv(envSession)
}

// loadGuard discovers config and rules from standard locations, compiles them.
func loadGuard() (*Guard, error) {
	globalConfigPath, projectConfigPath := configPaths()
	globalRulesDir, projectRulesDir := ruleDirs()

	// Load and merge configs
	globalCfg, err := LoadConfig(globalConfigPath)
	if err != nil {
		return nil, fmt.Errorf("global config: %w", err)
	}
	projectCfg, err := LoadConfig(projectConfigPath)
	if err != nil {
		return nil, fmt.Errorf("project config: %w", err)
	}
	cfg := MergeConfigs(globalCfg, projectCfg)

	// Load rules from both directories
	globalRules, err := LoadRulesFromDir(globalRulesDir)
	if err != nil {
		return nil, fmt.Errorf("global rules: %w", err)
	}
	projectRules, err := LoadRulesFromDir(projectRulesDir)
	if err != nil {
		return nil, fmt.Errorf("project rules: %w", err)
	}

	allRules := append(globalRules, projectRules...)
	return NewGuard(cfg, allRules)
}

// configPaths returns (global, project) config file paths.
func configPaths() (string, string) {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ward", "config.yaml"),
		filepath.Join(".ward", "config.yaml")
}

// ruleDirs returns (global, project) rule directories.
func ruleDirs() (string, string) {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ward", "rules"),
		filepath.Join(".ward", "rules")
}
