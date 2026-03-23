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
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		if len(os.Args) >= 2 {
			os.Exit(0)
		}
		os.Exit(1)
	}

	switch os.Args[1] {
	case "eval":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpEval)
			os.Exit(0)
		}
		cmdEval()
	case "set":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpSet)
			os.Exit(0)
		}
		cmdSet()
	case "validate":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpValidate)
			os.Exit(0)
		}
		cmdValidate()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Run 'ward --help' for usage.")
		os.Exit(1)
	}
}

func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

func printUsage() {
	fmt.Fprintln(os.Stderr, helpMain)
}

const helpMain = `ward - session-aware guard for AI coding agents

Evaluates CEL rules against tool calls from Claude Code, Gemini CLI, and
Codex CLI, enforcing project-specific policies.

Usage:
  ward <command> [args]

Commands:
  eval       Evaluate a tool call event from stdin
  set        Set the session phase
  validate   Validate all rule and fact files

Configuration:
  ~/.ward/facts/*.yaml   Global facts (shell commands evaluated on demand)
  .ward/facts/*.yaml     Project facts (override global)
  ~/.ward/rules/*.yaml   Global rules
  .ward/rules/*.yaml     Project rules

Run 'ward <command> --help' for details on a command.`

const helpEval = `ward eval - evaluate a tool call event

Reads a JSON tool call event from stdin, evaluates all rules, and prints
a response to stdout. Prints nothing if the call is allowed.

Usage:
  ward eval < event.json

The JSON format is auto-detected for Claude Code, Gemini CLI, and Codex CLI.

Example:
  echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",
    "tool_input":{"command":"git stash"},"session_id":"abc",
    "cwd":"/tmp"}' | ward eval`

const helpSet = `ward set - set the session phase

Usage:
  ward set <phase> [--session ID]

The session ID can also be provided via the WARD_SESSION env var.

Example:
  ward set implementing --session abc`

const helpValidate = `ward validate - validate rule and fact files

Scans rule files in both global (~/.ward/rules/) and project (.ward/rules/)
directories, compiles each CEL expression, and reports errors. Also validates
fact files in ~/.ward/facts/ and .ward/facts/.

Usage:
  ward validate`

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
		state = NewState(DefaultPhase)
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
	globalFactsDir, projectFactsDir := factsDirs()

	totalFiles := 0
	totalErrors := 0

	// Validate rules
	fmt.Fprintf(os.Stderr, "Rules:\n")
	for _, dir := range []string{globalRulesDir, projectRulesDir} {
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

	// Validate facts
	fmt.Fprintf(os.Stderr, "\nFacts:\n")
	for _, dir := range []string{globalFactsDir, projectFactsDir} {
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
			factName, _, err := LoadFact(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    FAIL  %s: %v\n", name, err)
				totalErrors++
				continue
			}
			fmt.Fprintf(os.Stderr, "    OK    %s  [%s]\n", name, factName)
		}
	}

	fmt.Fprintf(os.Stderr, "\n%d files scanned, %d errors\n", totalFiles, totalErrors)
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

// loadGuard discovers facts and rules from standard locations, compiles them.
func loadGuard() (*Guard, error) {
	globalRulesDir, projectRulesDir := ruleDirs()
	globalFactsDir, projectFactsDir := factsDirs()

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

	// Load facts from both directories
	globalFacts, err := LoadFactsFromDir(globalFactsDir)
	if err != nil {
		return nil, fmt.Errorf("global facts: %w", err)
	}
	projectFacts, err := LoadFactsFromDir(projectFactsDir)
	if err != nil {
		return nil, fmt.Errorf("project facts: %w", err)
	}
	allFacts := MergeFacts(globalFacts, projectFacts)

	return NewGuard(allFacts, allRules)
}

// ruleDirs returns (global, project) rule directories.
func ruleDirs() (string, string) {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ward", "rules"),
		filepath.Join(".ward", "rules")
}

// factsDirs returns (global, project) facts directories.
func factsDirs() (string, string) {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ward", "facts"),
		filepath.Join(".ward", "facts")
}
