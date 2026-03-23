package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const envSession = "WARD_SESSION"
const envRulesPath = "WARD_RULES_PATH"
const envFactsPath = "WARD_FACTS_PATH"

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

Environment:
  WARD_RULES_PATH   Additional rule directories (PATH-separated).
                    Loaded between global and project rules.
  WARD_FACTS_PATH   Additional fact directories (PATH-separated).
                    Loaded between global and project facts.
  WARD_SESSION      Session ID for phase tracking.

Run 'ward <command> --help' for details on a command.`

const helpEval = `ward eval - evaluate a tool call event

Reads a JSON tool call event from stdin, evaluates all rules, and prints
a response to stdout. Prints nothing if the call is allowed.

Usage:
  ward eval [--verbose|-v] [--session ID] < event.json

Flags:
  -v, --verbose   Print debug info to stderr: each rule evaluated, scope
                  match results, CEL expression outcomes (true/false/error),
                  actions taken, and the final decision.

The JSON format is auto-detected for Claude Code, Gemini CLI, and Codex CLI.

Example:
  echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",
    "tool_input":{"command":"git stash"},"session_id":"abc",
    "cwd":"/tmp"}' | ward eval -v`

const helpSet = `ward set - set the session phase

Usage:
  ward set <phase> [--session ID]

The session ID can also be provided via the WARD_SESSION env var.

Example:
  ward set implementing --session abc`

const helpValidate = `ward validate - validate rule and fact files

Scans rule files in global (~/.ward/rules/), WARD_RULES_PATH directories, and
project (.ward/rules/) directories, compiles each CEL expression, and reports
errors. Also validates fact files from ~/.ward/facts/, WARD_FACTS_PATH, and
.ward/facts/.

Priority: project-local rules are evaluated last. Deny-is-veto means the first
deny wins. For facts, project values override env-path values which override
global values.

Usage:
  ward validate`

func hasVerboseFlag(args []string) bool {
	for _, a := range args {
		if a == "--verbose" || a == "-v" {
			return true
		}
	}
	return false
}

func cmdEval() {
	verbose := hasVerboseFlag(os.Args[2:])

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

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = os.Stderr
	}

	result, err := EvaluateVerbose(guard, state, event, verboseWriter)
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

	out, err := EncodeResponse(agent, event.EventType, result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: encode response: %v\n", err)
		os.Exit(1)
	}
	if out == nil {
		return
	}
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

// labeledDir pairs a directory path with a label for validate output.
type labeledDir struct {
	path  string
	label string
}

func cmdValidate() {
	globalRulesDir, projectRulesDir := ruleDirs()
	globalFactsDir, projectFactsDir := factsDirs()

	// Build labeled directory lists
	ruleDirList := []labeledDir{
		{globalRulesDir, "global"},
	}
	for _, dir := range envPathDirs(envRulesPath) {
		ruleDirList = append(ruleDirList, labeledDir{dir, "WARD_RULES_PATH"})
	}
	ruleDirList = append(ruleDirList, labeledDir{projectRulesDir, "project"})

	factsDirList := []labeledDir{
		{globalFactsDir, "global"},
	}
	for _, dir := range envPathDirs(envFactsPath) {
		factsDirList = append(factsDirList, labeledDir{dir, "WARD_FACTS_PATH"})
	}
	factsDirList = append(factsDirList, labeledDir{projectFactsDir, "project"})

	totalFiles := 0
	totalErrors := 0

	// Validate rules
	fmt.Fprintf(os.Stderr, "Rules:\n")
	for _, ld := range ruleDirList {
		entries, err := os.ReadDir(ld.path)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "  %s (%s, not found, skipping)\n", ld.path, ld.label)
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s: %v\n", ld.path, err)
			totalErrors++
			continue
		}

		fmt.Fprintf(os.Stderr, "  %s (%s)\n", ld.path, ld.label)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isYAML(name) {
				continue
			}
			totalFiles++
			path := filepath.Join(ld.path, name)
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
	for _, ld := range factsDirList {
		entries, err := os.ReadDir(ld.path)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "  %s (%s, not found, skipping)\n", ld.path, ld.label)
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s: %v\n", ld.path, err)
			totalErrors++
			continue
		}

		fmt.Fprintf(os.Stderr, "  %s (%s)\n", ld.path, ld.label)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isYAML(name) {
				continue
			}
			totalFiles++
			path := filepath.Join(ld.path, name)
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

	// Load rules: global → WARD_RULES_PATH → project
	globalRules, err := LoadRulesFromDir(globalRulesDir)
	if err != nil {
		return nil, fmt.Errorf("global rules: %w", err)
	}
	allRules := globalRules

	for _, dir := range envPathDirs(envRulesPath) {
		extra, err := LoadRulesFromDir(dir)
		if err != nil {
			return nil, fmt.Errorf("WARD_RULES_PATH rules (%s): %w", dir, err)
		}
		allRules = append(allRules, extra...)
	}

	projectRules, err := LoadRulesFromDir(projectRulesDir)
	if err != nil {
		return nil, fmt.Errorf("project rules: %w", err)
	}
	allRules = append(allRules, projectRules...)

	// Load facts: global → WARD_FACTS_PATH → project
	globalFacts, err := LoadFactsFromDir(globalFactsDir)
	if err != nil {
		return nil, fmt.Errorf("global facts: %w", err)
	}
	allFacts := globalFacts
	if allFacts == nil {
		allFacts = make(map[string]Fact)
	}

	for _, dir := range envPathDirs(envFactsPath) {
		extra, err := LoadFactsFromDir(dir)
		if err != nil {
			return nil, fmt.Errorf("WARD_FACTS_PATH facts (%s): %w", dir, err)
		}
		allFacts = MergeFacts(allFacts, extra)
	}

	projectFacts, err := LoadFactsFromDir(projectFactsDir)
	if err != nil {
		return nil, fmt.Errorf("project facts: %w", err)
	}
	allFacts = MergeFacts(allFacts, projectFacts)

	return NewGuard(allFacts, allRules)
}

// envPathDirs splits an environment variable by os.PathListSeparator
// and returns non-empty directory paths.
func envPathDirs(envVar string) []string {
	val := os.Getenv(envVar)
	if val == "" {
		return nil
	}
	parts := filepath.SplitList(val)
	var dirs []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			dirs = append(dirs, p)
		}
	}
	return dirs
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
