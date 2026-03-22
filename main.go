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
		fmt.Fprintln(os.Stderr, "usage: ward <eval|set> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "eval":
		cmdEval()
	case "set":
		cmdSet()
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

	configPath := findConfig()
	cfg, err := LoadConfig(configPath)
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
		state = NewState(cfg.DefaultPhase)
	}

	state.Update(event.Tool, event.Input)

	result, err := Evaluate(cfg, state, event)
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

func sessionFromArgs() string {
	for i, arg := range os.Args {
		if arg == "--session" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return os.Getenv(envSession)
}

func findConfig() string {
	// Check current directory first, then home
	candidates := []string{
		"ward.yaml",
		".ward.yaml",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".config", "ward", "ward.yaml"),
			filepath.Join(home, ".ward.yaml"),
		)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "ward.yaml" // will fail at load time with a clear error
}
