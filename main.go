package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const envSession = "WARD_SESSION"
const envCodexThread = "CODEX_THREAD_ID"
const envActorID = "WARD_ACTOR_ID"
const envRulesPath = "WARD_RULES_PATH"
const envFactsPath = "WARD_FACTS_PATH"
const envSignalsPath = "WARD_SIGNALS_PATH"

// envClaudeSession is exported by Claude Code into every tool subshell, so
// commands like `ward allow` can resolve the correct session without the
// process-tree walk (which breaks under msys bash on Windows: bash.exe's
// ancestry never reaches node.exe, so resolution used to fall back to a
// cwd-hash key and signals landed in a state bucket eval never reads).
const envClaudeSession = "CLAUDE_CODE_SESSION_ID"

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
	case "enter":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpEnter)
			os.Exit(0)
		}
		cmdEnter()
	case "leave":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpLeave)
			os.Exit(0)
		}
		cmdLeave()
	case "allow":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpAllow)
			os.Exit(0)
		}
		cmdAllow()
	case "adopt":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpAdopt)
			os.Exit(0)
		}
		cmdGrantPaths("adopt")
	case "discard":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpDiscard)
			os.Exit(0)
		}
		cmdGrantPaths("discard")
	case "revoke":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpRevoke)
			os.Exit(0)
		}
		cmdRevoke()
	case "validate":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpValidate)
			os.Exit(0)
		}
		cmdValidate()
	case "end-session":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpEndSession)
			os.Exit(0)
		}
		cmdEndSession()
	case "start-actor":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpStartActor)
			os.Exit(0)
		}
		cmdStartActor()
	case "end-actor":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpEndActor)
			os.Exit(0)
		}
		cmdEndActor()
	case "install":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpInstall)
			os.Exit(0)
		}
		cmdInstall()
	case "install-defaults":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpInstallDefaults)
			os.Exit(0)
		}
		cmdInstallDefaults()
	case "install-profile":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpInstallProfile)
			os.Exit(0)
		}
		cmdInstallProfile()
	case "update-profile":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpUpdateProfile)
			os.Exit(0)
		}
		cmdUpdateProfile()
	case "remove-profile":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpRemoveProfile)
			os.Exit(0)
		}
		cmdRemoveProfile()
	case "list-profiles":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpListProfiles)
			os.Exit(0)
		}
		cmdListProfiles()
	case "resolve-config":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpResolveConfig)
			os.Exit(0)
		}
		cmdResolveConfig()
	case "validate-profile":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpValidateProfile)
			os.Exit(0)
		}
		cmdValidateProfile()
	case "uninstall":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, helpUninstall)
			os.Exit(0)
		}
		cmdUninstall()
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
  eval          Evaluate a tool call event from stdin
  set           Set one actor's phase
  enter         Enter a scoped phase and remember the current phase
  leave         Leave a scoped phase and restore the previous phase
  allow         Add a one-time override signal
  adopt         Grant commit authority for exact repo-relative paths
  discard       Grant discard authority for exact repo-relative paths
  revoke        Remove an override signal
  start-actor   Initialize one actor record (SubagentStart hook)
  end-actor     Delete one actor record (SubagentStop hook)
  end-session   Delete a session family and registry (SessionEnd hook)
  install       Register ward hooks in Claude Code or Codex settings
  install-defaults Install built-in default profiles
  install-profile  Install a profile from a local path or git source
  update-profile   Reinstall an installed profile from its recorded source
  remove-profile   Remove an installed profile
  list-profiles    List installed profiles
  resolve-config   Export the effective loaded ruleset/config
  validate-profile Validate a profile bundle without installing it
  uninstall     Remove ward hooks from Claude Code or Codex settings
  validate      Validate all rule and fact files

Configuration:
  ~/.ward/profiles/*     Installed profile bundles
  .ward/facts/*.yaml     Project-local fact overlays
  .ward/rules/*.yaml     Project-local rule overlays
  .ward/signals/*.yaml   Project-local signal overlays

Environment:
  WARD_RULES_PATH   Additional rule directories (PATH-separated), loaded
                    after installed profiles and before project overlays.
  WARD_FACTS_PATH   Additional fact directories (PATH-separated), loaded
                    after installed profiles and before project overlays.
  WARD_SESSION      Session ID for phase tracking.
  CODEX_THREAD_ID   Codex session ID fallback when WARD_SESSION is unset.
  WARD_ACTOR_ID     Explicit actor identity for CLI-launched workers.
  WARD_SIGNALS_PATH Additional signal directories (PATH-separated), loaded
                    after installed profiles and before project overlays.

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

const helpSet = `ward set - set one actor's phase

Usage:
  ward set <phase> [--session ID] [--agent ID]
  ward set <phase> --hook-input < event.json

The session and actor can also be provided via WARD_SESSION and WARD_ACTOR_ID.
Selecting an actor binds it to the session, so later CLI commands and hook
events that omit actor identity continue to use that actor. An explicit
--agent, WARD_ACTOR_ID, or host-supplied agent_id takes precedence.

Example:
  ward set implementing --session abc`

const helpEnter = `ward enter - enter a scoped phase

Pushes the actor's current phase and activates the requested phase. Pair every
successful enter with ward leave so the previous phase is restored.

Usage:
  ward enter <phase> [--session ID] [--agent ID]

Example:
  ward enter adversary --session abc`

const helpLeave = `ward leave - leave a scoped phase

Restores the phase saved by the actor's most recent ward enter. Fails when the
actor has no entered phase to leave.

Usage:
  ward leave [--session ID] [--agent ID]`

const helpValidate = `ward validate - validate the effective installed config

Validates installed profiles plus env/project overlays, compiles each CEL rule,
and reports manifest/load/compile errors for the effective configuration.

Usage:
  ward validate`

const helpEndSession = `ward end-session - delete a session family

Reads a SessionEnd event from stdin (JSON with session_id), removes every actor
record, the legacy state file, and process registry entries for that session.

Usage:
  ward end-session < event.json

The session_id is read from the stdin JSON, same format as other hooks.`

const helpStartActor = `ward start-actor - initialize one actor state record

Reads a Claude SubagentStart JSON event from stdin. Creates the actor named by
agent_id in the uninitialized phase and records agent_type without mutating the
main actor or sibling workers. Repeated starts do not reset an existing phase.

Usage:
  ward start-actor < event.json`

const helpEndActor = `ward end-actor - delete one actor state record

Reads a Claude SubagentStop JSON event from stdin. Deletes only the actor named
by agent_id; the main actor and sibling workers remain unchanged.

Usage:
  ward end-actor < event.json`

const helpInstall = `ward install - register ward hooks in host settings

Adds ward's PreToolUse (eval), SubagentStart (start-actor), SubagentStop
(end-actor), and SessionEnd (end-session) hooks to the selected host file.
Idempotent — safe to run multiple times.
Preserves all other hooks (claudio, etc).

Usage:
  ward install [claude|codex]

The default host is claude. Codex hooks are installed to ~/.codex/hooks.json.`

const helpInstallDefaults = `ward install-defaults - install built-in profile bundles

Usage:
  ward install-defaults --profile <name>[,<name>...] [--all]

Built-in profiles:
  core-safety
  git-discipline
  python
  windows`

const helpInstallProfile = `ward install-profile - install a profile from a path or git source

Usage:
  ward install-profile <source> [--ref <git-ref>] [--subdir <path>]

Examples:
  ward install-profile ./profiles/git-discipline
  ward install-profile https://github.com/example/ward-profiles.git --ref v1.2.0 --subdir profiles/git-discipline`

const helpUpdateProfile = `ward update-profile - reinstall an installed profile from its recorded source

Usage:
  ward update-profile <name>`

const helpRemoveProfile = `ward remove-profile - remove an installed profile

Usage:
  ward remove-profile <name>`

const helpListProfiles = `ward list-profiles - list installed profiles

Usage:
  ward list-profiles [--json]`

const helpResolveConfig = `ward resolve-config - export the effective loaded ruleset

Usage:
  ward resolve-config --json`

const helpValidateProfile = `ward validate-profile - validate a profile bundle without installing it

Usage:
  ward validate-profile <path> [--subdir <path>]`

const helpUninstall = `ward uninstall - remove ward hooks from host settings

Removes ward's hooks from the selected host file.
Preserves all other hooks.

Usage:
  ward uninstall [claude|codex]

The default host is claude. Codex hooks are removed from ~/.codex/hooks.json.`

const helpAllow = `ward allow - add a one-time override signal

Usage:
  ward allow <signal-name> [--session ID]

Adds a named signal to the session. Rules can check signals with
session.signals.contains("signal-name"). By default, signals are
consumed after the evaluation where they are checked.

To make a signal persistent, create a YAML definition:
  ~/.ward/signals/<signal-name>.yaml
with one_time_use: false

Signal definitions are loaded from:
  ~/.ward/signals/          (global)
  $WARD_SIGNALS_PATH dirs   (env, PATH-separated)
  .ward/signals/            (project, overrides others)

Example:
  ward allow force-push --session abc`

const helpAdopt = `ward adopt - explicitly include pre-existing paths in commit scope

Usage:
  ward adopt <path> [<path> ...] [--session ID]

Adds exact repo-relative file paths to session.adopted_paths. Adoption widens
commit authority only; it does NOT allow discard/reset/restore of those paths.

Example:
  ward adopt src/foo.py docs/spec.md --session abc`

const helpDiscard = `ward discard - explicitly allow discarding exact paths

Usage:
  ward discard <path> [<path> ...] [--session ID]

Adds exact repo-relative file paths to session.discardable_paths. This is
separate from adoption: a path may be adopted for commit without being
discardable.

Example:
  ward discard src/foo.py --session abc`

const helpRevoke = `ward revoke - remove an override signal

Usage:
  ward revoke <signal-name> [--session ID]

Removes a named signal from the session. No error if the signal
was not active.

Example:
  ward revoke force-push --session abc`

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

	event, agent, err := DetectAndParse(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: parse input: %v\n", err)
		os.Exit(1)
	}

	guard, err := loadGuard(event.CWD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load config: %v\n", err)
		os.Exit(1)
	}

	// Register CC PID → session_id so `ward allow` can resolve sessions
	// from the process tree when run via `!` inside Claude Code.
	if event.SessionID != "" {
		if ccPID, err := findClaudeCodeAncestorPID(); err == nil && ccPID != 0 {
			_ = registerSession(ccPID, event.SessionID, event.CWD)
		}
	}

	key, err := stateKeyFromHook(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}
	initialPhase := DefaultPhase
	if key.ActorKey != MainActorKey {
		initialPhase = UninitializedPhase
	}
	repoStatus, _ := ComputeRepoStatus(EffectiveRepoDir(event))

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = os.Stderr
	}

	var result *Result
	err = UpdateState(key, initialPhase, func(state *State) error {
		if event.AgentType != "" {
			state.AgentType = event.AgentType
		}
		state.SyncRepo(repoStatus)
		state.Update(event.Tool, event.Input)
		var matchedSignals map[string]bool
		var evalErr error
		result, matchedSignals, evalErr = EvaluateVerbose(guard, state, event, verboseWriter)
		if evalErr != nil {
			return evalErr
		}
		state.ConsumeSignals(matchedSignals)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: evaluate: %v\n", err)
		os.Exit(1)
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

func cmdAllow() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward allow <signal-name> [--session ID]")
		os.Exit(1)
	}
	name := os.Args[2]
	if !validSignalName.MatchString(name) {
		fmt.Fprintf(os.Stderr, "ward: invalid signal name %q\n", name)
		os.Exit(1)
	}
	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}

	// Default to one-time use unless a signal definition says otherwise.
	oneTime := true

	cwd, _ := os.Getwd()
	if config, err := resolveConfig(cwd); err == nil {
		if def, ok := config.signalDefs[name]; ok && def.OneTimeUse != nil {
			oneTime = *def.OneTimeUse
		}
	}

	if err := UpdateState(key, DefaultPhase, func(state *State) error {
		state.Signals[name] = Signal{OneTimeUse: oneTime}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}
	_, source := resolveCommandSessionWithSource(os.Args, resolveSessionFromProcessTree(), cwd)
	fmt.Fprintf(os.Stderr, "ward: signal %q activated (session %s, actor %s, via %s)\n",
		name, key.SessionKey, key.ActorKey, source)
	if source == "cwd-fallback" {
		fmt.Fprintf(os.Stderr,
			"ward: WARNING: session resolved from cwd hash, not a live agent session; "+
				"hook evaluation will NOT see this signal. Pass --session <id> or set %s.\n",
			envSession)
	}
}

func cmdGrantPaths(kind string) {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: ward %s <path> [<path> ...] [--session ID]\n", kind)
		os.Exit(1)
	}

	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}
	rawPaths := pathArgsFromCLI(os.Args[2:])
	if len(rawPaths) == 0 {
		fmt.Fprintf(os.Stderr, "ward: no paths supplied for %s\n", kind)
		os.Exit(1)
	}

	cwd, _ := os.Getwd()
	var normalized []string
	if err := UpdateState(key, DefaultPhase, func(state *State) error {
		var err error
		normalized, err = grantPaths(state, kind, cwd, rawPaths)
		return err
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ward: %s granted for %s\n", kind, strings.Join(normalized, ", "))
}

func grantPaths(state *State, kind, cwd string, rawPaths []string) ([]string, error) {
	normalized := make([]string, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		if rawPath == "" {
			return nil, fmt.Errorf("%s path: empty path", kind)
		}

		targetPath := rawPath
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(cwd, targetPath)
		}
		absPath, err := filepath.Abs(targetPath)
		if err != nil {
			return nil, fmt.Errorf("%s path %q: %w", kind, rawPath, err)
		}
		repoStatus, err := ComputeRepoStatus(filepath.Dir(absPath))
		if err != nil {
			return nil, fmt.Errorf("resolve repo for %s path %q: %w", kind, rawPath, err)
		}
		if repoStatus == nil || !repoStatus.InGit {
			return nil, fmt.Errorf("%s path %q is not inside a git repo", kind, rawPath)
		}
		path, err := normalizeGrantPath(repoStatus.Root, cwd, rawPath)
		if err != nil {
			return nil, fmt.Errorf("%s path %q: %w", kind, rawPath, err)
		}

		state.SyncRepo(repoStatus)
		switch kind {
		case "adopt":
			state.AdoptedPaths = uniquePaths(append(state.AdoptedPaths, path))
		case "discard":
			state.DiscardablePaths = uniquePaths(append(state.DiscardablePaths, path))
		default:
			return nil, fmt.Errorf("unknown grant kind %q", kind)
		}
		normalized = append(normalized, path)
	}
	return normalized, nil
}

func cmdRevoke() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward revoke <signal-name> [--session ID]")
		os.Exit(1)
	}
	name := os.Args[2]
	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}

	if err := UpdateState(key, DefaultPhase, func(state *State) error {
		delete(state.Signals, name)
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: signal %q revoked\n", name)
}

func cmdEndSession() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: read stdin: %v\n", err)
		os.Exit(1)
	}

	event, parseErr := hookIdentityFromInput(input)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "ward: %v\n", parseErr)
		os.Exit(1)
	}
	if err := DeleteSessionFromHookInput(input); err != nil {
		fmt.Fprintf(os.Stderr, "ward: end session: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: session ended %s\n", event.SessionID)
}

func cmdStartActor() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: read stdin: %v\n", err)
		os.Exit(1)
	}
	key, err := InitializeActorFromHookInput(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: start actor: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: actor started %s/%s\n", key.SessionKey, key.ActorKey)
}

func cmdEndActor() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: read stdin: %v\n", err)
		os.Exit(1)
	}
	event, parseErr := hookIdentityFromInput(input)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "ward: %v\n", parseErr)
		os.Exit(1)
	}
	if err := DeleteActorFromHookInput(input); err != nil {
		fmt.Fprintf(os.Stderr, "ward: end actor: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: actor ended %s/%s\n", event.SessionID, event.AgentID)
}

func cmdSet() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward set <phase> [--session ID] [--agent ID] [--hook-input]")
		os.Exit(1)
	}
	phase := os.Args[2]
	if flagValue(os.Args, "--hook-input") != "" || hasExactFlag(os.Args, "--hook-input") {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ward: read stdin: %v\n", err)
			os.Exit(1)
		}
		key, err := SetPhaseFromHookInput(input, phase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ward: set phase from hook: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ward: phase → %s (%s/%s)\n", phase, key.SessionKey, key.ActorKey)
		return
	}

	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}
	if err := UpdateState(key, phase, func(state *State) error {
		state.Phase = phase
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: phase → %s\n", phase)
}

func cmdEnter() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward enter <phase> [--session ID] [--agent ID]")
		os.Exit(1)
	}
	phase := os.Args[2]
	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}
	if err := UpdateState(key, DefaultPhase, func(state *State) error {
		state.EnterPhase(phase)
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save state: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: entered phase %s\n", phase)
}

func cmdLeave() {
	key, err := commandStateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve state identity: %v\n", err)
		os.Exit(1)
	}
	phase := ""
	if err := UpdateState(key, DefaultPhase, func(state *State) error {
		var leaveErr error
		phase, leaveErr = state.LeavePhase()
		return leaveErr
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ward: leave phase: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: phase restored to %s\n", phase)
}

func cmdValidate() {
	config, err := resolveConfig(mustGetwd())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate: %v\n", err)
		os.Exit(1)
	}
	totalErrors := 0
	fmt.Fprintf(os.Stderr, "Profiles:\n")
	for _, profile := range config.Profiles {
		fmt.Fprintf(os.Stderr, "  %s  [%s]\n", profile.Name, profile.Source)
	}
	fmt.Fprintf(os.Stderr, "\nRules:\n")
	for _, rule := range config.guardRules {
		if err := CompileRule(&rule); err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL  %s: %v\n", rule.filename, err)
			totalErrors++
			continue
		}
		fmt.Fprintf(os.Stderr, "  OK    %s  [%s]\n", rule.filename, rule.Action)
	}
	fmt.Fprintf(os.Stderr, "\nFacts:\n")
	for _, fact := range config.Facts {
		fmt.Fprintf(os.Stderr, "  OK    %s  [%s]\n", fact.Source, fact.Name)
	}
	fmt.Fprintf(os.Stderr, "\nSignals:\n")
	for _, signal := range config.Signals {
		fmt.Fprintf(os.Stderr, "  OK    %s  [%s]\n", signal.Source, signal.Name)
	}
	fmt.Fprintf(os.Stderr, "\n%d rules, %d facts, %d signals, %d errors\n", len(config.guardRules), len(config.Facts), len(config.Signals), totalErrors)
	if totalErrors > 0 {
		os.Exit(1)
	}
}

func isYAML(name string) bool {
	return filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml"
}

func pathArgsFromCLI(args []string) []string {
	paths := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--session" || arg == "--agent" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--session=") || strings.HasPrefix(arg, "--agent=") || arg == "--hook-input" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		paths = append(paths, arg)
	}
	return paths
}

func normalizeGrantPath(repoRoot, cwd, rawPath string) (string, error) {
	if rawPath == "" {
		return "", fmt.Errorf("empty path")
	}

	path := rawPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	repoRootAbs, err := filepath.Abs(filepath.FromSlash(repoRoot))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(repoRootAbs, absPath)
	if err != nil {
		return "", err
	}
	rel = NormalizePath(rel)
	if rel == "." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("must stay within repo root")
	}
	if strings.HasSuffix(rel, "/") || strings.Contains(rel, "*") {
		return "", fmt.Errorf("must be an exact file path")
	}
	return rel, nil
}

func flagValue(args []string, name string) string {
	for i, arg := range args {
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"=")
		}
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasExactFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func resolveCommandSession(args []string, processSession, cwd string) string {
	session, _ := resolveCommandSessionWithSource(args, processSession, cwd)
	return session
}

// resolveCommandSessionWithSource resolves the session key for a ward CLI
// command and reports where the key came from, so commands can tell the user
// which state bucket they touched instead of silently writing to a fallback
// key that eval never reads.
func resolveCommandSessionWithSource(args []string, processSession, cwd string) (string, string) {
	if explicit := flagValue(args, "--session"); explicit != "" {
		return explicit, "--session"
	}
	if value := os.Getenv(envSession); value != "" {
		return value, envSession
	}
	if value := os.Getenv(envCodexThread); value != "" {
		return value, envCodexThread
	}
	if value := os.Getenv(envClaudeSession); value != "" {
		return value, envClaudeSession
	}
	if processSession != "" {
		return processSession, "process-tree"
	}
	sum := sha256.Sum256([]byte(cwd))
	return fmt.Sprintf("wd-%x", sum[:8]), "cwd-fallback"
}

func sessionFromArgs() string {
	wd, _ := os.Getwd()
	return resolveCommandSession(os.Args, resolveSessionFromProcessTree(), wd)
}

func stateKeyFromCommandArgs(args []string, processSession, cwd string) (StateKey, error) {
	sessionKey := resolveCommandSession(args, processSession, cwd)
	actorKey := flagValue(args, "--agent")
	if actorKey == "" {
		actorKey = os.Getenv(envActorID)
	}
	if actorKey == "" {
		boundActor, err := loadActiveActor(sessionKey)
		if err == nil {
			actorKey = boundActor
		} else if !os.IsNotExist(err) {
			return StateKey{}, fmt.Errorf("load active actor binding: %w", err)
		}
	}
	if actorKey == "" {
		actorKey = MainActorKey
	}
	key := StateKey{
		SessionKey: sessionKey,
		ActorKey:   actorKey,
	}
	if err := validateStateKey(key); err != nil {
		return StateKey{}, err
	}
	return key, nil
}

func commandStateKey() (StateKey, error) {
	wd, _ := os.Getwd()
	key, err := stateKeyFromCommandArgs(os.Args, resolveSessionFromProcessTree(), wd)
	if err != nil {
		return StateKey{}, err
	}
	if err := bindActiveActor(key); err != nil {
		return StateKey{}, fmt.Errorf("bind active actor: %w", err)
	}
	return key, nil
}

func stateKeyFromHook(event ToolEvent) (StateKey, error) {
	actorKey := event.AgentID
	if actorKey == "" {
		actorKey = os.Getenv(envActorID)
	}
	if actorKey == "" {
		boundActor, err := loadActiveActor(event.SessionID)
		if err == nil {
			actorKey = boundActor
		} else if !os.IsNotExist(err) {
			return StateKey{}, fmt.Errorf("load active actor binding: %w", err)
		}
	}
	if actorKey == "" {
		actorKey = MainActorKey
	}
	key := StateKey{SessionKey: event.SessionID, ActorKey: actorKey}
	if err := validateStateKey(key); err != nil {
		return StateKey{}, err
	}
	return key, nil
}

func hookIdentityFromInput(input []byte) (ToolEvent, error) {
	var raw map[string]any
	if err := json.Unmarshal(input, &raw); err != nil {
		return ToolEvent{}, fmt.Errorf("parse hook input: %w", err)
	}
	event := ToolEvent{
		SessionID: strField(raw, "session_id"),
		AgentID:   strField(raw, "agent_id"),
		AgentType: strField(raw, "agent_type"),
	}
	if event.SessionID == "" {
		return ToolEvent{}, fmt.Errorf("no session_id in input")
	}
	return event, nil
}

func SetPhaseFromHookInput(input []byte, phase string) (StateKey, error) {
	event, err := hookIdentityFromInput(input)
	if err != nil {
		return StateKey{}, err
	}
	key, err := stateKeyFromHook(event)
	if err != nil {
		return StateKey{}, err
	}
	if key.ActorKey == MainActorKey {
		return StateKey{}, fmt.Errorf("actor initialization hook has no actor identity")
	}
	err = UpdateState(key, phase, func(state *State) error {
		state.Phase = phase
		if event.AgentType != "" {
			state.AgentType = event.AgentType
		}
		return nil
	})
	return key, err
}

func InitializeActorFromHookInput(input []byte) (StateKey, error) {
	event, err := hookIdentityFromInput(input)
	if err != nil {
		return StateKey{}, err
	}
	key, err := stateKeyFromHook(event)
	if err != nil {
		return StateKey{}, err
	}
	if key.ActorKey == MainActorKey {
		return StateKey{}, fmt.Errorf("SubagentStart input has no actor identity")
	}
	err = UpdateState(key, UninitializedPhase, func(state *State) error {
		if event.AgentType != "" {
			state.AgentType = event.AgentType
		}
		return nil
	})
	return key, err
}

func DeleteActorFromHookInput(input []byte) error {
	event, err := hookIdentityFromInput(input)
	if err != nil {
		return err
	}
	key, err := stateKeyFromHook(event)
	if err != nil {
		return err
	}
	if key.ActorKey == MainActorKey {
		return fmt.Errorf("SubagentStop input has no actor identity")
	}
	return DeleteActorState(key)
}

func DeleteSessionFromHookInput(input []byte) error {
	event, err := hookIdentityFromInput(input)
	if err != nil {
		return err
	}
	if err := DeleteSessionFamily(event.SessionID); err != nil {
		return err
	}
	return unregisterBySessionID(event.SessionID)
}

// loadGuard discovers facts and rules from standard locations, compiles them.
func loadGuard(cwd string) (*Guard, error) {
	config, err := resolveConfig(cwd)
	if err != nil {
		return nil, err
	}
	return NewGuard(config.guardFacts, config.guardRules)
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
