package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParsedCommand represents a single command extracted from a shell AST.
type ParsedCommand struct {
	Name          string   // the command name (first word)
	Args          []string // the arguments (everything after the command name)
	Via           []string // wrapper chain unwrapped to reach Name, outermost first (e.g. ["sudo", "uv"])
	Full          string   // reconstructed "name arg1 arg2 ..." without heredoc bodies
	GitSubcommand string   // parsed git subcommand (e.g. "checkout")
	GitArgs       []string
	GitCategory   string   // query, stage, commit, switch, restore, integrate, push, tag, history_rewrite, workspace_destructive
	GitPaths      []string // repo-relative path operands, when syntactically recoverable
	ReadOnly      bool     // command belongs to Ward's narrow discovery allowlist
	// Dir is the directory this command effectively runs in, relative to the
	// event cwd unless absolute: preceding `cd <path>` commands in the same
	// shell string compose into it, and git's global `-C <path>` composes on
	// top. Empty means "the event cwd" — either no cd/-C preceded the
	// command, or the target was not statically resolvable (`cd -`,
	// `cd "$dir"`), in which case ward falls back to the event cwd rather
	// than guessing.
	Dir string
}

// ParseCommands extracts the actual commands from a shell command string.
// It parses the shell into an AST and walks CallExpr nodes, extracting
// command names and arguments. Heredoc content, string literals inside
// heredocs, and command substitutions inside heredoc bodies are NOT
// included as top-level commands.
//
// If parsing fails, returns a single ParsedCommand with the raw string
// as both Name and Full, so rules still work as a fallback.
func ParseCommands(cmdStr string) []ParsedCommand {
	parser := syntax.NewParser(syntax.KeepComments(false))
	prog, err := parser.Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		// Fallback: treat the whole string as one command. Name/Args/Full are
		// normalized exactly like the AST path so the command-wrapper and path
		// bypasses stay closed even when the shell fails to parse.
		parts := strings.Fields(cmdStr)
		if len(parts) == 0 {
			return []ParsedCommand{annotateParsedCommand(ParsedCommand{Name: cmdStr, Full: cmdStr})}
		}
		name, fallbackArgs, via := normalizeInvocation(parts)
		cmd := ParsedCommand{
			Name: name,
			Args: fallbackArgs,
			Via:  via,
			Full: strings.Join(append([]string{name}, fallbackArgs...), " "),
		}
		return []ParsedCommand{annotateParsedCommand(cmd)}
	}

	var commands []ParsedCommand
	syntax.Walk(prog, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true // keep walking
		}
		if len(call.Args) == 0 {
			return true
		}

		// Extract literal parts from each word, skipping heredoc bodies
		var parts []string
		for _, word := range call.Args {
			lit := wordToString(word)
			parts = append(parts, lit)
		}

		if len(parts) == 0 {
			return true
		}

		name, cmdArgs, via := normalizeInvocation(parts)
		// Full is reconstructed from the normalized invocation so that
		// rules matching on the leading token (e.g. "^git", "^python")
		// see through directory paths, .exe suffixes, and command wrappers.
		fullParts := append([]string{name}, cmdArgs...)
		cmd := ParsedCommand{
			Name: name,
			Args: cmdArgs,
			Via:  via,
			Full: strings.Join(fullParts, " "),
		}
		commands = append(commands, annotateParsedCommand(cmd))

		// Don't recurse into this CallExpr's children — we already
		// extracted what we need. But we DO want to find sibling
		// commands in pipes/chains, which are at higher AST levels.
		return false
	})

	if len(commands) == 0 {
		// Parser succeeded but found no commands (e.g., empty string)
		return nil
	}

	return assignEffectiveDirs(commands)
}

// assignEffectiveDirs threads `cd` chains through the ordered command list so
// each command carries the directory it actually runs in. A `cd` whose target
// is not statically resolvable (no argument, `-`, or an unexpanded variable)
// poisons the chain: subsequent commands get Dir == "" (the event cwd) rather
// than a guess. Subshell scoping is deliberately over-approximated — a `cd`
// inside `( ... )` is treated as affecting later commands, which errs toward
// evaluating against the repo the agent named rather than missing it.
func assignEffectiveDirs(commands []ParsedCommand) []ParsedCommand {
	chainDir := ""
	known := true
	for i := range commands {
		cmd := &commands[i]
		effective := ""
		if known {
			effective = chainDir
		}
		if cmd.Name == "git" {
			if cDir := gitGlobalCDir(cmd.Args); cDir != "" {
				effective = joinShellDir(effective, cDir)
			}
		}
		cmd.Dir = effective
		if cmd.Name == "cd" {
			target := firstNonFlagArg(cmd.Args)
			if target == "" || target == "-" || strings.ContainsAny(target, "$`") {
				chainDir = ""
				known = false
				continue
			}
			next := chainDir
			if !known {
				next = ""
			}
			chainDir = joinShellDir(next, target)
			known = true
		}
	}
	return commands
}

// gitGlobalCDir composes git's global `-C <path>` options (which git applies
// in sequence, later relative paths resolving against earlier ones) that
// appear before the subcommand.
func gitGlobalCDir(args []string) string {
	dir := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "":
			continue
		case arg == "-C":
			if i+1 < len(args) {
				dir = joinShellDir(dir, args[i+1])
			}
			i++
		case arg == "-c" || arg == "--git-dir" || arg == "--work-tree" || arg == "--namespace":
			i++
		case strings.HasPrefix(arg, "-"):
			continue
		default:
			return dir // reached the subcommand
		}
	}
	return dir
}

func firstNonFlagArg(args []string) string {
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

// joinShellDir composes a relative-or-absolute path onto a base chain dir.
func joinShellDir(base, next string) string {
	next = NormalizePath(next)
	if base == "" || isAbsShellPath(next) {
		return next
	}
	return strings.TrimSuffix(base, "/") + "/" + next
}

func isAbsShellPath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/'
}

func annotateParsedCommand(cmd ParsedCommand) ParsedCommand {
	if strings.EqualFold(cmd.Name, "git") {
		subcommand, gitArgs := parseGitInvocation(cmd.Args)
		cmd.GitSubcommand = subcommand
		cmd.GitArgs = gitArgs
		cmd.GitCategory = classifyGitCommand(subcommand, gitArgs)
		cmd.GitPaths = gitPathspecs(subcommand, gitArgs)
	}
	cmd.ReadOnly = classifyReadOnlyCommand(cmd)
	return cmd
}

func classifyReadOnlyCommand(cmd ParsedCommand) bool {
	if len(cmd.Via) != 0 {
		return false
	}

	switch strings.ToLower(cmd.Name) {
	case "rg":
		return !containsArgOrPrefix(cmd.Args, "--pre", "--pre=")
	case "git":
		if cmd.GitCategory != "query" || !containsString(
			[]string{"status", "diff", "log", "show", "rev-parse"},
			cmd.GitSubcommand,
		) {
			return false
		}
		return !containsArgOrPrefix(
			cmd.Args,
			"-c",
			"--config-env",
			"--config-env=",
			"--ext-diff",
			"--textconv",
			"--output",
			"--output=",
		)
	case "get-content", "select-object":
		return true
	default:
		return false
	}
}

func containsArgOrPrefix(args []string, needles ...string) bool {
	for _, arg := range args {
		for _, needle := range needles {
			if strings.HasSuffix(needle, "=") {
				if strings.HasPrefix(arg, needle) {
					return true
				}
				continue
			}
			if arg == needle {
				return true
			}
		}
	}
	return false
}

// commandWrappers are programs that run another command given as their
// trailing arguments. An agent can hide a forbidden command behind one of
// these (e.g. "command git reset --hard", "env GIT_PAGER=cat git ...") so we
// unwrap them before identifying the real command.
var commandWrappers = map[string]bool{
	"command": true,
	"exec":    true,
	"builtin": true,
	"env":     true,
	"sudo":    true,
	"doas":    true,
	"nohup":   true,
	"nice":    true,
	"time":    true,
	"setsid":  true,
	"stdbuf":  true,
}

// wrappersWithAssignments additionally accept leading VAR=value environment
// assignments before the command (env, sudo, doas).
var wrappersWithAssignments = map[string]bool{
	"env":  true,
	"sudo": true,
	"doas": true,
}

// runWrappers are package/environment managers that execute another command via
// a "run" subcommand (e.g. "uv run python -c ...", "poetry run pytest"). Unlike
// commandWrappers, the inner command follows the literal "run" token, so these
// are only unwrapped when the wrapper's first non-flag argument is "run".
// Non-run subcommands (uv pip, uv venv, poetry add, ...) are left intact so the
// wrapper stays the command name.
var runWrappers = map[string]bool{
	"uv":     true,
	"poetry": true,
	"pdm":    true,
	"rye":    true,
	"pipenv": true,
}

// execWrappers directly execute their first non-flag argument as a command
// (e.g. "uvx ruff check", "npx tsc --noEmit"), with no "run" subcommand.
var execWrappers = map[string]bool{
	"uvx": true,
	"npx": true,
}

// uvValueFlags are the realistically common uv option flags that take a
// SEPARATE value token (space-separated "--flag value"). Shared by "uv" (both
// its global options and the "run" subcommand options) and by "uvx" (which also
// accepts --from). Listing --from here too is harmless for "uv run" — that
// subcommand never uses it, so it can't appear legitimately.
var uvValueFlags = map[string]bool{
	"--python":            true,
	"-p":                  true,
	"--with":              true,
	"--with-requirements": true,
	"--index":             true,
	"--index-url":         true,
	"--extra-index-url":   true,
	"--directory":         true,
	"--project":           true,
	"--config-file":       true,
	"--refresh-package":   true,
	"--resolution":        true,
	"--python-preference": true,
	"--from":              true,
}

// wrapperValueFlags maps a normalized wrapper name to the set of its known
// value-taking flags (the "--flag value" space-separated form). When advancing
// past flags to find the inner command, a flag in this set consumes the flag
// PLUS the following token, so the flag's VALUE is not mistaken for the inner
// command name (e.g. "uv run --python 3.11 python" resolves to python, not
// 3.11). "--flag=value" already consumes one token, and an unknown flag is
// treated as boolean. A wrapper absent from this map (nil set) has no known
// value flags and behaves exactly as before (all flags boolean).
//
// RESIDUAL (best-effort seal): an UNKNOWN value-taking flag in the space-
// separated form before the inner command can still mis-resolve to its value.
// This is no worse than before the seal for those unknown flags.
var wrapperValueFlags = map[string]map[string]bool{
	"uv":     uvValueFlags,
	"uvx":    uvValueFlags,
	"poetry": {"--directory": true, "-C": true, "--project": true},
	"pdm":    {"--directory": true, "-C": true, "--project": true, "-p": true},
	"rye":    {"--directory": true, "-C": true, "--project": true},
	"pipenv": {"--python": true},
	"npx":    {"--package": true, "-p": true, "--userconfig": true},
}

// normalizeInvocation unwraps command wrappers and strips the directory path
// and executable suffix from the command name, returning the real command
// name, its arguments, and the chain of wrappers that were unwrapped
// (outermost first). Bare commands pass through with an empty chain.
func normalizeInvocation(parts []string) (string, []string, []string) {
	parts, via := unwrapCommand(parts)
	if len(parts) == 0 {
		return "", nil, via
	}
	return normalizeBinaryName(parts[0]), parts[1:], via
}

// unwrapCommand strips leading wrapper programs (and their options / env
// assignments) so the slice begins with the real command, returning the
// remaining parts and the normalized names of the wrappers that were
// unwrapped, outermost first. It loops to handle nesting such as
// "sudo command git ...".
func unwrapCommand(parts []string) ([]string, []string) {
	var via []string
	for len(parts) > 1 {
		head := normalizeBinaryName(parts[0])
		switch {
		case commandWrappers[head]:
			allowAssign := wrappersWithAssignments[head]
			i := 1
			for i < len(parts) {
				tok := parts[i]
				if strings.HasPrefix(tok, "-") {
					i++
					continue
				}
				if allowAssign && isEnvAssignment(tok) {
					i++
					continue
				}
				break
			}
			if i >= len(parts) {
				// Wrapper with no real command after it; leave untouched.
				return parts, via
			}
			parts = parts[i:]
			via = append(via, head)
		case runWrappers[head]:
			// Only "<wrapper> run <cmd> ..." unwraps. Skip leading flags to the
			// first non-flag argument; it must be the "run" subcommand, else the
			// wrapper stays the command (uv pip, uv venv, poetry add, ...).
			valueFlags := wrapperValueFlags[head]
			i := skipFlags(parts, 1, valueFlags)
			if i >= len(parts) || parts[i] != "run" {
				return parts, via
			}
			// Advance past "run" and any run options to the inner command.
			i = skipFlags(parts, i+1, valueFlags)
			if i >= len(parts) {
				return parts, via
			}
			parts = parts[i:]
			via = append(via, head)
		case execWrappers[head]:
			// "<wrapper> <cmd> ...": the first non-flag argument is the command.
			i := skipFlags(parts, 1, wrapperValueFlags[head])
			if i >= len(parts) {
				return parts, via
			}
			parts = parts[i:]
			via = append(via, head)
		default:
			return parts, via
		}
	}
	return parts, via
}

// skipFlags returns the index of the first argument at or after start that does
// not begin with "-". If all remaining tokens are flags, it returns len(parts).
//
// valueFlags names the wrapper's known value-taking flags in the space-separated
// "--flag value" form: such a flag consumes the flag PLUS the following token, so
// the flag's VALUE is not mistaken for the inner command (e.g. "--python 3.11"
// consumes both, landing on the real command that follows). The "--flag=value"
// form already carries its value in one token, and an unknown flag is treated as
// boolean (one token). A nil valueFlags set means "no known value flags", which
// reproduces the original boolean-only behavior.
func skipFlags(parts []string, start int, valueFlags map[string]bool) int {
	i := start
	for i < len(parts) && strings.HasPrefix(parts[i], "-") {
		tok := parts[i]
		// A known value-taking flag in "--flag value" form (no '=') swallows the
		// next token as its value, provided one exists. If it is the last token,
		// fall through to boolean handling so the caller's bounds check trips and
		// the wrapper is left untouched.
		if valueFlags[tok] && !strings.ContainsRune(tok, '=') && i+1 < len(parts) {
			i += 2
			continue
		}
		i++
	}
	return i
}

// normalizeBinaryName reduces a command token to its base name without a
// directory path or Windows executable suffix: "/usr/bin/git" -> "git",
// "C:\\Program Files\\Git\\git.exe" -> "git".
func normalizeBinaryName(name string) string {
	if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
		name = name[idx+1:]
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		if strings.HasSuffix(lower, ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

// isEnvAssignment reports whether tok looks like NAME=value with a valid shell
// identifier on the left-hand side.
func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := tok[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func parseGitInvocation(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "":
			continue
		case arg == "-C" || arg == "-c" || arg == "--git-dir" || arg == "--work-tree" || arg == "--namespace":
			i++
			continue
		case strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--work-tree=") || strings.HasPrefix(arg, "--namespace="):
			continue
		case arg == "--no-pager" || arg == "--paginate" || arg == "-p":
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		default:
			return arg, args[i+1:]
		}
	}
	return "", nil
}

func classifyGitCommand(subcommand string, args []string) string {
	switch subcommand {
	case "":
		return ""
	case "status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "grep", "blame", "annotate",
		"remote", "fetch", "config", "symbolic-ref", "cat-file", "merge-base", "rev-list":
		return "query"
	case "add", "rm", "mv":
		return "stage"
	case "commit":
		return "commit"
	case "push":
		return "push"
	case "tag":
		return "tag"
	case "checkout":
		if containsString(args, "--") {
			return "restore"
		}
		return "switch"
	case "switch":
		return "switch"
	case "restore":
		return "restore"
	case "reset":
		return "history_rewrite"
	case "clean", "stash":
		return "workspace_destructive"
	case "rebase", "merge", "cherry-pick", "pull", "am":
		return "integrate"
	default:
		return "other"
	}
}

func containsString(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func gitPathspecs(subcommand string, args []string) []string {
	if len(args) == 0 {
		return nil
	}

	if idx := indexOfString(args, "--"); idx >= 0 {
		return collectPathspecs(args[idx+1:])
	}

	switch subcommand {
	case "add", "rm":
		return collectPathspecs(args)
	case "restore":
		return collectPathspecsSkippingOptionValues(args, map[string]bool{
			"--source":          true,
			"--worktree":        false,
			"--staged":          false,
			"--ours":            false,
			"--theirs":          false,
			"--patch":           false,
			"--ignore-unmerged": false,
		})
	default:
		return nil
	}
}

func collectPathspecs(args []string) []string {
	paths := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		paths = append(paths, NormalizePath(arg))
	}
	return uniquePaths(paths)
}

func collectPathspecsSkippingOptionValues(args []string, options map[string]bool) []string {
	paths := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if takesValue, ok := options[arg]; ok {
			if takesValue {
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--source=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		paths = append(paths, NormalizePath(arg))
	}
	return uniquePaths(paths)
}

func indexOfString(items []string, needle string) int {
	for i, item := range items {
		if item == needle {
			return i
		}
	}
	return -1
}

// wordToString converts a syntax.Word to a flat string representation.
// It concatenates literal parts and simple expansions but does NOT
// recurse into heredoc bodies or command substitutions.
func wordToString(word *syntax.Word) string {
	var sb strings.Builder
	for _, part := range word.Parts {
		writeWordPart(&sb, part)
	}
	return sb.String()
}

// writeWordPart writes the string representation of a single word part.
func writeWordPart(sb *strings.Builder, part syntax.WordPart) {
	switch p := part.(type) {
	case *syntax.Lit:
		sb.WriteString(p.Value)
	case *syntax.SglQuoted:
		sb.WriteString(p.Value)
	case *syntax.DblQuoted:
		for _, qp := range p.Parts {
			writeWordPart(sb, qp)
		}
	case *syntax.ParamExp:
		// $VAR or ${VAR} — write the variable name as placeholder
		sb.WriteString("$")
		if p.Param != nil {
			sb.WriteString(p.Param.Value)
		}
	case *syntax.CmdSubst:
		// $(command) — write as opaque token, don't recurse
		sb.WriteString("$(…)")
	case *syntax.ProcSubst:
		sb.WriteString("<(…)")
	case *syntax.ArithmExp:
		sb.WriteString("$((…))")
	default:
		// Unknown part type — skip rather than crash
	}
}
