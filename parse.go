package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParsedCommand represents a single command extracted from a shell AST.
type ParsedCommand struct {
	Name          string   // the command name (first word)
	Args          []string // the arguments (everything after the command name)
	Full          string   // reconstructed "name arg1 arg2 ..." without heredoc bodies
	GitSubcommand string   // parsed git subcommand (e.g. "checkout")
	GitArgs       []string
	GitCategory   string   // query, stage, commit, switch, restore, integrate, push, tag, history_rewrite, workspace_destructive
	GitPaths      []string // repo-relative path operands, when syntactically recoverable
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
		name, fallbackArgs := normalizeInvocation(parts)
		cmd := ParsedCommand{
			Name: name,
			Args: fallbackArgs,
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

		name, cmdArgs := normalizeInvocation(parts)
		// Full is reconstructed from the normalized invocation so that
		// rules matching on the leading token (e.g. "^git", "^python")
		// see through directory paths, .exe suffixes, and command wrappers.
		fullParts := append([]string{name}, cmdArgs...)
		cmd := ParsedCommand{
			Name: name,
			Args: cmdArgs,
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

	return commands
}

func annotateParsedCommand(cmd ParsedCommand) ParsedCommand {
	if cmd.Name != "git" {
		return cmd
	}
	subcommand, gitArgs := parseGitInvocation(cmd.Args)
	cmd.GitSubcommand = subcommand
	cmd.GitArgs = gitArgs
	cmd.GitCategory = classifyGitCommand(subcommand, gitArgs)
	cmd.GitPaths = gitPathspecs(subcommand, gitArgs)
	return cmd
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

// normalizeInvocation unwraps command wrappers and strips the directory path
// and executable suffix from the command name, returning the real command name
// and its arguments. Bare commands pass through unchanged.
func normalizeInvocation(parts []string) (string, []string) {
	parts = unwrapCommand(parts)
	if len(parts) == 0 {
		return "", nil
	}
	return normalizeBinaryName(parts[0]), parts[1:]
}

// unwrapCommand strips leading wrapper programs (and their options / env
// assignments) so the slice begins with the real command. It loops to handle
// nesting such as "sudo command git ...".
func unwrapCommand(parts []string) []string {
	for len(parts) > 1 {
		head := normalizeBinaryName(parts[0])
		if !commandWrappers[head] {
			return parts
		}
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
			return parts
		}
		parts = parts[i:]
	}
	return parts
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
