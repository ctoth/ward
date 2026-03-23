package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParsedCommand represents a single command extracted from a shell AST.
type ParsedCommand struct {
	Name string   // the command name (first word)
	Args []string // the arguments (everything after the command name)
	Full string   // reconstructed "name arg1 arg2 ..." without heredoc bodies
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
		// Fallback: treat the whole string as one command
		parts := strings.Fields(cmdStr)
		name := cmdStr
		if len(parts) > 0 {
			name = parts[0]
		}
		return []ParsedCommand{{
			Name: name,
			Full: cmdStr,
		}}
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

		cmd := ParsedCommand{
			Name: parts[0],
			Full: strings.Join(parts, " "),
		}
		if len(parts) > 1 {
			cmd.Args = parts[1:]
		}
		commands = append(commands, cmd)

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
	case *syntax.ArithExp:
		sb.WriteString("$((…))")
	default:
		// Unknown part type — skip rather than crash
	}
}
