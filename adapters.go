package main

import (
	"encoding/json"
	"fmt"
)

// AgentType identifies which AI coding agent sent the hook event.
type AgentType int

const (
	AgentClaude AgentType = iota
	AgentGemini
	AgentCodex
)

func (a AgentType) String() string {
	switch a {
	case AgentClaude:
		return "claude"
	case AgentGemini:
		return "gemini"
	case AgentCodex:
		return "codex"
	default:
		return "unknown"
	}
}

// ToolEvent is the normalized representation of a tool call from any agent.
type ToolEvent struct {
	Tool      string         // "Bash", "Edit", "Write", "Read", etc.
	Input     map[string]any // tool-specific input
	SessionID string
	EventType string // "pre_tool", "post_tool"
	CWD       string
}

// DetectAndParse auto-detects which agent sent the JSON and parses it.
func DetectAndParse(data []byte) (ToolEvent, AgentType, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return ToolEvent{}, 0, fmt.Errorf("invalid JSON: %w", err)
	}

	var event ToolEvent
	var agent AgentType
	var err error

	// Codex: has nested hook_event.event_type
	if hookEvent, ok := raw["hook_event"].(map[string]any); ok {
		if _, hasEventType := hookEvent["event_type"]; hasEventType {
			event, agent, err = parseCodex(raw, hookEvent)
			if err != nil {
				return event, agent, err
			}
			enrichBashCommands(&event)
			return event, agent, nil
		}
	}

	// Claude vs Gemini: both have hook_event_name, but different values
	if eventName, ok := raw["hook_event_name"].(string); ok {
		switch eventName {
		case "PreToolUse", "PostToolUse", "PostToolUseFailure":
			event, agent, err = parseClaude(raw, eventName)
		case "BeforeTool", "AfterTool":
			event, agent, err = parseGemini(raw, eventName)
		}
		if err != nil {
			return event, agent, err
		}
		if event.Tool != "" {
			enrichBashCommands(&event)
			return event, agent, nil
		}
	}

	return ToolEvent{}, 0, fmt.Errorf("cannot detect agent from JSON (no hook_event_name or hook_event.event_type)")
}

// enrichBashCommands adds parsed shell commands to Bash tool events.
// input.commands is a list of maps with "name" and "full" keys.
func enrichBashCommands(event *ToolEvent) {
	if event.Tool != "Bash" && event.Tool != "local_shell" {
		return
	}
	cmd, ok := event.Input["command"].(string)
	if !ok || cmd == "" {
		return
	}
	parsed := ParseCommands(cmd)
	commands := make([]any, len(parsed))
	for i, p := range parsed {
		commands[i] = map[string]any{
			"name": p.Name,
			"full": p.Full,
		}
	}
	event.Input["commands"] = commands
}

func parseClaude(raw map[string]any, eventName string) (ToolEvent, AgentType, error) {
	event := ToolEvent{
		SessionID: strField(raw, "session_id"),
		CWD:       strField(raw, "cwd"),
	}

	event.Tool = strField(raw, "tool_name")
	if input, ok := raw["tool_input"].(map[string]any); ok {
		event.Input = input
	} else {
		event.Input = make(map[string]any)
	}

	switch eventName {
	case "PreToolUse":
		event.EventType = "pre_tool"
	default:
		event.EventType = "post_tool"
	}

	return event, AgentClaude, nil
}

func parseGemini(raw map[string]any, eventName string) (ToolEvent, AgentType, error) {
	event := ToolEvent{
		SessionID: strField(raw, "session_id"),
		CWD:       strField(raw, "cwd"),
	}

	event.Tool = strField(raw, "tool_name")
	if input, ok := raw["tool_input"].(map[string]any); ok {
		event.Input = input
	} else {
		event.Input = make(map[string]any)
	}

	switch eventName {
	case "BeforeTool":
		event.EventType = "pre_tool"
	default:
		event.EventType = "post_tool"
	}

	return event, AgentGemini, nil
}

func parseCodex(raw map[string]any, hookEvent map[string]any) (ToolEvent, AgentType, error) {
	event := ToolEvent{
		SessionID: strField(raw, "session_id"),
		CWD:       strField(raw, "cwd"),
		EventType: "post_tool", // Codex only has after-events
	}

	event.Tool = strField(hookEvent, "tool_name")

	// Codex tool_input is nested differently depending on tool_kind
	if toolInput, ok := hookEvent["tool_input"].(map[string]any); ok {
		// Flatten the input for uniform access
		event.Input = make(map[string]any)
		if params, ok := toolInput["params"].(map[string]any); ok {
			// LocalShell: params.command is []string, join for regex matching
			if cmdSlice, ok := params["command"].([]any); ok {
				parts := make([]string, 0, len(cmdSlice))
				for _, p := range cmdSlice {
					if s, ok := p.(string); ok {
						parts = append(parts, s)
					}
				}
				event.Input["command"] = joinStrings(parts)
			}
			for k, v := range params {
				if k != "command" {
					event.Input[k] = v
				}
			}
		} else {
			// Function or Custom: has "arguments" or "input" directly
			for k, v := range toolInput {
				event.Input[k] = v
			}
		}
	} else {
		event.Input = make(map[string]any)
	}

	return event, AgentCodex, nil
}

// FormatResponse converts a Result into agent-specific hook response JSON.
func FormatResponse(agent AgentType, result *Result) map[string]any {
	switch agent {
	case AgentClaude:
		return formatClaude(result)
	case AgentGemini:
		return formatGemini(result)
	case AgentCodex:
		return nil // Codex has no response mechanism
	default:
		return nil
	}
}

func formatClaude(r *Result) map[string]any {
	switch r.Action {
	case "deny":
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":           "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": r.Message,
			},
		}
	case "context":
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":    "PreToolUse",
				"additionalContext": r.Message,
			},
		}
	case "allow":
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":      "PreToolUse",
				"permissionDecision": "allow",
			},
		}
	default:
		return nil
	}
}

func formatGemini(r *Result) map[string]any {
	switch r.Action {
	case "deny":
		return map[string]any{
			"decision": "deny",
			"reason":   r.Message,
		}
	case "context":
		return map[string]any{
			"systemMessage": r.Message,
		}
	case "allow":
		return map[string]any{
			"decision": "allow",
		}
	default:
		return nil
	}
}

// Helpers

func strField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func joinStrings(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}
