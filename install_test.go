package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	captainhook "github.com/ctoth/captain-hook"
)

func TestWardHookSpecsIncludeActorAndFamilyLifecycleCleanup(t *testing.T) {
	specs := wardHookSpecs()
	want := map[string]string{
		"PreToolUse":    " eval",
		"SubagentStart": " start-actor",
		"SubagentStop":  " end-actor",
		"SessionEnd":    " end-session",
	}
	seen := make(map[string]int)
	for _, spec := range specs {
		suffix, ok := want[spec.Event]
		if !ok {
			continue
		}
		seen[spec.Event]++
		if !strings.HasSuffix(spec.Command, suffix) {
			t.Errorf("%s command = %q, want suffix %q", spec.Event, spec.Command, suffix)
		}
	}
	for event := range want {
		if seen[event] != 1 {
			t.Errorf("%s installed %d times, want once", event, seen[event])
		}
	}
}

func TestWardHookInstallIsIdempotentAndPreservesUnrelatedHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".claude", "settings.json")
	settings := captainhook.SettingsMap{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": "Read",
					"hooks": []interface{}{
						map[string]interface{}{"type": "command", "command": "other-tool check"},
					},
				},
			},
		},
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installWardHooks(path); err != nil {
		t.Fatal(err)
	}
	if err := installWardHooks(path); err != nil {
		t.Fatal(err)
	}

	installed, err := captainhook.ReadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := (*installed)["hooks"].(map[string]interface{})
	preToolGroups := hooks["PreToolUse"].([]interface{})
	if len(preToolGroups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want unrelated + ward: %#v", len(preToolGroups), preToolGroups)
	}
	unrelated := preToolGroups[0].(map[string]interface{})
	unrelatedEntry := unrelated["hooks"].([]interface{})[0].(map[string]interface{})
	if unrelatedEntry["command"] != "other-tool check" {
		t.Fatalf("unrelated hook changed: %#v", unrelatedEntry)
	}
	for _, event := range []string{"SubagentStart", "SubagentStop", "SessionEnd"} {
		groups, ok := hooks[event].([]interface{})
		if !ok || len(groups) != 1 {
			t.Fatalf("%s groups = %#v, want one", event, hooks[event])
		}
	}
}
