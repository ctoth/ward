package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	captainhook "github.com/ctoth/captain-hook"
)

var wardIdentity = captainhook.CommandIdentity("ward", "ward.exe", filepath.Base(wardExePath()))

func wardHookSpecs() []captainhook.HookSpec {
	exe := wardExePath()
	return []captainhook.HookSpec{
		{
			Event:   "PreToolUse",
			Matcher: "Bash|Edit|Write|WebFetch",
			Command: exe + " eval",
			Timeout: 5,
		},
		{
			Event:   "SubagentStart",
			Command: exe + " start-actor",
		},
		{
			Event:   "SubagentStop",
			Command: exe + " end-actor",
		},
		{
			Event:   "SessionEnd",
			Command: exe + " end-session",
		},
	}
}

func wardExePath() string {
	// Try to find ward on PATH first
	if p, err := exec.LookPath("ward"); err == nil {
		abs, err := filepath.Abs(p)
		if err == nil {
			return filepath.ToSlash(abs)
		}
		return filepath.ToSlash(p)
	}
	// Fall back to current executable
	if p, err := os.Executable(); err == nil {
		return filepath.ToSlash(p)
	}
	return "ward"
}

func cmdInstall() {
	path, err := captainhook.FindSettingsPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: find settings: %v\n", err)
		os.Exit(1)
	}

	if err := installWardHooks(path); err != nil {
		fmt.Fprintf(os.Stderr, "ward: install hooks: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ward: installed hooks to %s\n", path)
	for _, spec := range wardHookSpecs() {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", spec.Event, spec.Command)
	}
}

func installWardHooks(path string) error {
	settings, err := captainhook.ReadSettings(path)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	if err := captainhook.Install(settings, wardHookSpecs(), wardIdentity); err != nil {
		return err
	}
	if err := captainhook.WriteSettings(path, settings); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	return nil
}

func cmdUninstall() {
	path, err := captainhook.FindSettingsPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: find settings: %v\n", err)
		os.Exit(1)
	}

	settings, err := captainhook.ReadSettings(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: read settings: %v\n", err)
		os.Exit(1)
	}

	captainhook.Uninstall(settings, wardIdentity)

	if err := captainhook.WriteSettings(path, settings); err != nil {
		fmt.Fprintf(os.Stderr, "ward: write settings: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ward: uninstalled hooks from %s\n", path)
}
