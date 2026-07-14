package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	captainhook "github.com/ctoth/captain-hook"
)

var wardIdentity = captainhook.CommandIdentity("ward", "ward.exe", filepath.Base(wardExePath()))

func wardHookSpecs(host string) []captainhook.HookSpec {
	exe := wardExePath()
	specs := []captainhook.HookSpec{
		{
			Event:   "PreToolUse",
			Matcher: "*",
			Command: exe,
			Args:    []string{"eval"},
			Timeout: 5,
		},
		{
			Event:   "PostToolUse",
			Matcher: "*",
			Command: exe,
			Args:    []string{"eval"},
			Timeout: 5,
		},
		{
			Event:   "SubagentStart",
			Command: exe,
			Args:    []string{"start-actor"},
		},
		{
			Event:   "SubagentStop",
			Command: exe,
			Args:    []string{"end-actor"},
		},
	}
	if host == "claude" {
		specs = append(specs,
			captainhook.HookSpec{
				Event:   "PostToolUseFailure",
				Matcher: "*",
				Command: exe,
				Args:    []string{"eval"},
				Timeout: 5,
			},
			captainhook.HookSpec{
				Event:   "SessionEnd",
				Command: exe,
				Args:    []string{"end-session"},
			},
		)
	}
	if host == "codex" {
		for i := range specs {
			command := strconv.Quote(exe) + " " + specs[i].Args[0]
			specs[i].Command = command
			specs[i].CommandWindows = command
			specs[i].Args = nil
		}
	}
	return specs
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
	path, host, err := wardSettingsPath(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: find settings: %v\n", err)
		os.Exit(1)
	}

	if err := installWardHooks(path, host); err != nil {
		fmt.Fprintf(os.Stderr, "ward: install hooks: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ward: installed hooks to %s\n", path)
	for _, spec := range wardHookSpecs(host) {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", spec.Event, spec.Command)
	}
	if host == "codex" {
		fmt.Fprintln(os.Stderr, "ward: approve the new hooks during Codex's next interactive startup")
		fmt.Fprintln(os.Stderr, "ward: non-interactive Codex runs require previously trusted hooks or --dangerously-bypass-hook-trust")
	}
}

func wardSettingsPath(args []string) (string, string, error) {
	if len(args) == 0 || len(args) == 1 && args[0] == "claude" {
		path, err := captainhook.FindSettingsPath()
		return path, "claude", err
	}
	if len(args) == 1 && args[0] == "codex" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
		return filepath.Join(home, ".codex", "hooks.json"), "codex", nil
	}
	return "", "", fmt.Errorf("usage: ward %s [claude|codex]", os.Args[1])
}

func installWardHooks(path, host string) error {
	settings, err := captainhook.ReadSettings(path)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	captainhook.Uninstall(settings, wardIdentity)
	if err := captainhook.Install(settings, wardHookSpecs(host), wardIdentity); err != nil {
		return err
	}
	if err := captainhook.WriteSettings(path, settings); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	return nil
}

func cmdUninstall() {
	path, _, err := wardSettingsPath(os.Args[2:])
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
