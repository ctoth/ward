package main

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuiltinRuleOverrideMessagesDoNotMintTheirOwnAuthority(t *testing.T) {
	const authorityBoundary = "Only after the user or controlling workflow authorizes this exact exception, record it with: ward allow"
	found := 0
	err := fs.WalkDir(builtinProfilesFS, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(builtinProfilesFS, path)
		if err != nil {
			return err
		}
		text := string(data)
		if !strings.Contains(text, "ward allow") {
			return nil
		}
		found++
		if !strings.Contains(text, authorityBoundary) {
			t.Errorf("%s presents ward allow without the authority boundary", path)
		}
		if strings.Contains(text, "Run: ward allow") {
			t.Errorf("%s tells the actor to mint its own override", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("expected built-in rules with ward allow overrides")
	}
}

func TestBuiltinProfileNames(t *testing.T) {
	names, err := builtinProfileNames()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"core-safety", "git-discipline", "python", "windows"} {
		if !slices.Contains(names, required) {
			t.Fatalf("expected builtin profile %s in %v", required, names)
		}
	}
}

func TestResolveInstalledProfilesOrdersDependencies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	installBuiltinProfileForTest(t, "git-discipline")
	installBuiltinProfileForTest(t, "core-safety")

	profiles, err := resolveInstalledProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	if profiles[0].Name != "core-safety" || profiles[1].Name != "git-discipline" {
		t.Fatalf("unexpected profile order: %s, %s", profiles[0].Name, profiles[1].Name)
	}
}

func TestResolveConfigIncludesInstalledProfiles(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	installBuiltinProfileForTest(t, "core-safety")
	installBuiltinProfileForTest(t, "git-discipline")

	config, err := resolveConfig(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Profiles) != 2 {
		t.Fatalf("expected 2 resolved profiles, got %d", len(config.Profiles))
	}
	if len(config.Rules) == 0 || len(config.guardRules) == 0 {
		t.Fatal("expected resolved rules from installed profiles")
	}
	if config.ConfigHash == "" {
		t.Fatal("expected config hash")
	}
}

func TestResolveConfigJSONRoundTrip(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	installBuiltinProfileForTest(t, "core-safety")
	config, err := resolveConfig(cwd)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["config_hash"] == "" {
		t.Fatal("expected config_hash in JSON")
	}
}

func installBuiltinProfileForTest(t *testing.T, name string) {
	t.Helper()
	profile, err := loadBuiltinProfile(name)
	if err != nil {
		t.Fatal(err)
	}
	target := profilePath(profile.Name)
	if err := copyFSDir(builtinProfilesFS, profile.Root, target); err != nil {
		t.Fatal(err)
	}
	registry, err := loadInstalledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	registry.upsert(InstalledProfile{
		Name:        profile.Name,
		Version:     profile.Manifest.Version,
		Source:      "builtin:" + profile.Name,
		InstalledAt: time.Now(),
		Builtin:     true,
	})
	if err := saveInstalledRegistry(registry); err != nil {
		t.Fatal(err)
	}
}
