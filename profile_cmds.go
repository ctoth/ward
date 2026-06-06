package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdInstallDefaults() {
	names := selectedBuiltinProfiles(os.Args[2:])
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "ward: specify --profile <name>[,<name>...] or --all")
		os.Exit(1)
	}
	registry, err := loadInstalledRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load registry: %v\n", err)
		os.Exit(1)
	}
	for _, name := range names {
		profile, err := loadBuiltinProfile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ward: load builtin profile %s: %v\n", name, err)
			os.Exit(1)
		}
		target := profilePath(profile.Name)
		_ = os.RemoveAll(target)
		if err := copyFSDir(builtinProfilesFS, profile.Root, target); err != nil {
			fmt.Fprintf(os.Stderr, "ward: install profile %s: %v\n", name, err)
			os.Exit(1)
		}
		registry.upsert(InstalledProfile{
			Name:        profile.Name,
			Version:     profile.Manifest.Version,
			Source:      "builtin:" + profile.Name,
			InstalledAt: time.Now(),
			Builtin:     true,
		})
		fmt.Fprintf(os.Stderr, "ward: installed builtin profile %s\n", profile.Name)
	}
	if err := saveInstalledRegistry(registry); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save registry: %v\n", err)
		os.Exit(1)
	}
}

func cmdInstallProfile() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward install-profile <source> [--ref <git-ref>] [--subdir <path>]")
		os.Exit(1)
	}
	source := os.Args[2]
	ref, _ := stringFlagValue(os.Args[3:], "--ref")
	subdir, _ := stringFlagValue(os.Args[3:], "--subdir")
	profile, installed, err := materializeProfileInstall(source, ref, subdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: install-profile: %v\n", err)
		os.Exit(1)
	}
	registry, err := loadInstalledRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load registry: %v\n", err)
		os.Exit(1)
	}
	registry.upsert(installed)
	if err := saveInstalledRegistry(registry); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save registry: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: installed profile %s from %s\n", profile.Name, installed.Source)
}

func cmdUpdateProfile() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward update-profile <name>")
		os.Exit(1)
	}
	name := os.Args[2]
	registry, err := loadInstalledRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load registry: %v\n", err)
		os.Exit(1)
	}
	entry := registry.get(name)
	if entry == nil {
		fmt.Fprintf(os.Stderr, "ward: profile %s is not installed\n", name)
		os.Exit(1)
	}
	if entry.Builtin {
		os.Args = []string{os.Args[0], "install-defaults", "--profile", entry.Name}
		cmdInstallDefaults()
		return
	}
	_, installed, err := materializeProfileInstall(entry.Source, entry.Ref, entry.Subdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: update-profile: %v\n", err)
		os.Exit(1)
	}
	registry.upsert(installed)
	if err := saveInstalledRegistry(registry); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save registry: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ward: updated profile %s\n", name)
}

func cmdRemoveProfile() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward remove-profile <name>")
		os.Exit(1)
	}
	name := os.Args[2]
	registry, err := loadInstalledRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load registry: %v\n", err)
		os.Exit(1)
	}
	registry.remove(name)
	if err := saveInstalledRegistry(registry); err != nil {
		fmt.Fprintf(os.Stderr, "ward: save registry: %v\n", err)
		os.Exit(1)
	}
	_ = os.RemoveAll(profilePath(name))
	fmt.Fprintf(os.Stderr, "ward: removed profile %s\n", name)
}

func cmdListProfiles() {
	registry, err := loadInstalledRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: load registry: %v\n", err)
		os.Exit(1)
	}
	if hasJSONFlag(os.Args[2:]) {
		data, err := json.MarshalIndent(registry.Profiles, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ward: marshal profiles: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}
	if len(registry.Profiles) == 0 {
		fmt.Println("no installed profiles")
		return
	}
	for _, profile := range registry.Profiles {
		fmt.Printf("%s\t%s\t%s\n", profile.Name, profile.Version, profile.Source)
	}
}

func cmdResolveConfig() {
	config, err := resolveConfig(mustGetwd())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: resolve-config: %v\n", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: marshal config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func cmdValidateProfile() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ward validate-profile <path> [--subdir <path>]")
		os.Exit(1)
	}
	source := os.Args[2]
	subdir, _ := stringFlagValue(os.Args[3:], "--subdir")
	profileDir, cleanup, err := resolveProfileSource(source, "", subdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	profile, err := loadProfileFromDir(profileDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile: %v\n", err)
		os.Exit(1)
	}
	if _, err := loadRulesGeneric(filepath.Join(profile.Root, "rules")); err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile rules: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := loadFactsGeneric(filepath.Join(profile.Root, "facts")); err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile facts: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := loadSignalsGeneric(filepath.Join(profile.Root, "signals")); err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile signals: %v\n", err)
		os.Exit(1)
	}
	rules, err := loadRulesGeneric(filepath.Join(profile.Root, "rules"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: validate-profile rules: %v\n", err)
		os.Exit(1)
	}
	for _, rule := range rules {
		if err := CompileRule(&rule); err != nil {
			fmt.Fprintf(os.Stderr, "ward: validate-profile compile: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "ward: profile %s is valid\n", profile.Name)
}

func materializeProfileInstall(source, ref, subdir string) (*ProfileBundle, InstalledProfile, error) {
	profileDir, cleanup, err := resolveProfileSource(source, ref, subdir)
	if err != nil {
		return nil, InstalledProfile{}, err
	}
	defer cleanup()

	profile, err := loadProfileFromDir(profileDir)
	if err != nil {
		return nil, InstalledProfile{}, err
	}
	target := profilePath(profile.Name)
	_ = os.RemoveAll(target)
	if err := copyLocalDir(profileDir, target); err != nil {
		return nil, InstalledProfile{}, err
	}
	installed := InstalledProfile{
		Name:        profile.Name,
		Version:     profile.Manifest.Version,
		Source:      source,
		Subdir:      subdir,
		Ref:         ref,
		InstalledAt: time.Now(),
		Builtin:     false,
	}
	return profile, installed, nil
}

func resolveProfileSource(source, ref, subdir string) (string, func(), error) {
	cleanup := func() {}
	if info, err := os.Stat(source); err == nil && info.IsDir() {
		root := source
		if subdir != "" {
			root = filepath.Join(root, subdir)
		}
		return root, cleanup, nil
	}

	if !isGitLikeSource(source) {
		return "", cleanup, fmt.Errorf("source %q is neither a local directory nor a git source", source)
	}
	cloneDir, _, err := cloneProfileSource(source, ref)
	if err != nil {
		return "", cleanup, err
	}
	cleanup = func() { _ = os.RemoveAll(cloneDir) }
	root := cloneDir
	if subdir != "" {
		root = filepath.Join(root, subdir)
	}
	return root, cleanup, nil
}

func selectedBuiltinProfiles(args []string) []string {
	if boolFlag(args, "--all") {
		names, _ := builtinProfileNames()
		return names
	}
	values := multiFlagValues(args, "--profile")
	selected := make([]string, 0, len(values))
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				selected = append(selected, name)
			}
		}
	}
	return uniqueStrings(selected)
}

func stringFlagValue(args []string, name string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == name && i+1 < len(args) {
			return args[i+1], true
		}
		prefix := name + "="
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix), true
		}
	}
	return "", false
}

func multiFlagValues(args []string, name string) []string {
	values := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == name && i+1 < len(args) {
			values = append(values, args[i+1])
			i++
			continue
		}
		prefix := name + "="
		if strings.HasPrefix(arg, prefix) {
			values = append(values, strings.TrimPrefix(arg, prefix))
		}
	}
	return values
}

func boolFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func hasJSONFlag(args []string) bool {
	return boolFlag(args, "--json")
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func isGitLikeSource(source string) bool {
	return strings.Contains(source, "://") || strings.HasSuffix(source, ".git") || strings.Count(source, "/") == 1
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ward: getwd: %v\n", err)
		os.Exit(1)
	}
	return wd
}
