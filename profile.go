package main

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed builtin_profiles/**
var builtinProfilesFS embed.FS

type ProfileManifest struct {
	Name           string         `yaml:"name" json:"name"`
	Version        string         `yaml:"version" json:"version"`
	WardMinVersion string         `yaml:"ward_min_version,omitempty" json:"ward_min_version,omitempty"`
	Description    string         `yaml:"description,omitempty" json:"description,omitempty"`
	Requires       []string       `yaml:"requires,omitempty" json:"requires,omitempty"`
	Conflicts      []string       `yaml:"conflicts,omitempty" json:"conflicts,omitempty"`
	Exports        ProfileExports `yaml:"exports,omitempty" json:"exports,omitempty"`
	Blocks         ProfileBlocks  `yaml:"blocks,omitempty" json:"blocks,omitempty"`
	Tests          ProfileTests   `yaml:"tests,omitempty" json:"tests,omitempty"`
}

type ProfileExports struct {
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type ProfileBlocks struct {
	Operations []string `yaml:"operations,omitempty" json:"operations,omitempty"`
}

type ProfileTests struct {
	Suites             []string `yaml:"suites,omitempty" json:"suites,omitempty"`
	ComposeWith        []string `yaml:"compose_with,omitempty" json:"compose_with,omitempty"`
	ComposeBlockedWith []string `yaml:"compose_blocked_with,omitempty" json:"compose_blocked_with,omitempty"`
}

type InstalledProfile struct {
	Name        string    `yaml:"name" json:"name"`
	Version     string    `yaml:"version" json:"version"`
	Source      string    `yaml:"source" json:"source"`
	Subdir      string    `yaml:"subdir,omitempty" json:"subdir,omitempty"`
	Ref         string    `yaml:"ref,omitempty" json:"ref,omitempty"`
	Revision    string    `yaml:"revision,omitempty" json:"revision,omitempty"`
	InstalledAt time.Time `yaml:"installed_at" json:"installed_at"`
	Builtin     bool      `yaml:"builtin" json:"builtin"`
}

type InstalledProfileRegistry struct {
	Profiles []InstalledProfile `yaml:"profiles" json:"profiles"`
}

type ProfileBundle struct {
	Manifest  ProfileManifest
	Name      string
	Root      string
	Source    string
	Builtin   bool
	Installed *InstalledProfile
}

type ResolvedRule struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Action  string `json:"action"`
	Message string `json:"message"`
	Scope   string `json:"scope,omitempty"`
	When    string `json:"when"`
}

type ResolvedFact struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Type   string `json:"type,omitempty"`
}

type ResolvedSignal struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	OneTimeUse *bool  `json:"one_time_use,omitempty"`
}

type ResolvedProfile struct {
	Name      string            `json:"name"`
	Root      string            `json:"root"`
	Source    string            `json:"source"`
	Builtin   bool              `json:"builtin"`
	Manifest  ProfileManifest   `json:"manifest"`
	Installed *InstalledProfile `json:"installed,omitempty"`
}

type ResolvedConfig struct {
	Profiles   []ResolvedProfile `json:"profiles"`
	Rules      []ResolvedRule    `json:"rules"`
	Facts      []ResolvedFact    `json:"facts"`
	Signals    []ResolvedSignal  `json:"signals"`
	LoadOrder  []string          `json:"load_order"`
	ConfigHash string            `json:"config_hash"`

	guardRules   []Rule
	guardFacts   map[string]Fact
	signalDefs   map[string]SignalDef
	signalSearch []string
}

func wardHomeDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ward")
}

func profilesRootDir() string {
	return filepath.Join(wardHomeDir(), "profiles")
}

func installedRegistryPath() string {
	return filepath.Join(profilesRootDir(), "installed.yaml")
}

func profilePath(name string) string {
	return filepath.Join(profilesRootDir(), name)
}

func loadInstalledRegistry() (*InstalledProfileRegistry, error) {
	data, err := os.ReadFile(installedRegistryPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &InstalledProfileRegistry{}, nil
		}
		return nil, err
	}
	var registry InstalledProfileRegistry
	if err := yaml.Unmarshal(data, &registry); err != nil {
		return nil, err
	}
	return &registry, nil
}

func saveInstalledRegistry(registry *InstalledProfileRegistry) error {
	if err := os.MkdirAll(profilesRootDir(), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(registry)
	if err != nil {
		return err
	}
	return os.WriteFile(installedRegistryPath(), data, 0o644)
}

func (r *InstalledProfileRegistry) upsert(profile InstalledProfile) {
	for i, existing := range r.Profiles {
		if existing.Name == profile.Name {
			r.Profiles[i] = profile
			return
		}
	}
	r.Profiles = append(r.Profiles, profile)
	slices.SortFunc(r.Profiles, func(a, b InstalledProfile) int {
		return strings.Compare(a.Name, b.Name)
	})
}

func (r *InstalledProfileRegistry) remove(name string) {
	filtered := r.Profiles[:0]
	for _, profile := range r.Profiles {
		if profile.Name != name {
			filtered = append(filtered, profile)
		}
	}
	r.Profiles = filtered
}

func (r *InstalledProfileRegistry) get(name string) *InstalledProfile {
	for i := range r.Profiles {
		if r.Profiles[i].Name == name {
			return &r.Profiles[i]
		}
	}
	return nil
}

func builtinProfileNames() ([]string, error) {
	entries, err := fs.ReadDir(builtinProfilesFS, "builtin_profiles")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

func loadBuiltinProfile(name string) (*ProfileBundle, error) {
	root := filepath.ToSlash(filepath.Join("builtin_profiles", name))
	data, err := builtinProfilesFS.ReadFile(root + "/profile.yaml")
	if err != nil {
		return nil, err
	}
	var manifest ProfileManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	if err := validateManifest(manifest, root); err != nil {
		return nil, err
	}
	return &ProfileBundle{
		Manifest: manifest,
		Name:     manifest.Name,
		Root:     root,
		Source:   "builtin:" + manifest.Name,
		Builtin:  true,
	}, nil
}

func loadProfileFromDir(dir string) (*ProfileBundle, error) {
	data, err := os.ReadFile(filepath.Join(dir, "profile.yaml"))
	if err != nil {
		return nil, err
	}
	var manifest ProfileManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	if err := validateManifest(manifest, dir); err != nil {
		return nil, err
	}
	return &ProfileBundle{
		Manifest: manifest,
		Name:     manifest.Name,
		Root:     dir,
		Source:   dir,
	}, nil
}

func validateManifest(manifest ProfileManifest, source string) error {
	if manifest.Name == "" {
		return fmt.Errorf("%s: missing profile name", source)
	}
	if manifest.Version == "" {
		return fmt.Errorf("%s: missing profile version", source)
	}
	return nil
}

func resolveInstalledProfiles() ([]ProfileBundle, error) {
	registry, err := loadInstalledRegistry()
	if err != nil {
		return nil, err
	}
	profiles := make([]ProfileBundle, 0, len(registry.Profiles))
	for _, entry := range registry.Profiles {
		bundle, err := loadProfileFromDir(profilePath(entry.Name))
		if err != nil {
			return nil, fmt.Errorf("load installed profile %s: %w", entry.Name, err)
		}
		bundle.Source = entry.Source
		bundle.Builtin = entry.Builtin
		entryCopy := entry
		bundle.Installed = &entryCopy
		profiles = append(profiles, *bundle)
	}
	return orderProfiles(profiles)
}

func orderProfiles(profiles []ProfileBundle) ([]ProfileBundle, error) {
	byName := make(map[string]ProfileBundle, len(profiles))
	for _, profile := range profiles {
		byName[profile.Name] = profile
	}

	seen := make(map[string]bool)
	active := make(map[string]bool)
	ordered := make([]ProfileBundle, 0, len(profiles))

	var visit func(string) error
	visit = func(name string) error {
		if seen[name] {
			return nil
		}
		if active[name] {
			return fmt.Errorf("profile dependency cycle at %s", name)
		}
		profile, ok := byName[name]
		if !ok {
			return fmt.Errorf("missing required profile %s", name)
		}
		active[name] = true
		for _, req := range profile.Manifest.Requires {
			if _, ok := byName[req]; !ok {
				return fmt.Errorf("profile %s requires missing profile %s", name, req)
			}
			if err := visit(req); err != nil {
				return err
			}
		}
		for _, conflict := range profile.Manifest.Conflicts {
			if _, ok := byName[conflict]; ok {
				return fmt.Errorf("profile %s conflicts with installed profile %s", name, conflict)
			}
		}
		active[name] = false
		seen[name] = true
		ordered = append(ordered, profile)
		return nil
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func resolveConfig(cwd string) (*ResolvedConfig, error) {
	profiles, err := resolveInstalledProfiles()
	if err != nil {
		return nil, err
	}

	config := &ResolvedConfig{
		Profiles:   make([]ResolvedProfile, 0, len(profiles)),
		Rules:      []ResolvedRule{},
		Facts:      []ResolvedFact{},
		Signals:    []ResolvedSignal{},
		LoadOrder:  []string{},
		guardFacts: make(map[string]Fact),
		signalDefs: make(map[string]SignalDef),
	}

	for _, profile := range profiles {
		config.LoadOrder = append(config.LoadOrder, "profile:"+profile.Name)
		config.Profiles = append(config.Profiles, ResolvedProfile{
			Name:      profile.Name,
			Root:      profile.Root,
			Source:    profile.Source,
			Builtin:   profile.Builtin,
			Manifest:  profile.Manifest,
			Installed: profile.Installed,
		})
		if err := config.addProfile(profile); err != nil {
			return nil, err
		}
	}

	for _, dir := range envPathDirs(envRulesPath) {
		if err := config.addRulesFromDir(dir, "env:"+dir); err != nil {
			return nil, err
		}
		config.LoadOrder = append(config.LoadOrder, "env-rules:"+dir)
	}
	for _, dir := range envPathDirs(envFactsPath) {
		if err := config.addFactsFromDir(dir, "env:"+dir); err != nil {
			return nil, err
		}
		config.LoadOrder = append(config.LoadOrder, "env-facts:"+dir)
	}
	for _, dir := range envPathDirs(envSignalsPath) {
		if err := config.addSignalsFromDir(dir, "env:"+dir); err != nil {
			return nil, err
		}
		config.LoadOrder = append(config.LoadOrder, "env-signals:"+dir)
	}

	projectRulesDir, projectFactsDir, projectSignalsDir := projectOverlayDirs(cwd)
	if err := config.addRulesFromDir(projectRulesDir, "project:"+projectRulesDir); err != nil {
		return nil, err
	}
	if err := config.addFactsFromDir(projectFactsDir, "project:"+projectFactsDir); err != nil {
		return nil, err
	}
	if err := config.addSignalsFromDir(projectSignalsDir, "project:"+projectSignalsDir); err != nil {
		return nil, err
	}
	config.LoadOrder = append(config.LoadOrder, "project")

	configHash, err := config.computeHash()
	if err != nil {
		return nil, err
	}
	config.ConfigHash = configHash
	return config, nil
}

func (c *ResolvedConfig) addProfile(profile ProfileBundle) error {
	if err := c.addRulesFromDir(profileSubdir(profile, "rules"), profile.Name); err != nil {
		return err
	}
	if err := c.addFactsFromDir(profileSubdir(profile, "facts"), profile.Name); err != nil {
		return err
	}
	if err := c.addSignalsFromDir(profileSubdir(profile, "signals"), profile.Name); err != nil {
		return err
	}
	return nil
}

func profileSubdir(profile ProfileBundle, name string) string {
	return filepath.Join(profile.Root, name)
}

func (c *ResolvedConfig) addRulesFromDir(dir, source string) error {
	rules, err := loadRulesGeneric(dir)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		c.guardRules = append(c.guardRules, rule)
		c.Rules = append(c.Rules, ResolvedRule{
			ID:      stableID(source + ":" + rule.filename + ":" + rule.When),
			Source:  rule.filename,
			Action:  rule.Action,
			Message: rule.Message,
			Scope:   rule.Scope,
			When:    rule.When,
		})
	}
	return nil
}

func (c *ResolvedConfig) addFactsFromDir(dir, source string) error {
	facts, meta, err := loadFactsGeneric(dir)
	if err != nil {
		return err
	}
	for name, fact := range facts {
		c.guardFacts[name] = fact
	}
	c.Facts = append(c.Facts, meta...)
	return nil
}

func (c *ResolvedConfig) addSignalsFromDir(dir, source string) error {
	defs, meta, err := loadSignalsGeneric(dir)
	if err != nil {
		return err
	}
	for name, def := range defs {
		c.signalDefs[name] = def
	}
	c.Signals = append(c.Signals, meta...)
	if dir != "" {
		c.signalSearch = append(c.signalSearch, dir)
	}
	_ = source
	return nil
}

func (c *ResolvedConfig) computeHash() (string, error) {
	payload := map[string]any{
		"profiles": c.Profiles,
		"rules":    c.Rules,
		"facts":    c.Facts,
		"signals":  c.Signals,
		"load":     c.LoadOrder,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), nil
}

func stableID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8])
}

func loadRulesGeneric(dir string) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}
	if strings.HasPrefix(filepath.ToSlash(dir), "builtin_profiles/") {
		return loadRulesFromFS(builtinProfilesFS, dir)
	}
	return LoadRulesFromDir(dir)
}

func loadFactsGeneric(dir string) (map[string]Fact, []ResolvedFact, error) {
	if dir == "" {
		return nil, nil, nil
	}
	if strings.HasPrefix(filepath.ToSlash(dir), "builtin_profiles/") {
		return loadFactsFromFS(builtinProfilesFS, dir)
	}
	facts, err := LoadFactsFromDir(dir)
	if err != nil {
		return nil, nil, err
	}
	meta := make([]ResolvedFact, 0, len(facts))
	for name, fact := range facts {
		meta = append(meta, ResolvedFact{Name: name, Source: filepath.Join(dir, name+".yaml"), Type: fact.Type})
	}
	slices.SortFunc(meta, func(a, b ResolvedFact) int { return strings.Compare(a.Name, b.Name) })
	return facts, meta, nil
}

func loadSignalsGeneric(dir string) (map[string]SignalDef, []ResolvedSignal, error) {
	if dir == "" {
		return nil, nil, nil
	}
	var defs map[string]SignalDef
	var err error
	if strings.HasPrefix(filepath.ToSlash(dir), "builtin_profiles/") {
		defs, err = loadSignalsFromFS(builtinProfilesFS, dir)
	} else {
		defs, err = LoadSignalDefsFromDir(dir)
	}
	if err != nil {
		return nil, nil, err
	}
	meta := make([]ResolvedSignal, 0, len(defs))
	for name, def := range defs {
		meta = append(meta, ResolvedSignal{Name: name, Source: filepath.Join(dir, name+".yaml"), OneTimeUse: def.OneTimeUse})
	}
	slices.SortFunc(meta, func(a, b ResolvedSignal) int { return strings.Compare(a.Name, b.Name) })
	return defs, meta, nil
}

func projectOverlayDirs(cwd string) (rulesDir, factsDir, signalsDir string) {
	base := filepath.Join(cwd, ".ward")
	return filepath.Join(base, "rules"), filepath.Join(base, "facts"), filepath.Join(base, "signals")
}

func copyFSDir(srcFS fs.FS, srcDir, dstDir string) error {
	return fs.WalkDir(srcFS, srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(srcFS, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func copyLocalDir(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func gitRevision(dir string) string {
	out, err := gitOutput(dir, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func cloneProfileSource(source, ref string) (string, string, error) {
	tmpDir, err := os.MkdirTemp("", "ward-profile-*")
	if err != nil {
		return "", "", err
	}
	if strings.Count(source, "/") == 1 && !strings.Contains(source, "://") && !strings.HasSuffix(source, ".git") {
		source = "https://github.com/" + source + ".git"
	}
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, source, tmpDir)
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("git clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return tmpDir, gitRevision(tmpDir), nil
}
