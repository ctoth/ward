package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func loadRulesFromFS(src fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(src, filepath.ToSlash(dir))
	if err != nil {
		if isFSNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	rules := make([]Rule, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return nil, err
		}
		var rule Rule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if rule.When == "" || rule.Action == "" {
			return nil, fmt.Errorf("%s: missing required fields", path)
		}
		rule.filename = path
		rules = append(rules, rule)
	}
	return rules, nil
}

func loadFactsFromFS(src fs.FS, dir string) (map[string]Fact, []ResolvedFact, error) {
	entries, err := fs.ReadDir(src, filepath.ToSlash(dir))
	if err != nil {
		if isFSNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	facts := make(map[string]Fact)
	meta := make([]ResolvedFact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return nil, nil, err
		}
		var fact Fact
		if err := yaml.Unmarshal(data, &fact); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if fact.Command == "" {
			return nil, nil, fmt.Errorf("%s: missing command", path)
		}
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		facts[name] = fact
		meta = append(meta, ResolvedFact{Name: name, Source: path, Type: fact.Type})
	}
	return facts, meta, nil
}

func loadSignalsFromFS(src fs.FS, dir string) (map[string]SignalDef, error) {
	entries, err := fs.ReadDir(src, filepath.ToSlash(dir))
	if err != nil {
		if isFSNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defs := make(map[string]SignalDef)
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return nil, err
		}
		var def SignalDef
		if err := yaml.Unmarshal(data, &def); err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		defs[name] = def
	}
	return defs, nil
}

func isFSNotExist(err error) bool {
	return strings.Contains(err.Error(), "file does not exist")
}
