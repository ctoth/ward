package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type RepoStatus struct {
	InGit          bool
	Root           string
	Branch         string
	Clean          bool
	HasStaged      bool
	HasUnstaged    bool
	HasUntracked   bool
	DirtyPaths     []string
	StagedPaths    []string
	UnstagedPaths  []string
	UntrackedPaths []string
}

func ComputeRepoStatus(cwd string) (*RepoStatus, error) {
	root := cwd
	if _, err := os.Stat(filepath.Join(cwd, ".git")); err != nil {
		rootOut, gitErr := gitOutput(cwd, "rev-parse", "--show-toplevel")
		if gitErr != nil {
			if isNotGitRepoErr(gitErr) {
				return &RepoStatus{Clean: true}, nil
			}
			return nil, gitErr
		}
		root = strings.TrimSpace(rootOut)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repo root %q: %w", root, err)
	}
	root = NormalizePath(absRoot)

	statusOut, err := gitOutput(root, "status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, err
	}

	var branch string
	var staged, unstaged, untracked []string
	for _, record := range strings.Split(statusOut, "\x00") {
		if record == "" {
			continue
		}
		switch {
		case strings.HasPrefix(record, "# branch.head "):
			branch = strings.TrimPrefix(record, "# branch.head ")
			if branch == "(detached)" {
				branch = ""
			}
		case strings.HasPrefix(record, "? "):
			untracked = append(untracked, strings.TrimPrefix(record, "? "))
		case strings.HasPrefix(record, "1 "):
			fields := strings.SplitN(record, " ", 9)
			if len(fields) != 9 || len(fields[1]) != 2 {
				return nil, fmt.Errorf("parse git status record %q", record)
			}
			if fields[1][0] != '.' {
				staged = append(staged, fields[8])
			}
			if fields[1][1] != '.' {
				unstaged = append(unstaged, fields[8])
			}
		case strings.HasPrefix(record, "u "):
			fields := strings.SplitN(record, " ", 11)
			if len(fields) != 11 || len(fields[1]) != 2 {
				return nil, fmt.Errorf("parse git status record %q", record)
			}
			staged = append(staged, fields[10])
			unstaged = append(unstaged, fields[10])
		}
	}

	status := &RepoStatus{
		InGit:          true,
		Root:           root,
		Branch:         branch,
		StagedPaths:    uniquePaths(staged),
		UnstagedPaths:  uniquePaths(unstaged),
		UntrackedPaths: uniquePaths(untracked),
	}
	status.HasStaged = len(status.StagedPaths) > 0
	status.HasUnstaged = len(status.UnstagedPaths) > 0
	status.HasUntracked = len(status.UntrackedPaths) > 0
	status.DirtyPaths = uniquePaths(append(append([]string{}, status.StagedPaths...), append(status.UnstagedPaths, status.UntrackedPaths...)...))
	status.Clean = len(status.DirtyPaths) == 0
	return status, nil
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

func isNotGitRepoErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "not a git repository") || strings.Contains(msg, "outside repository")
}

func uniquePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = NormalizePath(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	slices.Sort(out)
	return out
}

func pathIntersection(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	set := make(map[string]bool, len(right))
	for _, path := range right {
		set[NormalizePath(path)] = true
	}
	out := make([]string, 0, len(left))
	for _, path := range left {
		path = NormalizePath(path)
		if set[path] {
			out = append(out, path)
		}
	}
	return uniquePaths(out)
}

func pathDifference(left, right []string) []string {
	if len(left) == 0 {
		return nil
	}
	if len(right) == 0 {
		return uniquePaths(left)
	}
	set := make(map[string]bool, len(right))
	for _, path := range right {
		set[NormalizePath(path)] = true
	}
	out := make([]string, 0, len(left))
	for _, path := range left {
		path = NormalizePath(path)
		if !set[path] {
			out = append(out, path)
		}
	}
	return uniquePaths(out)
}
