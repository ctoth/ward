package main

import (
	"bytes"
	"fmt"
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
	rootOut, err := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		if isNotGitRepoErr(err) {
			return &RepoStatus{Clean: true}, nil
		}
		return nil, err
	}

	root := NormalizePath(strings.TrimSpace(rootOut))
	branchOut, err := gitOutput(root, "branch", "--show-current")
	if err != nil {
		return nil, err
	}

	staged, err := gitLines(root, "diff", "--name-only", "--cached", "--no-renames")
	if err != nil {
		return nil, err
	}
	unstaged, err := gitLines(root, "diff", "--name-only", "--no-renames")
	if err != nil {
		return nil, err
	}
	untracked, err := gitLines(root, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}

	status := &RepoStatus{
		InGit:          true,
		Root:           root,
		Branch:         strings.TrimSpace(branchOut),
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

func gitLines(dir string, args ...string) ([]string, error) {
	out, err := gitOutput(dir, args...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths = append(paths, NormalizePath(filepath.ToSlash(line)))
	}
	return paths, nil
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
