package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestComputeRepoStatus(t *testing.T) {
	repo := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "tracked.txt")
	gitRun(t, repo, "commit", "-m", "initial")

	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "staged.txt"), []byte("stage me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "staged.txt")

	status, err := ComputeRepoStatus(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !status.InGit {
		t.Fatal("expected git repo")
	}
	if status.Clean {
		t.Fatal("expected dirty repo")
	}
	if !status.HasStaged || !status.HasUnstaged || !status.HasUntracked {
		t.Fatalf("expected staged/unstaged/untracked flags, got %+v", status)
	}
	if len(status.StagedPaths) != 1 || status.StagedPaths[0] != "staged.txt" {
		t.Fatalf("unexpected staged paths: %#v", status.StagedPaths)
	}
	if len(status.UnstagedPaths) != 1 || status.UnstagedPaths[0] != "tracked.txt" {
		t.Fatalf("unexpected unstaged paths: %#v", status.UnstagedPaths)
	}
	if len(status.UntrackedPaths) != 1 || status.UntrackedPaths[0] != "untracked.txt" {
		t.Fatalf("unexpected untracked paths: %#v", status.UntrackedPaths)
	}
}

func TestStateSyncRepoAndTouchedFiles(t *testing.T) {
	state := NewState("implementing")
	status := &RepoStatus{
		InGit:       true,
		Root:        "C:/repo",
		DirtyPaths:  []string{"user.txt"},
		StagedPaths: []string{"user.txt"},
	}
	state.SyncRepo(status)

	if state.RepoRoot != "C:/repo" {
		t.Fatalf("expected repo root recorded, got %q", state.RepoRoot)
	}
	if len(state.BaselineDirtyPaths) != 1 || state.BaselineDirtyPaths[0] != "user.txt" {
		t.Fatalf("unexpected baseline dirty paths: %#v", state.BaselineDirtyPaths)
	}

	state.UpdateEvent(ToolEvent{Tool: "Edit", Input: map[string]any{"file_path": `C:\repo\agent.txt`}, EventType: "pre_tool"}, status)
	state.UpdateEvent(ToolEvent{Tool: "Bash", Input: map[string]any{"command": "git commit -m test"}, EventType: "pre_tool"}, status)

	if len(state.TouchedFiles) != 1 || state.TouchedFiles[0] != "agent.txt" {
		t.Fatalf("unexpected touched files: %#v", state.TouchedFiles)
	}
	if len(state.TouchedSinceCommit) != 0 {
		t.Fatalf("expected touched-since-commit reset after commit, got %#v", state.TouchedSinceCommit)
	}
}

func TestSyncRepoParksAndRestoresScopeAcrossRootSwitch(t *testing.T) {
	state := NewState("implementing")
	repoA := &RepoStatus{InGit: true, Root: "C:/repo-a", DirtyPaths: []string{"pre-a.txt"}}
	repoB := &RepoStatus{InGit: true, Root: "C:/repo-b", DirtyPaths: []string{"pre-b.txt"}}

	state.SyncRepo(repoA)
	state.UpdateEvent(ToolEvent{Tool: "Edit", Input: map[string]any{"file_path": "C:/repo-a/agent-a.txt"}, EventType: "pre_tool"}, repoA)
	state.AdoptedPaths = []string{"adopted-a.txt"}

	// Switching repos must PARK repo-a's scope, not destroy it — an agent
	// that greps a sibling repo mid-task must not lose its commit authority.
	state.SyncRepo(repoB)
	if len(state.TouchedFiles) != 0 {
		t.Fatalf("repo-b inherited repo-a touched files: %#v", state.TouchedFiles)
	}
	if len(state.AdoptedPaths) != 0 {
		t.Fatalf("repo-b inherited repo-a adoptions: %#v", state.AdoptedPaths)
	}
	if len(state.BaselineDirtyPaths) != 1 || state.BaselineDirtyPaths[0] != "pre-b.txt" {
		t.Fatalf("unexpected repo-b baseline: %#v", state.BaselineDirtyPaths)
	}
	state.UpdateEvent(ToolEvent{Tool: "Edit", Input: map[string]any{"file_path": "C:/repo-b/agent-b.txt"}, EventType: "pre_tool"}, repoB)

	// Returning restores repo-a's scope intact.
	state.SyncRepo(repoA)
	if len(state.TouchedFiles) != 1 || state.TouchedFiles[0] != "agent-a.txt" {
		t.Fatalf("repo-a touched files not restored: %#v", state.TouchedFiles)
	}
	if len(state.AdoptedPaths) != 1 || state.AdoptedPaths[0] != "adopted-a.txt" {
		t.Fatalf("repo-a adoptions not restored: %#v", state.AdoptedPaths)
	}
	if len(state.BaselineDirtyPaths) != 1 || state.BaselineDirtyPaths[0] != "pre-a.txt" {
		t.Fatalf("repo-a baseline not restored: %#v", state.BaselineDirtyPaths)
	}

	// And repo-b's scope was parked in turn.
	state.SyncRepo(repoB)
	if len(state.TouchedFiles) != 1 || state.TouchedFiles[0] != "agent-b.txt" {
		t.Fatalf("repo-b touched files not restored: %#v", state.TouchedFiles)
	}
}

func TestStateToMapIncludesGrantPaths(t *testing.T) {
	state := NewState("implementing")
	state.AdoptedPaths = []string{"src/app.py"}
	state.DiscardablePaths = []string{"src/menu.py"}
	state.TouchedFiles = []string{"src/app.py", "docs/spec.md"}
	state.BaselineDirtyPaths = []string{"src/app.py"}

	mapped := state.ToMap()
	adopted := mapped["adopted_paths"].([]any)
	discardable := mapped["discardable_paths"].([]any)
	owned := mapped["session_owned_paths"].([]any)

	if len(adopted) != 1 || adopted[0] != "src/app.py" {
		t.Fatalf("unexpected adopted paths: %#v", adopted)
	}
	if len(discardable) != 1 || discardable[0] != "src/menu.py" {
		t.Fatalf("unexpected discardable paths: %#v", discardable)
	}
	if len(owned) != 1 || owned[0] != "docs/spec.md" {
		t.Fatalf("unexpected session owned paths: %#v", owned)
	}
}

func TestNormalizeGrantPath(t *testing.T) {
	repo := t.TempDir()
	path, err := normalizeGrantPath(NormalizePath(repo), repo, filepath.Join(repo, "src", "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	if path != "src/app.py" {
		t.Fatalf("expected src/app.py, got %q", path)
	}
}

func TestGrantPathsAdoptsAbsolutePathInSiblingRepoScope(t *testing.T) {
	repoA := t.TempDir()
	repoB := t.TempDir()
	target := filepath.Join(repoB, "src", "app.py")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package src\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := NewState("implementing")
	statusA := &RepoStatus{InGit: true, Root: NormalizePath(repoA), Branch: "main", Clean: true}
	statusB := &RepoStatus{InGit: true, Root: NormalizePath(repoB), Branch: "main", Clean: true}
	resolveStatus := func(path string) (*RepoStatus, error) {
		path = NormalizePath(path)
		if path == statusA.Root || strings.HasPrefix(path, statusA.Root+"/") {
			return statusA, nil
		}
		if path == statusB.Root || strings.HasPrefix(path, statusB.Root+"/") {
			return statusB, nil
		}
		return &RepoStatus{Clean: true}, nil
	}
	state.SyncRepo(statusA)

	normalized, err := grantPathsWithStatus(state, "adopt", repoA, []string{target}, resolveStatus)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 1 || normalized[0] != "src/app.py" {
		t.Fatalf("normalized paths = %#v, want [src/app.py]", normalized)
	}
	if state.RepoRoot != NormalizePath(repoB) {
		t.Fatalf("active repo = %q, want sibling repo %q", state.RepoRoot, NormalizePath(repoB))
	}
	if len(state.AdoptedPaths) != 1 || state.AdoptedPaths[0] != "src/app.py" {
		t.Fatalf("sibling adopted paths = %#v, want [src/app.py]", state.AdoptedPaths)
	}

	state.SyncRepo(statusA)
	if len(state.AdoptedPaths) != 0 {
		t.Fatalf("caller repo inherited sibling adoption: %#v", state.AdoptedPaths)
	}
	state.SyncRepo(statusB)
	if len(state.AdoptedPaths) != 1 || state.AdoptedPaths[0] != "src/app.py" {
		t.Fatalf("sibling adoption was not restored: %#v", state.AdoptedPaths)
	}

	rules, err := LoadRulesFromDir("builtin_profiles/git-discipline/rules")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewGuard(nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	event := gitBashEvent(t, repoB, "git add -- src/app.py")
	result, _, err := EvaluateVerbose(guard, state, event, statusB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Action == "deny" {
		t.Fatalf("staging explicitly adopted sibling path was denied: %+v", result)
	}
}

func initTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitRun(t, repo, "init")
	gitRun(t, repo, "config", "core.fsmonitor", "false")
	return repo
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Ward Test",
		"GIT_AUTHOR_EMAIL=ward@example.com",
		"GIT_COMMITTER_NAME=Ward Test",
		"GIT_COMMITTER_EMAIL=ward@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}
