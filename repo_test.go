package main

import (
	"os"
	"os/exec"
	"path/filepath"
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

	state.Update("Edit", map[string]any{"file_path": `C:\repo\agent.txt`})
	state.Update("Bash", map[string]any{"command": "git commit -m test"})

	if len(state.TouchedFiles) != 1 || state.TouchedFiles[0] != "agent.txt" {
		t.Fatalf("unexpected touched files: %#v", state.TouchedFiles)
	}
	if len(state.TouchedSinceCommit) != 0 {
		t.Fatalf("expected touched-since-commit reset after commit, got %#v", state.TouchedSinceCommit)
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
	repo := initTestRepo(t)
	path, err := normalizeGrantPath(NormalizePath(repo), repo, filepath.Join(repo, "src", "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	if path != "src/app.py" {
		t.Fatalf("expected src/app.py, got %q", path)
	}
}

func initTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitRun(t, repo, "init")
	gitRun(t, repo, "config", "user.name", "Ward Test")
	gitRun(t, repo, "config", "user.email", "ward@example.com")
	return repo
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}
