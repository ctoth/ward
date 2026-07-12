package main

import "testing"

func TestCommandSessionPrecedenceRemainsExact(t *testing.T) {
	t.Setenv(envSession, "ward-session")
	t.Setenv(envCodexThread, "codex-thread")
	t.Setenv(envClaudeSession, "claude-session")

	tests := []struct {
		name           string
		args           []string
		processSession string
		cwd            string
		want           string
	}{
		{
			name:           "explicit session",
			args:           []string{"ward", "set", "scout", "--session", "explicit-session"},
			processSession: "process-session",
			cwd:            "C:/repo",
			want:           "explicit-session",
		},
		{
			name:           "WARD_SESSION",
			args:           []string{"ward", "set", "scout"},
			processSession: "process-session",
			cwd:            "C:/repo",
			want:           "ward-session",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveCommandSession(test.args, test.processSession, test.cwd)
			if got != test.want {
				t.Fatalf("resolveCommandSession() = %q, want %q", got, test.want)
			}
		})
	}

	t.Setenv(envSession, "")
	if got := resolveCommandSession([]string{"ward", "set", "scout"}, "process-session", "C:/repo"); got != "codex-thread" {
		t.Fatalf("Codex precedence = %q, want codex-thread", got)
	}

	t.Setenv(envCodexThread, "")
	if got := resolveCommandSession([]string{"ward", "set", "scout"}, "process-session", "C:/repo"); got != "claude-session" {
		t.Fatalf("Claude env precedence = %q, want claude-session", got)
	}

	t.Setenv(envClaudeSession, "")
	if got := resolveCommandSession([]string{"ward", "set", "scout"}, "process-session", "C:/repo"); got != "process-session" {
		t.Fatalf("process-tree precedence = %q, want process-session", got)
	}

	got := resolveCommandSession([]string{"ward", "set", "scout"}, "", "C:/repo")
	if got == "" || got[:3] != "wd-" {
		t.Fatalf("cwd fallback = %q, want wd-*", got)
	}
}

func TestSessionRegistryCleanupDoesNotDeleteAnotherSession(t *testing.T) {
	sessionA := "registry-a-" + t.Name()
	sessionB := "registry-b-" + t.Name()
	const pidA uint32 = 41001
	const pidB uint32 = 41002
	t.Cleanup(func() {
		_ = unregisterBySessionID(sessionA)
		_ = unregisterBySessionID(sessionB)
	})

	if err := registerSession(pidA, sessionA, "C:/repo-a"); err != nil {
		t.Fatal(err)
	}
	if err := registerSession(pidB, sessionB, "C:/repo-b"); err != nil {
		t.Fatal(err)
	}
	if err := unregisterBySessionID(sessionA); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupSessionByPID(pidA); err == nil {
		t.Fatal("session A registry entry still exists")
	}
	got, err := lookupSessionByPID(pidB)
	if err != nil {
		t.Fatal(err)
	}
	if got != sessionB {
		t.Fatalf("session B registry = %q, want %q", got, sessionB)
	}
}
