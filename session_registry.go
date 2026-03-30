package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// registryEntry maps a Claude Code PID to a session ID.
type registryEntry struct {
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
}

func registryDir() string {
	return filepath.Join(stateDir(), "sessions")
}

func registryPath(ccPID uint32) string {
	return filepath.Join(registryDir(), fmt.Sprintf("pid-%d.json", ccPID))
}

// registerSession writes the CC PID → session_id mapping.
func registerSession(ccPID uint32, sessionID, cwd string) error {
	dir := registryDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entry := registryEntry{SessionID: sessionID, CWD: cwd}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return os.WriteFile(registryPath(ccPID), data, 0o644)
}

// lookupSessionByPID reads the session ID for a given CC PID.
func lookupSessionByPID(ccPID uint32) (string, error) {
	data, err := os.ReadFile(registryPath(ccPID))
	if err != nil {
		return "", err
	}
	var entry registryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return "", err
	}
	return entry.SessionID, nil
}

// unregisterBySessionID scans the registry and removes entries matching the session ID.
func unregisterBySessionID(sessionID string) error {
	dir := registryDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "pid-") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var reg registryEntry
		if err := json.Unmarshal(data, &reg); err != nil {
			continue
		}
		if reg.SessionID == sessionID {
			os.Remove(path)
		}
	}
	return nil
}

// resolveSessionFromProcessTree walks up the process tree to find the Claude Code
// ancestor PID, then looks up the registered session ID for that PID.
// Returns empty string if not inside Claude Code or no registration found.
func resolveSessionFromProcessTree() string {
	ccPID, err := findClaudeCodeAncestorPID()
	if err != nil || ccPID == 0 {
		return ""
	}
	sid, err := lookupSessionByPID(ccPID)
	if err != nil {
		return ""
	}
	return sid
}
