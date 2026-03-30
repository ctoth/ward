//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// findClaudeCodeAncestorPID walks up the process tree from the current process
// and returns the PID of the first node ancestor (Claude Code).
// Returns 0 if not found.
func findClaudeCodeAncestorPID() (uint32, error) {
	if os.Getenv("CLAUDECODE") != "1" {
		return 0, nil
	}

	pid := os.Getpid()
	visited := make(map[int]bool)

	for {
		if visited[pid] || pid <= 1 {
			break
		}
		visited[pid] = true

		name, err := processName(pid)
		if err != nil {
			break
		}

		nameLower := strings.ToLower(name)
		if nameLower == "node" || nameLower == "node.exe" || nameLower == "claude" {
			return uint32(pid), nil
		}

		ppid, err := parentPID(pid)
		if err != nil || ppid == pid {
			break
		}
		pid = ppid
	}
	return 0, nil
}

// parentPID reads the parent PID from /proc/{pid}/status.
func parentPID(pid int) (int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, os.ErrNotExist
}

// processName reads the process name from /proc/{pid}/comm.
func processName(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
