//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API constants
const (
	thSnapProcess = 0x00000002
	maxPath       = 260
)

// PROCESSENTRY32 is the Windows process entry structure.
type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW   = kernel32.NewProc("Process32FirstW")
	procProcess32NextW    = kernel32.NewProc("Process32NextW")
)

type procInfo struct {
	pid  uint32
	ppid uint32
	name string
}

// snapshotProcesses returns a map of PID → procInfo for all running processes.
func snapshotProcesses() (map[uint32]procInfo, error) {
	handle, _, err := procCreateToolhelp32.Call(uintptr(thSnapProcess), 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW: %w", err)
	}

	procs := make(map[uint32]procInfo)
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		procs[entry.ProcessID] = procInfo{
			pid:  entry.ProcessID,
			ppid: entry.ParentProcessID,
			name: name,
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return procs, nil
}

// findClaudeCodeAncestorPID walks up the process tree from the current process
// and returns the PID of the first node.exe ancestor (Claude Code).
// Returns 0 if not found.
func findClaudeCodeAncestorPID() (uint32, error) {
	if os.Getenv("CLAUDECODE") != "1" {
		return 0, nil
	}

	procs, err := snapshotProcesses()
	if err != nil {
		return 0, err
	}

	pid := uint32(os.Getpid())
	visited := make(map[uint32]bool)

	for {
		if visited[pid] {
			break // cycle guard
		}
		visited[pid] = true

		info, ok := procs[pid]
		if !ok {
			break
		}

		name := strings.ToLower(info.name)
		if name == "node.exe" || name == "node" || name == "claude.exe" {
			return pid, nil
		}

		if info.ppid == 0 || info.ppid == pid {
			break
		}
		pid = info.ppid
	}
	return 0, nil
}
