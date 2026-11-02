//go:build linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
)

// Resolve a normal host-visible mount path. Passing /proc/PID/root to Syft is
// unsafe: canonicalizing that magic link can resolve to the scanner's own root.
func containerFilesystem(host string, pid int) (string, []string, func() error, error) {
	if pid <= 1 {
		return "", nil, nil, fmt.Errorf("invalid container PID %d", pid)
	}
	proc := filepath.Join(host, "proc", strconv.Itoa(pid))
	start, err := processStart(proc)
	if err != nil {
		return "", nil, nil, err
	}
	rootInfo, err := os.Stat(filepath.Join(proc, "root"))
	if err != nil {
		return "", nil, nil, fmt.Errorf("read container root: %w", err)
	}
	hostInfo, err := os.Stat(host)
	if err != nil {
		return "", nil, nil, err
	}
	if os.SameFile(rootInfo, hostInfo) {
		return "", nil, nil, fmt.Errorf("container root is host root")
	}
	readMounts := func(path string) ([]*mountinfo.Info, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return mountinfo.GetMountsFromReader(f, nil)
	}
	mounts, err := readMounts(filepath.Join(proc, "mountinfo"))
	if err != nil {
		return "", nil, nil, err
	}
	var rootMount *mountinfo.Info
	var excludes []string
	for _, m := range mounts {
		if m.Mountpoint == "/" {
			rootMount = m
		} else {
			excludes = append(excludes, m.Mountpoint)
		}
	}
	if rootMount == nil {
		return "", nil, nil, fmt.Errorf("container has no root mount")
	}
	hostMounts, err := readMounts(filepath.Join(host, "proc/1/mountinfo"))
	if err != nil {
		return "", nil, nil, err
	}
	resolved := ""
	for _, m := range hostMounts {
		if m.Major != rootMount.Major || m.Minor != rootMount.Minor || m.Root != rootMount.Root {
			continue
		}
		candidate, err := filepath.EvalSymlinks(filepath.Join(host, m.Mountpoint))
		if err != nil {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil || !os.SameFile(info, rootInfo) {
			continue
		}
		if resolved != "" && resolved != candidate {
			return "", nil, nil, fmt.Errorf("ambiguous container root mounts")
		}
		resolved = candidate
	}
	if resolved == "" {
		return "", nil, nil, fmt.Errorf("no verified host-visible container root mount")
	}
	validate := func() error {
		current, err := processStart(proc)
		if err != nil || current != start {
			return fmt.Errorf("container process changed during scan")
		}
		for _, path := range []string{filepath.Join(proc, "root"), resolved} {
			info, err := os.Stat(path)
			if err != nil || !os.SameFile(info, rootInfo) {
				return fmt.Errorf("container root changed during scan")
			}
		}
		return nil
	}
	if err := validate(); err != nil {
		return "", nil, nil, err
	}
	return resolved, excludes, validate, nil
}

func processStart(proc string) (string, error) {
	data, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return "", err
	}
	// comm is parenthesized and can itself contain spaces and parentheses.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return "", fmt.Errorf("incomplete process stat")
	}
	return fields[19], nil
}
