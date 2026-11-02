//go:build linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerFilesystemIdentityAndExclusions(t *testing.T) {
	host := t.TempDir()
	root := filepath.Join(host, "run/task/rootfs")
	proc := filepath.Join(host, "proc/123")
	for _, p := range []string{root, proc, filepath.Join(host, "proc/1")} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stat := "123 (command with ) spaces) S " + strings.Repeat("0 ", 18) + "12345 0\n"
	write(filepath.Join(proc, "stat"), stat)
	if err := os.Symlink(root, filepath.Join(proc, "root")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(proc, "mountinfo"), "10 9 0:42 / / rw - overlay overlay rw\n11 10 8:1 /data /data\\040with\\040spaces rw - ext4 /dev/sda rw\n")
	write(filepath.Join(host, "proc/1/mountinfo"), "20 9 0:42 / /run/task/rootfs rw - overlay overlay rw\n")
	path, excludes, validate, err := containerFilesystem(host, 123)
	if err != nil {
		t.Fatal(err)
	}
	if path != root || fmt.Sprint(excludes) != "[/data with spaces]" {
		t.Fatalf("wrong root or mounts: %s %v", path, excludes)
	}
	if err := validate(); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(proc, "stat"), strings.Replace(stat, "12345", "54321", 1))
	if validate() == nil {
		t.Fatal("PID reuse accepted")
	}
	write(filepath.Join(proc, "stat"), stat)
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if validate() == nil {
		t.Fatal("replacement root accepted")
	}
}

func TestContainerFilesystemFailsClosed(t *testing.T) {
	for _, pid := range []int{-1, 0, 1, 99999999} {
		if _, _, _, err := containerFilesystem(t.TempDir(), pid); err == nil {
			t.Fatalf("accepted PID %d", pid)
		}
	}
}
