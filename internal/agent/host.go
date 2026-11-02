package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func hostInventory(c Config) (Event, error) {
	// Follow relative symlinks within the host root. If /etc/os-release uses an
	// absolute symlink, read its canonical location without escaping the host root.
	data, err := readRootFile(c.Root, "etc/os-release")
	if err != nil {
		data, err = readRootFile(c.Root, "usr/lib/os-release")
	}
	if err != nil {
		return nil, fmt.Errorf("read host os-release: %w", err)
	}
	osInfo := parseOSRelease(string(data))
	id := c.HostID
	if id == "" {
		id = readText(c.Root, "etc/machine-id")
	}
	if id == "" {
		return nil, fmt.Errorf("host machine-id is missing; supply --host-id")
	}
	name := c.HostName
	if name == "" {
		name = readText(c.Root, "etc/hostname")
	}
	if name == "" && c.Root == "/" {
		name, _ = os.Hostname()
	}
	if name == "" {
		return nil, fmt.Errorf("host hostname is missing; supply --host-name")
	}
	kernel := readText(c.Root, "proc/sys/kernel/osrelease")
	// The agent container shares the node kernel even when /host/proc is masked.
	if kernel == "" {
		kernel = readText("/", "proc/sys/kernel/osrelease")
	}
	event := Event{"host.id": id, "host.name": name, "recense.host.os.id": osInfo["ID"], "recense.host.os.name": osInfo["NAME"], "recense.host.os.version": osInfo["VERSION_ID"], "recense.host.kernel.release": kernel, "host.arch": runtime.GOARCH, "recense.inventory.scope": "host"}
	if osInfo["ID"] == "ubuntu" {
		_, err := os.Stat(filepath.Join(c.Root, "run/reboot-required"))
		if err == nil {
			event["recense.host.reboot_required"] = true
		} else if os.IsNotExist(err) {
			event["recense.host.reboot_required"] = false
		}
	}
	return event, nil
}

func readRootFile(root, path string) ([]byte, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.ReadFile(path)
}

func readText(root, path string) string {
	b, err := readRootFile(root, path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func parseOSRelease(s string) map[string]string {
	out := map[string]string{}
	scan := bufio.NewScanner(strings.NewReader(s))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if unquoted, err := strconv.Unquote(v); err == nil {
			v = unquoted
		} else {
			v = strings.Trim(v, "'")
		}
		out[k] = v
	}
	return out
}

// Native package managers know which repository updates are actually available.
// A host mount does not make the container's APT/DNF a host package manager.
func checkUpdates(ctx context.Context, c Config) Event {
	if c.Root != "/" {
		return Event{"recense.status": "unsupported", "recense.reason": "package-manager update checks require a native host installation"}
	}
	data := readText(c.Root, "usr/lib/os-release")
	if data == "" {
		data = readText(c.Root, "etc/os-release")
	}
	distro := parseOSRelease(data)
	var name string
	var args []string
	switch distro["ID"] {
	case "ubuntu":
		name = "/usr/bin/python3"
		args = []string{"-c", ubuntuUpdates}
	case "amzn":
		if distro["VERSION_ID"] != "2023" {
			return Event{"recense.status": "unsupported", "recense.reason": "update checks support Amazon Linux 2023 and Ubuntu"}
		}
		name = "dnf"
		args = []string{"-q", "--refresh", "--releasever=latest", "updateinfo", "list", "--security", "--available"}
	default:
		return Event{"recense.status": "unsupported", "recense.reason": "unsupported package manager"}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	output, err := commandOutput(ctx, name, args, nil, 4<<20)
	if err != nil {
		return Event{"recense.status": "failed", "recense.error": err.Error()}
	}
	event := Event{"recense.status": "success", "recense.host.updates.checked_at": time.Now().UTC().Format(time.RFC3339Nano)}
	if distro["ID"] == "ubuntu" {
		if err := json.Unmarshal(output, &event); err != nil {
			return Event{"recense.status": "failed", "recense.error": "invalid Ubuntu update check output"}
		}
		// This is the last successful metadata refresh, not the time this query ran.
		if st, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil {
			event["recense.host.updates.metadata_refreshed_at"] = st.ModTime().UTC().Format(time.RFC3339Nano)
		}
		event["recense.host.updates.metadata_policy"] = "existing apt cache; refreshed by the host's apt timers"
	} else {
		packages := map[string]bool{}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.HasPrefix(fields[0], "ALAS") {
				packages[fields[len(fields)-1]] = true
			}
		}
		event["recense.host.updates.security_updates_pending"] = len(packages)
		event["recense.host.updates.repository_release"] = "latest"
		event["recense.host.updates.metadata_refreshed_at"] = event["recense.host.updates.checked_at"]
	}
	return event
}

const ubuntuUpdates = `import apt, apt_pkg, json
cache = apt.Cache()
count = 0
for package in cache:
    if not package.is_installed or not package.is_upgradable:
        continue
    if any(apt_pkg.version_compare(v.version, package.installed.version) > 0
           and any(o.archive.endswith('-security') and o.origin in ('Ubuntu', 'UbuntuESM', 'UbuntuESMApps') for o in v.origins)
           for v in package.versions):
        count += 1
print(json.dumps({'recense.host.updates.security_updates_pending': count}))
`
