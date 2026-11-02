package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type target struct{ Kind, ID, Source string }
type packageRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	PURL      string `json:"purl"`
	Locations []struct {
		Path string `json:"path"`
	} `json:"locations"`
}
type sbom struct {
	Artifacts []packageRecord `json:"artifacts"`
}
type grypeReport struct {
	Matches []struct {
		Artifact      packageRecord `json:"artifact"`
		Vulnerability struct {
			ID, Namespace, Severity string
			Fix                     struct {
				State    string
				Versions []string
			}
		} `json:"vulnerability"`
	} `json:"matches"`
	Descriptor struct {
		Version string
		DB      json.RawMessage
	} `json:"descriptor"`
}

func scan(ctx context.Context, c Config, e *emitter, t target) (resultErr error) {
	scanID, err := newID()
	if err != nil {
		return err
	}
	started := time.Now()
	base := Event{"scan_id": scanID, "target_type": t.Kind, "target_id": t.ID}
	emit := func(kind string, fields Event) error {
		merged := Event{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range fields {
			merged[k] = v
		}
		return e.emit(kind, merged)
	}
	defer func() {
		if resultErr != nil {
			if err := emit("vulnerability.scan_completed", Event{"status": "failed", "error": resultErr.Error(), "duration_seconds": time.Since(started).Seconds()}); err != nil {
				resultErr = fmt.Errorf("%w; emit failure: %v", resultErr, err)
			}
		}
	}()
	work, err := os.MkdirTemp("", "recense-scan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	// Explicit config files prevent scanners from reading configuration from the
	// current directory or a scanned filesystem. Never forward their raw config.
	config := filepath.Join(work, "scanner.yaml")
	if err := os.WriteFile(config, []byte("check-for-app-update: false\n"), 0600); err != nil {
		return err
	}
	env := []string{"CONTAINERD_ADDRESS=" + c.Socket, "CONTAINERD_NAMESPACE=" + c.Namespace, "DOCKER_HOST=unix://" + c.Socket}
	args := []string{"scan", t.Source, "-o", "syft-json", "-c", config, "--quiet"}
	if t.Kind == "host" {
		for _, path := range []string{"proc", "sys", "dev", "run", "tmp", "var/lib/docker", "var/lib/containerd", "var/lib/kubelet", "var/lib/recense"} {
			args = append(args, "--exclude", "./"+path+"/**")
		}
	}
	scanCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	inventory, err := commandOutput(scanCtx, c.Syft, args, env, 128<<20)
	cancel()
	if err != nil {
		return fmt.Errorf("Syft %s: %w", t.ID, err)
	}
	var packages sbom
	if err := json.Unmarshal(inventory, &packages); err != nil {
		return fmt.Errorf("parse Syft output: %w", err)
	}
	if packages.Artifacts == nil {
		return fmt.Errorf("Syft report is missing artifacts")
	}
	for _, p := range packages.Artifacts {
		fields := packageFields(p)
		if err := emit("software.inventory", fields); err != nil {
			return err
		}
	}
	if err := emit("software.inventory_completed", Event{"status": "success", "package_count": len(packages.Artifacts)}); err != nil {
		return err
	}
	sbomPath := filepath.Join(work, "sbom.json")
	if err := os.WriteFile(sbomPath, inventory, 0600); err != nil {
		return err
	}
	scanCtx, cancel = context.WithTimeout(ctx, c.Timeout)
	findings, err := commandOutput(scanCtx, c.Grype, []string{"sbom:" + sbomPath, "-o", "json", "-c", config, "--quiet"}, env, 128<<20)
	cancel()
	if err != nil {
		return fmt.Errorf("Grype %s: %w", t.ID, err)
	}
	var report grypeReport
	if err := json.Unmarshal(findings, &report); err != nil {
		return fmt.Errorf("parse Grype output: %w", err)
	}
	if report.Matches == nil {
		return fmt.Errorf("Grype report is missing matches")
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
	for _, m := range report.Matches {
		fields := packageFields(m.Artifact)
		fields["vulnerability_id"] = m.Vulnerability.ID
		fields["vulnerability_namespace"] = m.Vulnerability.Namespace
		fields["vulnerability_severity"] = m.Vulnerability.Severity
		fields["fix_state"] = m.Vulnerability.Fix.State
		fields["fix_versions"] = m.Vulnerability.Fix.Versions
		fields["scanner_name"] = "grype"
		if err := emit("vulnerability.finding", fields); err != nil {
			return err
		}
		counts[strings.ToLower(m.Vulnerability.Severity)]++
	}
	fields := Event{"status": "success", "finding_count": len(report.Matches), "package_count": len(packages.Artifacts), "scanner_name": "grype", "scanner_version": report.Descriptor.Version, "duration_seconds": time.Since(started).Seconds()}
	// Preserve database provenance only. Never emit descriptor.configuration:
	// it can contain registry credentials and local environment information.
	var db map[string]any
	if json.Unmarshal(report.Descriptor.DB, &db) == nil {
		for _, key := range []string{"built", "schemaVersion", "checksum"} {
			if v, ok := db[key]; ok {
				fields["vulnerability_db_"+key] = v
			}
		}
	}
	for severity, count := range counts {
		fields[severity+"_count"] = count
	}
	return emit("vulnerability.scan_completed", fields)
}

func packageFields(p packageRecord) Event {
	paths := make([]string, 0, len(p.Locations))
	for _, l := range p.Locations {
		paths = append(paths, l.Path)
	}
	return Event{"package_id": p.ID, "package_name": p.Name, "package_version": p.Version, "package_type": p.Type, "package_purl": p.PURL, "package_paths": paths}
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buf.Len() {
		return 0, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	return b.buf.Write(p)
}

func commandOutput(ctx context.Context, name string, args, extraEnv []string, limit int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	// Keep only transport/cache settings needed by scanners, not arbitrary agent
	// environment variables or scanner options that could suppress findings.
	allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "http_proxy": true, "https_proxy": true, "no_proxy": true, "XDG_CACHE_HOME": true, "DOCKER_CONFIG": true}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if allowed[key] {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C", "LANG=C")
	cmd.Env = append(cmd.Env, extraEnv...)
	out := &limitedBuffer{limit: limit}
	// Discard stderr: scanner errors may contain registry credentials or URLs.
	// The stage, exit status and target identify failures without leaking them.
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return out.buf.Bytes(), nil
}
