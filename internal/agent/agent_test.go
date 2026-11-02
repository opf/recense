package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func fixtureHost(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, value := range map[string]string{"usr/lib/os-release": "ID=ubuntu\nNAME=\"Ubuntu Linux\"\nVERSION_ID=\"24.04\"\n", "etc/machine-id": "machine-123\n", "etc/hostname": "worker-1\n", "proc/sys/kernel/osrelease": "6.8.0-test\n"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestHostInventoryUsesMountedHost(t *testing.T) {
	root := fixtureHost(t)
	event, err := hostInventory(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if event["host_id"] != "machine-123" || event["kernel_release"] != "6.8.0-test" || event["os_name"] != "Ubuntu Linux" {
		t.Fatalf("wrong host: %#v", event)
	}
	if got := checkUpdates(context.Background(), Config{Root: root}); got["status"] != "unsupported" {
		t.Fatalf("must not query agent OS: %#v", got)
	}
}
func fakeScanner(t *testing.T, name, output string, exit int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\ncat <<'REPORT'\n" + output + "\nREPORT\nexit " + string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}
func events(t *testing.T, b *bytes.Buffer) []Event {
	t.Helper()
	var rows []Event
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, e)
	}
	return rows
}

const inventoryFixture = `{"artifacts":[{"id":"pkg1","name":"openssl","version":"1.0","type":"deb","purl":"pkg:deb/ubuntu/openssl@1.0","locations":[{"path":"/var/lib/dpkg/status"}]},{"id":"pkg2","name":"safe-package","version":"2.0","type":"deb"}]}`
const findingsFixture = `{"matches":[{"artifact":{"id":"pkg1","name":"openssl","version":"1.0","type":"deb"},"vulnerability":{"id":"TEST-001","namespace":"ubuntu:test","severity":"High","fix":{"state":"fixed","versions":["1.1"]}}}],"descriptor":{"version":"test","configuration":{"password":"secret-never-emit"},"db":{"status":{"built":"2026-01-01T00:00:00Z","schemaVersion":"v6.1.10","valid":true}}}}`

func TestScanInventoryFindingsAndCompletion(t *testing.T) {
	var b bytes.Buffer
	e := &emitter{writer: &b, base: Event{"host_id": "host-1"}}
	c := Config{Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", findingsFixture, 0), Timeout: time.Second, Root: "/"}
	if err := scan(context.Background(), c, e, target{Kind: "host", ID: "host-1", Source: "dir:/fixture"}); err != nil {
		t.Fatal(err)
	}
	rows := events(t, &b)
	if len(rows) != 5 {
		t.Fatalf("got %d events: %#v", len(rows), rows)
	}
	if rows[1]["package_name"] != "safe-package" {
		t.Fatal("inventory omitted a package without vulnerabilities")
	}
	final := rows[len(rows)-1]
	if final["vulnerability_db_built_at"] != "2026-01-01T00:00:00Z" {
		t.Fatal("missing database provenance")
	}
	if final["status"] != "success" || final["high_count"] != float64(1) || final["finding_count"] != float64(1) {
		t.Fatalf("bad completion: %#v", final)
	}
	for _, e := range rows {
		if e["scan_id"] != final["scan_id"] {
			t.Fatal("inconsistent scan IDs")
		}
	}
	if strings.Contains(b.String(), "secret-never-emit") {
		t.Fatal("scanner config leaked")
	}
}
func TestScanFailuresNeverReportClean(t *testing.T) {
	for _, tc := range []struct {
		name, report string
		exit         int
	}{{"command failure", `{"matches":[]}`, 1}, {"invalid JSON", `oops`, 0}, {"missing matches", `{}`, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			e := &emitter{writer: &b}
			c := Config{Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", tc.report, tc.exit), Timeout: time.Second}
			if err := scan(context.Background(), c, e, target{Kind: "host", ID: "host-1", Source: "dir:/fixture"}); err == nil {
				t.Fatal("expected failure")
			}
			rows := events(t, &b)
			last := rows[len(rows)-1]
			if last["status"] != "failed" {
				t.Fatalf("bad status: %#v", last)
			}
			if _, ok := last["finding_count"]; ok {
				t.Fatal("failure reported a finding count")
			}
		})
	}
}
func TestEmptySuccessfulScan(t *testing.T) {
	var b bytes.Buffer
	e := &emitter{writer: &b}
	c := Config{Syft: fakeScanner(t, "syft", `{"artifacts":[]}`, 0), Grype: fakeScanner(t, "grype", `{"matches":[]}`, 0), Timeout: time.Second}
	if err := scan(context.Background(), c, e, target{Kind: "container_image", ID: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	rows := events(t, &b)
	last := rows[len(rows)-1]
	if last["status"] != "success" || last["finding_count"] != float64(0) {
		t.Fatalf("missing clean result: %#v", last)
	}
}
func TestCommandOutputBoundAndTimeout(t *testing.T) {
	if _, err := commandOutput(context.Background(), fakeScanner(t, "large", strings.Repeat("x", 100), 0), nil, nil, 10); err == nil {
		t.Fatal("output cap ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := commandOutput(ctx, "sh", []string{"-c", "sleep 10"}, nil, 10); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestDockerDiscovery(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" || r.URL.Query().Get("all") != "false" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		_, _ = w.Write([]byte(`[{"Id":"c1","Names":["/app"],"Image":"app:latest","ImageID":"sha256:abc"}]`))
	})}
	go server.Serve(listener)
	defer server.Close()
	rows, err := dockerContainers(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ImageID != "sha256:abc" || rows[0].Name != "app" {
		t.Fatalf("bad discovery: %#v", rows)
	}
}

type criFixture struct {
	cri.UnimplementedRuntimeServiceServer
	cri.UnimplementedImageServiceServer
}

func (f *criFixture) ListContainers(_ context.Context, r *cri.ListContainersRequest) (*cri.ListContainersResponse, error) {
	if r.Filter.State.State != cri.ContainerState_CONTAINER_RUNNING {
		panic("wrong filter")
	}
	return &cri.ListContainersResponse{Containers: []*cri.Container{{Id: "c1", ImageRef: "sha256:config", Image: &cri.ImageSpec{Image: "app:latest"}, Metadata: &cri.ContainerMetadata{Name: "api"}, Labels: map[string]string{"io.kubernetes.pod.name": "api-123", "io.kubernetes.pod.namespace": "prod"}}}}, nil
}
func (f *criFixture) ImageStatus(_ context.Context, _ *cri.ImageStatusRequest) (*cri.ImageStatusResponse, error) {
	return &cri.ImageStatusResponse{Image: &cri.Image{RepoDigests: []string{"registry/app@sha256:manifest"}}}, nil
}
func TestCRIDiscoveryResolvesDigest(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fixture := &criFixture{}
	cri.RegisterRuntimeServiceServer(server, fixture)
	cri.RegisterImageServiceServer(server, fixture)
	go server.Serve(listener)
	defer server.Stop()
	rows, err := criContainers(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ImageID != "registry/app@sha256:manifest" || rows[0].PodNamespace != "prod" {
		t.Fatalf("bad discovery: %#v", rows)
	}
}
func TestEmitterReopensRotatedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	e := &emitter{output: path}
	if err := e.emit("first", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := e.emit("second", nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "second") || strings.Contains(string(b), "first") {
		t.Fatalf("wrong log: %s", b)
	}
}

func TestHostAbsoluteSymlinksDoNotReadAgentFilesystem(t *testing.T) {
	root := fixtureHost(t)
	if err := os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run", filepath.Join(root, "var/run")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "run/reboot-required"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	event, err := hostInventory(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if event["reboot_required"] != true || event["os_version"] != "24.04" {
		t.Fatalf("read agent filesystem: %#v", event)
	}
}
