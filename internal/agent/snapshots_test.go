package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWeeklySnapshotsKeepDailyFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshots.json")
	schedule, err := loadSnapshotSchedule(path, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{HostID: "host-1", Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", findingsFixture, 0), Timeout: time.Second, snapshots: schedule}
	target := target{Kind: "host", ID: "host-1", Source: "dir:/fixture"}
	run := func(wantInventory bool) {
		t.Helper()
		var b bytes.Buffer
		if err := scan(context.Background(), c, &emitter{writer: &b}, target); err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		rows := events(t, &b)
		for _, row := range rows {
			counts[row["recense.event.type"].(string)]++
		}
		if wantInventory && (counts["software.inventory"] != 2 || counts["software.inventory_completed"] != 1) {
			t.Fatalf("missing full snapshot: %v", counts)
		}
		if !wantInventory && (counts["software.inventory"] != 0 || counts["software.inventory_completed"] != 0) {
			t.Fatalf("repeated snapshot: %v", counts)
		}
		if counts["vulnerability.finding"] != 1 || counts["vulnerability.scan_completed"] != 1 {
			t.Fatalf("daily results missing: %v", counts)
		}
		if !wantInventory {
			for _, row := range rows {
				if row["recense.event.type"] == "vulnerability.finding" && row["recense.vulnerability.id"] != "TEST-NEW" {
					t.Fatal("reused stale CVE results")
				}
			}
		}
		if rows[len(rows)-1]["recense.inventory.snapshot_sent"] != wantInventory {
			t.Fatal("incorrect snapshot summary")
		}
	}
	run(true)
	// A process restart must retain the schedule, but still run both scanners.
	c.snapshots, err = loadSnapshotSchedule(path, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A changed scanner result must appear even while the package snapshot is skipped.
	c.Grype = fakeScanner(t, "grype", strings.ReplaceAll(findingsFixture, "TEST-001", "TEST-NEW"), 0)
	run(false)
	key := snapshotKey(c.HostID, target)
	c.snapshots.sent[key] = time.Now().Add(-7 * 24 * time.Hour)
	run(true)
	// Cache loss must produce a complete replacement snapshot.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.snapshots, err = loadSnapshotSchedule(path, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	run(true)
}

func TestSnapshotScheduleRecoveryAndTargetIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte(`{"broken":`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSnapshotSchedule(path, 7*24*time.Hour)
	if err == nil {
		t.Fatal("accepted corrupt state")
	}
	now := time.Now()
	host := target{Kind: "host", ID: "h"}
	key := snapshotKey("h", host)
	if !s.due(key, now) {
		t.Fatal("corrupt state suppressed snapshot")
	}
	if err := s.record(key, now); err != nil {
		t.Fatal(err)
	}
	if s.due(key, now.Add(24*time.Hour)) || !s.due(key, now.Add(7*24*time.Hour)) {
		t.Fatal("wrong schedule")
	}
	if !s.due(key, now.Add(-time.Hour)) {
		t.Fatal("clock rollback suppressed snapshot")
	}
	if !s.due(snapshotKey("other-host", host), now) || !s.due(snapshotKey("h", target{Kind: "container", ID: "h"}), now) {
		t.Fatal("targets share schedule")
	}
	s.sent["expired"] = now.Add(-8 * 24 * time.Hour)
	if err := s.record(key, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.sent["expired"]; ok {
		t.Fatal("expired container state retained")
	}
}

func TestFailedInventoryDoesNotAdvanceSnapshotSchedule(t *testing.T) {
	s, err := loadSnapshotSchedule(filepath.Join(t.TempDir(), "state"), 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{HostID: "h", Syft: fakeScanner(t, "syft", "oops", 0), Timeout: time.Second, snapshots: s}
	target := target{Kind: "host", ID: "h"}
	var b bytes.Buffer
	if scan(context.Background(), c, &emitter{writer: &b}, target) == nil {
		t.Fatal("accepted invalid inventory")
	}
	if !s.due(snapshotKey("h", target), time.Now()) {
		t.Fatal("failed inventory advanced schedule")
	}
}

func TestScheduleWriteFailureDoesNotSkipCVECheck(t *testing.T) {
	dir := t.TempDir()
	s, err := loadSnapshotSchedule(filepath.Join(dir, "state"), 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// An existing directory cannot be replaced with the state file.
	if err := os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	c := Config{Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", findingsFixture, 0), Timeout: time.Second, snapshots: s}
	if err := scan(context.Background(), c, &emitter{writer: &b}, target{Kind: "host", ID: "h"}); err != nil {
		t.Fatal(err)
	}
	rows := events(t, &b)
	warnings := 0
	for _, r := range rows {
		if r["recense.event.type"] == "agent.error" {
			warnings++
		}
	}
	if warnings != 1 || rows[len(rows)-1]["recense.status"] != "success" {
		t.Fatal("state error hid CVE results")
	}
}

func TestFixAvailabilityFields(t *testing.T) {
	for _, fixed := range []bool{true, false} {
		report := findingsFixture
		if !fixed {
			report = strings.Replace(report, `"versions":["1.1"]`, `"versions":[]`, 1)
		}
		var b bytes.Buffer
		c := Config{Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", report, 0), Timeout: time.Second}
		if err := scan(context.Background(), c, &emitter{writer: &b}, target{Kind: "host", ID: "h"}); err != nil {
			t.Fatal(err)
		}
		rows := events(t, &b)
		for _, r := range rows {
			if r["recense.event.type"] == "vulnerability.finding" && r["recense.vulnerability.fix.available"] != fixed {
				t.Fatal("wrong fix availability")
			}
		}
		want := float64(0)
		if fixed {
			want = 1
		}
		if rows[len(rows)-1]["recense.vulnerability.fix_available_count"] != want {
			t.Fatal("wrong fix count")
		}
	}
}
