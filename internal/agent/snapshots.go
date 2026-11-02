package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// This is a disposable emission schedule, not an inventory or delivery receipt.
// Missing or invalid state causes extra full snapshots, never skipped CVE scans.
type snapshotSchedule struct {
	path     string
	interval time.Duration
	sent     map[string]time.Time
}

func loadSnapshotSchedule(path string, interval time.Duration) (*snapshotSchedule, error) {
	s := &snapshotSchedule{path: path, interval: interval, sent: map[string]time.Time{}}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return s, err
	}
	if len(data) > 4<<20 {
		return s, fmt.Errorf("inventory schedule exceeds 4 MiB")
	}
	var sent map[string]time.Time
	if err := json.Unmarshal(data, &sent); err != nil {
		return s, err
	}
	if sent != nil {
		s.sent = sent
	}
	return s, nil
}

func snapshotKey(host string, t target) string {
	sum := sha256.Sum256([]byte(host + "\x00" + t.Kind + "\x00" + t.ID))
	return hex.EncodeToString(sum[:])
}

func (s *snapshotSchedule) due(key string, now time.Time) bool {
	last, ok := s.sent[key]
	return !ok || last.After(now) || now.Sub(last) >= s.interval
}

func (s *snapshotSchedule) record(key string, now time.Time) error {
	// Drop expired and future entries to bound state under container churn and
	// recover conservatively from clock changes.
	for k, last := range s.sent {
		if last.After(now) || now.Sub(last) >= s.interval {
			delete(s.sent, k)
		}
	}
	s.sent[key] = now
	data, err := json.Marshal(s.sent)
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return fmt.Errorf("inventory schedule exceeds 4 MiB")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".inventory-snapshots-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.path)
}
