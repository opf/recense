package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Root, Runtime, Socket, HostID, HostName, Environment, Cluster string
	Syft, Grype, Output, Version                                  string
	Interval, Timeout, Jitter                                     time.Duration
	Once                                                          bool
	InventoryInterval                                             time.Duration
	StateFile                                                     string
	snapshots                                                     *snapshotSchedule
}

func Run(ctx context.Context, c Config) error {
	if c.Interval <= 0 || c.Timeout <= 0 || c.InventoryInterval <= 0 || c.Jitter < 0 {
		return errors.New("interval, inventory-interval and scan-timeout must be positive; jitter must be nonnegative")
	}
	switch c.Runtime {
	case "auto", "none", "docker", "containerd":
	default:
		return fmt.Errorf("invalid runtime %q", c.Runtime)
	}
	root, err := filepath.Abs(c.Root)
	if err != nil {
		return err
	}
	c.Root = root
	host, err := hostInventory(c)
	if err != nil {
		return err
	}
	c.HostID = host["host_id"].(string)
	e := &emitter{output: c.Output, writer: os.Stdout, base: Event{
		"host_id": c.HostID, "host_name": host["host_name"], "agent_version": c.Version,
		"environment": c.Environment, "k8s_cluster_name": c.Cluster,
	}}
	c.snapshots, err = loadSnapshotSchedule(c.StateFile, c.InventoryInterval)
	if err != nil {
		if emitErr := e.emit("agent.error", Event{"error": "inventory schedule could not be loaded; full snapshots will be sent", "stage": "inventory_schedule"}); emitErr != nil {
			return emitErr
		}
	}
	// Heartbeats continue during long scans, but do not imply that scans succeeded.
	heartbeatCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatErr := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if err := e.emit("agent.heartbeat", nil); err != nil {
					heartbeatErr <- err
					cancel()
					return
				}
			}
		}
	}()
	if err := e.emit("agent.heartbeat", nil); err != nil {
		return err
	}
	delay := func(duration time.Duration) error {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-heartbeatErr:
			return err
		case <-timer.C:
			return nil
		}
	}
	jitter := func() time.Duration {
		if c.Jitter == 0 {
			return 0
		}
		return time.Duration(mathrand.Int64N(int64(c.Jitter)))
	}
	if !c.Once {
		if err := delay(jitter()); err != nil {
			return err
		}
	}
	for {
		err := cycle(heartbeatCtx, c, e)
		if c.Once {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		select {
		case err := <-heartbeatErr:
			return err
		default:
		}
		if err != nil {
			if emitErr := e.emit("agent.error", Event{"error": err.Error()}); emitErr != nil {
				return emitErr
			}
		}
		if err := delay(c.Interval + jitter()); err != nil {
			return err
		}
	}
}

func cycle(ctx context.Context, c Config, e *emitter) error {
	id, err := newID()
	if err != nil {
		return err
	}
	var failures []error
	host, err := hostInventory(c)
	if err != nil {
		return err
	}
	host["collection_id"] = id
	if err := e.emit("host.inventory", host); err != nil {
		return err
	}
	updates := checkUpdates(ctx, c)
	updates["collection_id"] = id
	if err := e.emit("host.updates", updates); err != nil {
		return err
	}
	if updates["status"] == "failed" {
		failures = append(failures, errors.New("update check failed"))
	}

	if err := scan(ctx, c, e, target{Kind: "host", ID: c.HostID, Source: "dir:" + c.Root}); err != nil {
		failures = append(failures, err)
	}
	containers, runtimeName, socket, err := discover(ctx, c)
	if err != nil {
		failures = append(failures, err)
		if emitErr := e.emit("container.discovery_completed", Event{"collection_id": id, "status": "failed", "error": err.Error()}); emitErr != nil {
			return emitErr
		}
	} else {
		for _, container := range containers {
			event := Event{"collection_id": id, "container_id": container.ID, "container_name": container.Name,
				"image_id": container.ImageID, "image_name": container.ImageName, "container_runtime": runtimeName,
				"k8s_namespace_name": container.PodNamespace, "k8s_pod_name": container.PodName, "k8s_container_name": container.PodContainer}
			if err := e.emit("container.inventory", event); err != nil {
				return err
			}
		}
		if err := e.emit("container.discovery_completed", Event{"collection_id": id, "status": "success", "container_runtime": runtimeName, "container_count": len(containers)}); err != nil {
			return err
		}
		for _, container := range containers {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			t := target{Kind: "container", ID: container.ID}
			root, exclusions, validate, rootErr := containerFilesystem(c.Root, container.PID)
			if rootErr != nil {
				t.Validate = func() error { return rootErr }
			} else {
				t.Source = "dir:" + root
				t.Excludes = exclusions
				t.Validate = func() error {
					if err := validateContainerProcess(ctx, runtimeName, socket, container.ID, container.PID); err != nil {
						return err
					}
					return validate()
				}
			}
			if err := scan(ctx, c, e, t); err != nil {
				failures = append(failures, err)
			}
		}
	}
	status := "success"
	if len(failures) > 0 {
		status = "failed"
	}
	if err := e.emit("agent.collection_completed", Event{"collection_id": id, "status": status, "failure_count": len(failures)}); err != nil {
		return err
	}
	return errors.Join(failures...)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
