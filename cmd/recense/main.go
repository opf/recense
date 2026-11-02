package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opf/recense/internal/agent"
)

var version = "dev"

func main() {
	c := agent.Config{}
	flag.StringVar(&c.Root, "root", "/", "host filesystem root (use /host in Kubernetes)")
	flag.StringVar(&c.Runtime, "runtime", "auto", "container runtime: auto, none, docker, containerd")
	flag.StringVar(&c.Socket, "socket", "", "runtime Unix socket (auto detects standard paths)")
	flag.StringVar(&c.HostID, "host-id", os.Getenv("RECENSE_HOST_ID"), "stable host ID (defaults to host machine-id)")
	flag.StringVar(&c.HostName, "host-name", os.Getenv("RECENSE_HOST_NAME"), "host name (defaults to host hostname)")
	flag.StringVar(&c.Environment, "environment", os.Getenv("RECENSE_ENVIRONMENT"), "environment label")
	flag.StringVar(&c.Cluster, "cluster", os.Getenv("RECENSE_CLUSTER"), "Kubernetes cluster name")
	flag.StringVar(&c.Syft, "syft", "syft", "Syft executable")
	flag.StringVar(&c.Grype, "grype", "grype", "Grype executable")
	flag.StringVar(&c.Output, "output", "", "append JSON Lines to this file instead of stdout")
	flag.DurationVar(&c.Interval, "interval", 24*time.Hour, "time between completed collection cycles")
	flag.DurationVar(&c.InventoryInterval, "inventory-interval", 7*24*time.Hour, "minimum time between full package snapshots per target")
	flag.StringVar(&c.StateFile, "state-file", "/var/lib/recense/inventory-snapshots.json", "disposable inventory schedule file; loss triggers fresh snapshots")
	flag.DurationVar(&c.Timeout, "scan-timeout", 45*time.Minute, "timeout per scanner invocation")
	flag.DurationVar(&c.Jitter, "jitter", 15*time.Minute, "maximum random delay before startup and each cycle")
	flag.BoolVar(&c.Once, "once", false, "collect once and exit; nonzero on collection failure")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	c.Version = version
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agent.Run(ctx, c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
