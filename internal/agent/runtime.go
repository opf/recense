package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var errContainerStopped = errors.New("container is no longer running")

type container struct {
	ID, Name, ImageID, ImageName, PodName, PodNamespace, PodContainer string
	PID                                                               int
}

func discover(ctx context.Context, c Config) ([]container, string, string, error) {
	if c.Runtime == "none" {
		return nil, "none", "", nil
	}
	name, socket := c.Runtime, c.Socket
	if name == "auto" {
		if socket != "" {
			return nil, "", "", fmt.Errorf("--socket requires an explicit --runtime")
		}
		for _, candidate := range []struct{ name, path string }{{"docker", "/var/run/docker.sock"}, {"containerd", "/run/containerd/containerd.sock"}} {
			if _, err := os.Stat(candidate.path); err == nil {
				name = candidate.name
				socket = candidate.path
				break
			} else if !os.IsNotExist(err) {
				return nil, "", "", fmt.Errorf("inspect runtime socket %s: %w", candidate.path, err)
			}
		}
		if name == "auto" {
			return nil, "none", "", nil
		}
	}
	if socket == "" {
		if name == "docker" {
			socket = "/var/run/docker.sock"
		} else {
			socket = "/run/containerd/containerd.sock"
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var containers []container
	var err error
	if name == "docker" {
		containers, err = dockerContainers(ctx, socket)
	} else {
		containers, err = criContainers(ctx, socket)
	}
	return containers, name, socket, err
}

func dockerContainers(ctx context.Context, socket string) ([]container, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/json?all=false", nil)
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Docker discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker discovery returned HTTP %d", response.StatusCode)
	}
	var rows []struct {
		ID             string `json:"Id"`
		Names          []string
		Image, ImageID string
		Labels         map[string]string
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&rows); err != nil {
		return nil, err
	}
	result := make([]container, 0, len(rows))
	for _, r := range rows {
		name := ""
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		if r.ImageID == "" {
			return nil, fmt.Errorf("Docker container %s has no immutable image ID", r.ID)
		}
		pid, err := dockerPID(ctx, client, r.ID)
		if errors.Is(err, errContainerStopped) {
			continue
		}
		if err != nil {
			return nil, err
		}

		result = append(result, container{ID: r.ID, Name: name, ImageID: r.ImageID, ImageName: r.Image, PID: pid})
	}
	return result, nil
}

func criContainers(ctx context.Context, socket string) ([]container, error) {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	response, err := cri.NewRuntimeServiceClient(conn).ListContainers(ctx, &cri.ListContainersRequest{Filter: &cri.ContainerFilter{State: &cri.ContainerStateValue{State: cri.ContainerState_CONTAINER_RUNNING}}})
	if err != nil {
		return nil, fmt.Errorf("CRI discovery: %w", err)
	}
	result := make([]container, 0, len(response.Containers))
	for _, r := range response.Containers {
		if r.ImageRef == "" {
			return nil, fmt.Errorf("CRI container %s has no image reference", r.Id)
		}
		name := ""
		if r.Metadata != nil {
			name = r.Metadata.Name
		}
		pid, err := criPID(ctx, cri.NewRuntimeServiceClient(conn), r.Id)
		if errors.Is(err, errContainerStopped) {
			continue
		}
		if err != nil {
			return nil, err
		}

		result = append(result, container{ID: r.Id, Name: name, ImageID: r.ImageRef, ImageName: r.GetImage().GetImage(), PID: pid, PodName: r.Labels["io.kubernetes.pod.name"], PodNamespace: r.Labels["io.kubernetes.pod.namespace"], PodContainer: name})
	}
	return result, nil
}

func dockerPID(ctx context.Context, client *http.Client, id string) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/"+id+"/json", nil)
	response, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Docker container inspection: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return 0, errContainerStopped
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Docker inspection returned HTTP %d", response.StatusCode)
	}
	var status struct {
		State struct {
			Pid     int
			Running bool
		}
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&status); err != nil {
		return 0, err
	}
	if !status.State.Running || status.State.Pid <= 1 {
		return 0, errContainerStopped
	}
	return status.State.Pid, nil
}

func criPID(ctx context.Context, client cri.RuntimeServiceClient, id string) (int, error) {
	response, err := client.ContainerStatus(ctx, &cri.ContainerStatusRequest{ContainerId: id, Verbose: true})
	if status.Code(err) == codes.NotFound {
		return 0, errContainerStopped
	}
	if err != nil {
		return 0, fmt.Errorf("CRI container status: %w", err)
	}
	if response.Status == nil || response.Status.State != cri.ContainerState_CONTAINER_RUNNING {
		return 0, errContainerStopped
	}
	// Runtime info may contain environment secrets; decode only the PID.
	var info struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal([]byte(response.Info["info"]), &info); err != nil {
		return 0, fmt.Errorf("invalid CRI process metadata")
	}
	if info.PID <= 1 {
		return 0, fmt.Errorf("runtime did not provide a running container PID")
	}
	return info.PID, nil
}

// Runtime identity must still match at scan time, even if the discovered PID
// was reused while earlier containers were being scanned.
func validateContainerProcess(ctx context.Context, runtime, socket, id string, expectedPID int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var pid int
	var err error
	if runtime == "docker" {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
		defer transport.CloseIdleConnections()
		pid, err = dockerPID(ctx, &http.Client{Transport: transport}, id)
	} else {
		conn, connectErr := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if connectErr != nil {
			return connectErr
		}
		defer conn.Close()
		pid, err = criPID(ctx, cri.NewRuntimeServiceClient(conn), id)
	}
	if err != nil {
		return err
	}
	if pid != expectedPID {
		return fmt.Errorf("container process changed since discovery")
	}
	return nil
}
