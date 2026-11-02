package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type container struct{ ID, Name, ImageID, ImageName, PodName, PodNamespace, PodContainer string }

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
		result = append(result, container{ID: r.ID, Name: name, ImageID: r.ImageID, ImageName: r.Image})
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
		image := ""
		if r.Image != nil {
			image = r.Image.Image
		}
		// CRI imageRef can be a config digest. Resolve it to a repository digest
		// known to containerd's image store so Syft can open it without pulling tags.
		status, err := cri.NewImageServiceClient(conn).ImageStatus(ctx, &cri.ImageStatusRequest{Image: &cri.ImageSpec{Image: r.ImageRef}})
		if err != nil {
			return nil, fmt.Errorf("CRI image status: %w", err)
		}
		if status.Image == nil || len(status.Image.RepoDigests) == 0 {
			return nil, fmt.Errorf("CRI image %s has no repository digest", r.ImageRef)
		}
		result = append(result, container{ID: r.Id, Name: name, ImageID: status.Image.RepoDigests[0], ImageName: image, PodName: r.Labels["io.kubernetes.pod.name"], PodNamespace: r.Labels["io.kubernetes.pod.namespace"], PodContainer: name})
	}
	return result, nil
}
