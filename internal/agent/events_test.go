package agent

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestNamespacedScanFieldsIdentifyTarget(t *testing.T) {
	var b bytes.Buffer
	c := Config{Syft: fakeScanner(t, "syft", inventoryFixture, 0), Grype: fakeScanner(t, "grype", findingsFixture, 0), Timeout: time.Second}
	fields := containerFields(container{ID: "app-id", Name: "app", PodName: "app-pod", PodNamespace: "production"}, "containerd")
	e := &emitter{writer: &b, base: Event{"host.id": "node-id", "host.name": "node-name", "service.version": "test", "deployment.environment.name": "edge", "k8s.cluster.name": "cluster"}}
	if err := scan(context.Background(), c, e, target{Kind: "container", ID: "app-id", Fields: fields}); err != nil {
		t.Fatal(err)
	}
	standard := map[string]bool{"timestamp": true, "service.name": true, "service.version": true, "host.id": true, "host.name": true, "deployment.environment.name": true, "k8s.cluster.name": true}
	for _, row := range events(t, &b) {
		for key := range row {
			if !standard[key] && !strings.HasPrefix(key, "recense.") {
				t.Fatalf("unnamespaced custom field %q", key)
			}
		}
		if row["recense.schema.version"] != float64(3) || row["recense.target.k8s.namespace.name"] != "production" || row["recense.target.container.id"] != "app-id" {
			t.Fatalf("wrong target schema: %#v", row)
		}
		if _, ok := row["k8s.pod.name"]; ok {
			t.Fatal("scanned pod confused with emitter resource")
		}
	}
}
