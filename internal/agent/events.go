package agent

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Event map[string]any

type emitter struct {
	mu     sync.Mutex
	output string
	writer io.Writer
	base   Event
}

// Open the output on each write so logrotate can rename it without losing events.
func (e *emitter) emit(kind string, fields Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	event := Event{}
	for k, v := range e.base {
		event[k] = v
	}
	for k, v := range fields {
		event[k] = v
	}
	event["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	event["recense.event.type"] = kind
	event["recense.schema.version"] = 3
	event["service.name"] = "recense"
	w := e.writer
	if e.output != "" {
		f, err := os.OpenFile(e.output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	return json.NewEncoder(w).Encode(event)
}
