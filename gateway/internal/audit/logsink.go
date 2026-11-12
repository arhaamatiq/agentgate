package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
)

// LogSink writes one JSON event per line (stderr in stdio mode, where
// stdout carries the MCP protocol). Useful without Kafka; not chained.
type LogSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewLogSink(w io.Writer) *LogSink { return &LogSink{w: w} }

func (s *LogSink) Record(_ context.Context, ev *Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}

func (s *LogSink) Ready(context.Context) error { return nil }
func (s *LogSink) Close(context.Context) error { return nil }
