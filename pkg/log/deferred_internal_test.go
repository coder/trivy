package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeferredHandler(t *testing.T) {
	t.Parallel()

	handler := &DeferredHandler{state: &deferredState{}}
	logger := slog.New(handler)
	const workers = 32
	const messages = 32
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			child := logger.With("worker", worker)
			for message := range messages {
				child.Info("buffered", "message", message)
			}
		})
	}
	wg.Wait()

	var output bytes.Buffer
	target := slog.NewJSONHandler(&output, nil)
	handler.Flush(target)

	// Loggers obtained before initialization must keep delivering records.
	logger.With("worker", workers).Info("after flush", "message", 0)
	logger.Debug("disabled")
	handler.Flush(target)

	decoder := json.NewDecoder(&output)
	seen := make(map[[2]int]bool)
	for decoder.More() {
		var record struct {
			Worker  int `json:"worker"`
			Message int `json:"message"`
		}
		require.NoError(t, decoder.Decode(&record))
		key := [2]int{record.Worker, record.Message}
		require.False(t, seen[key], "duplicate record: %v", key)
		seen[key] = true
	}
	require.Len(t, seen, workers*messages+1)
}

func TestDeferredHandlerConcurrentFlush(t *testing.T) {
	t.Parallel()

	handler := &DeferredHandler{state: &deferredState{}}
	logger := slog.New(handler).With("key", "value")
	var output bytes.Buffer
	target := slog.NewJSONHandler(&output, nil)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 100 {
			logger.Info("message")
		}
	})
	wg.Go(func() {
		<-start
		handler.Flush(target)
	})
	close(start)
	wg.Wait()

	decoder := json.NewDecoder(&output)
	var count int
	for decoder.More() {
		var record map[string]any
		require.NoError(t, decoder.Decode(&record))
		require.Equal(t, "value", record["key"])
		count++
	}
	require.Equal(t, 100, count)
}
