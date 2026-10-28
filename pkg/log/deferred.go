package log

import (
	"context"
	"log/slog"
	"slices"
	"sync"
)

func init() {
	// Set the default logger so that logs are buffered until the logger is initialized.
	slog.SetDefault(New(&DeferredHandler{state: &deferredState{}}))
}

// DeferredHandler is needed to save logs and print them after calling `PrintLogs()` command.
// For example, this may be necessary when the logger is not yet initialized, but messages need to be transmitted.
// In this case, the messages are saved and printed when the logger is initialized.
type DeferredHandler struct {
	attrs []slog.Attr

	// Shared with all instances of the handler.
	state *deferredState
}

type deferredState struct {
	mu      sync.Mutex
	records []deferredRecord
	handler slog.Handler
}

type deferredRecord struct {
	ctx context.Context
	slog.Record
}

func (*DeferredHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (d *DeferredHandler) Handle(ctx context.Context, record slog.Record) error {
	record = record.Clone()
	record.AddAttrs(d.attrs...)

	d.state.mu.Lock()
	if h := d.state.handler; h != nil {
		d.state.mu.Unlock()
		if h.Enabled(ctx, record.Level) {
			return h.Handle(ctx, record)
		}
		return nil
	}
	d.state.records = append(d.state.records, deferredRecord{
		ctx:    ctx,
		Record: record,
	})
	d.state.mu.Unlock()
	return nil
}

func (d *DeferredHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h := *d
	h.attrs = slices.Clip(d.attrs)
	h.attrs = append(h.attrs, attrs...)
	return &h
}

func (*DeferredHandler) WithGroup(_ string) slog.Handler {
	panic("WithGroup is not implemented")
}

func (d *DeferredHandler) Flush(h slog.Handler) {
	d.state.mu.Lock()
	records := d.state.records
	d.state.records = nil
	// Existing loggers may still hold this handler after SetDefault.
	d.state.handler = h
	d.state.mu.Unlock()

	for _, record := range records {
		if !h.Enabled(record.ctx, record.Level) {
			continue
		}
		_ = h.Handle(record.ctx, record.Record)
	}
}
