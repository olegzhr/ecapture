package handlers

import (
	"errors"
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"testing"
)

type structuredEvent struct {
	mockTLSDataEvent
	module bool
}

func (e *structuredEvent) ToProtobufEvent() *pb.Event {
	return &pb.Event{Pid: 7, SrcIp: "192.0.2.7", SrcPort: 12345, DstIp: "192.0.2.20", DstPort: 443}
}
func (e *structuredEvent) Type() domain.EventType {
	if e.module {
		return domain.EventTypeModuleData
	}
	return domain.EventTypeOutput
}

type structuredWriter struct {
	event *pb.Event
	fail  bool
	calls int
}

func (w *structuredWriter) Write(data []byte) (int, error) {
	return 0, errors.New("unexpected text fallback")
}
func (w *structuredWriter) WriteProtobufEvent(event *pb.Event) (bool, error) {
	w.calls++
	w.event = event
	if w.fail {
		return true, errors.New("queue full")
	}
	return true, nil
}

func TestStructuredEventThroughProductionAdapter(t *testing.T) {
	e := &structuredEvent{mockTLSDataEvent: mockTLSDataEvent{data: []byte("GET / HTTP/1.1\r\n\r\n")}}
	w := new(structuredWriter)
	h := NewTextHandler(writers.NewIOWriterAdapter(w, "ecaptureQ"), false)
	if err := h.Handle(e); err != nil {
		t.Fatal(err)
	}
	if w.calls != 1 || w.event.SrcPort != 12345 || w.event.Pid != 7 || int(w.event.Length) != len(w.event.Payload) {
		t.Fatal(w.event)
	}
	w.fail = true
	if h.Handle(e) == nil {
		t.Fatal("structured delivery failure swallowed")
	}
	e.module = true
	w.fail = false
	if err := h.Handle(e); err != nil || w.event != nil {
		t.Fatal("lifecycle metadata must not overwrite socket snapshot", err)
	}
	// A plain writer still receives the original text via the same adapter.
	plain := newMockWriter()
	h = NewTextHandler(writers.NewIOWriterAdapter(plain, "file"), false)
	e.module = false
	if err := h.Handle(e); err != nil || plain.Len() == 0 {
		t.Fatal("plain output changed", err)
	}
}
