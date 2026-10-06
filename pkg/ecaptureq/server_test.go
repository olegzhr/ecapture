package ecaptureq

import (
	"bytes"
	"fmt"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testClient(capacity int) *Client {
	return &Client{send: make(chan []byte, capacity), done: make(chan struct{})}
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func TestHubIdleBurstFIFOAndOwnership(t *testing.T) {
	h := newHub()
	c := testClient(2048)
	h.addClient(c, nil)
	// No worker ready: the former unbuffered/default implementation lost all.
	for i := 0; i < 300; i++ {
		data := []byte(fmt.Sprint(i))
		if err := h.broadcastMessage(data); err != nil {
			t.Fatal(err)
		}
		data[0] = 'x'
	}
	go h.run()
	defer h.close()
	for i := 0; i < 300; i++ {
		select {
		case msg := <-c.send:
			h.consumed(c, msg)
			if string(msg) != fmt.Sprint(i) {
				t.Fatalf("message %d: %q", i, msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("lost queued event")
		}
	}
	if stats := h.snapshot(); stats.Accepted != 300 || stats.QueueFull != 0 || stats.QueuedBytes != 0 {
		t.Fatal(stats)
	}
}

func TestHubCountAndByteBudgets(t *testing.T) {
	for _, byBytes := range []bool{false, true} {
		h := newHub()
		h.addClient(testClient(2048), nil)
		data := []byte("x")
		count := hubQueueMessages
		if byBytes {
			data = bytes.Repeat(data, 3<<20)
			count = 2
		}
		for i := 0; i < count; i++ {
			if err := h.broadcastMessage(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.broadcastMessage(data); err == nil {
			t.Fatal("overload silently accepted")
		}
		if stats := h.snapshot(); stats.QueueFull != 1 || stats.QueuedBytes > queueBytes {
			t.Fatal(stats)
		}
		go h.run()
		h.close()
		if stats := h.snapshot(); stats.QueuedBytes != 0 {
			t.Fatal(stats)
		}
	}
}

func TestSlowSubscriberDoesNotDamageOtherSubscriber(t *testing.T) {
	h := newHub()
	slow := testClient(2)
	fast := testClient(10)
	h.addClient(slow, nil)
	h.addClient(fast, nil)
	for i := 0; i < 3; i++ {
		if err := h.broadcastMessage([]byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	go h.run()
	defer h.close()
	waitFor(t, func() bool { return h.snapshot().SlowClients == 1 })
	select {
	case <-slow.done:
	default:
		t.Fatal("slow subscriber not disconnected")
	}
	for i := 0; i < 3; i++ {
		msg := <-fast.send
		h.consumed(fast, msg)
		if string(msg) != fmt.Sprint(i) {
			t.Fatal(string(msg))
		}
	}
}

func TestAdmissionRejections(t *testing.T) {
	s := NewServer("127.0.0.1:0", io.Discard)
	if n, err := s.WriteEvent([]byte("no subscriber")); n != 0 || err == nil {
		t.Fatal(n, err)
	}
	if n, err := s.WriteEvent(make([]byte, maxMessageBytes)); n != 0 || err == nil {
		t.Fatal(n, err)
	}
	if stats := s.Stats(); stats.NoSubscribers != 1 || stats.Oversized != 1 {
		t.Fatal(stats)
	}
	s.Close()
	s.Close()
	if _, err := s.WriteEvent([]byte("closed")); err == nil {
		t.Fatal("closed server accepted event")
	}
	if _, err := s.WriteLog([]byte("closed")); err == nil {
		t.Fatal("closed server accepted log")
	}
}

func openTestSocket(t *testing.T, s *Server) (*websocket.Conn, *httptest.Server) {
	t.Helper()
	httpServer := httptest.NewServer(websocket.Handler(s.handleWebSocket))
	conn, err := websocket.Dial("ws"+strings.TrimPrefix(httpServer.URL, "http"), "", httpServer.URL)
	if err != nil {
		httpServer.Close()
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return conn, httpServer
}

func readEntry(t *testing.T, conn *websocket.Conn) *pb.LogEntry {
	t.Helper()
	var data []byte
	if err := websocket.Message.Receive(conn, &data); err != nil {
		t.Fatal(err)
	}
	entry := new(pb.LogEntry)
	if err := proto.Unmarshal(data, entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestWebSocketBurstAndReconnect(t *testing.T) {
	s := NewServer("127.0.0.1:0", io.Discard)
	defer s.Close()
	conn, server := openTestSocket(t, s)
	defer server.Close()
	defer conn.Close()
	if e := readEntry(t, conn); e.GetHeartbeatPayload() == nil {
		t.Fatal("initial heartbeat missing")
	}
	for i := 0; i < 300; i++ {
		if _, err := s.WriteEvent([]byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 300; i++ {
		e := readEntry(t, conn).GetEventPayload()
		if e == nil || string(e.Payload) != fmt.Sprint(i) || int(e.Length) != len(e.Payload) {
			t.Fatalf("event %d: %v", i, e)
		}
	}
	conn.Close()
	waitFor(t, func() bool { return s.Stats().Clients == 0 })
	conn2, server2 := openTestSocket(t, s)
	defer conn2.Close()
	defer server2.Close()
	readEntry(t, conn2)
	if _, err := s.WriteEvent([]byte("after reconnect")); err != nil {
		t.Fatal(err)
	}
	if e := readEntry(t, conn2).GetEventPayload(); string(e.Payload) != "after reconnect" {
		t.Fatal(e)
	}
}

func TestHistoryIsBoundedAndLiveLogsAreNotWithheld(t *testing.T) {
	s := NewServer("127.0.0.1:0", io.Discard)
	defer s.Close()
	for i := 0; i < 140; i++ {
		if _, err := s.WriteLog([]byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.logbuff) != LogBuffLen || s.logBytes > logBuffBytes {
		t.Fatal("unbounded history")
	}
	conn, server := openTestSocket(t, s)
	defer conn.Close()
	defer server.Close()
	readEntry(t, conn) // heartbeat
	for i := 12; i < 140; i++ {
		if e := readEntry(t, conn); e.GetRunLog() != fmt.Sprint(i) {
			t.Fatal(e)
		}
	}
	if _, err := s.WriteLog([]byte("live")); err != nil {
		t.Fatal(err)
	}
	if e := readEntry(t, conn); e.GetRunLog() != "live" {
		t.Fatal(e)
	}
	// A joining subscriber must not receive pending live logs twice via history.
}

func TestConcurrentLogsEventsAndClose(t *testing.T) {
	s := NewServer("127.0.0.1:0", io.Discard)
	conn, server := openTestSocket(t, s)
	defer server.Close()
	defer conn.Close()
	readEntry(t, conn)
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				s.WriteLog([]byte("log"))
				s.WriteEvent([]byte("event"))
			}
		})
	}
	wg.Go(s.Close)
	wg.Wait()
	s.Close()
	if stats := s.Stats(); stats.Clients != 0 || stats.QueuedBytes != 0 {
		t.Fatal(stats)
	}
}

func TestStructuredTLSMetadataOnWebSocket(t *testing.T) {
	s := NewServer("127.0.0.1:0", io.Discard)
	defer s.Close()
	conn, server := openTestSocket(t, s)
	defer conn.Close()
	defer server.Close()
	readEntry(t, conn)
	for _, port := range []uint32{12345, 23456} {
		event := &pb.Event{Pid: 7, Uuid: "7_8_curl_9", SrcIp: "192.0.2.7", SrcPort: port, DstIp: "192.0.2.20", DstPort: 443, Payload: []byte("TLS data"), Length: 8}
		if err := s.WriteProtobufEvent(event); err != nil {
			t.Fatal(err)
		}
		wire := readEntry(t, conn).GetEventPayload()
		if !proto.Equal(event, wire) {
			t.Fatal(wire)
		}
	}
	if err := s.WriteProtobufEvent(&pb.Event{Pid: 7, Payload: []byte("missing snapshot")}); err == nil {
		t.Fatal("unknown endpoint permitted stale collector fallback")
	}
	if s.Stats().MissingEndpoints != 1 {
		t.Fatal(s.Stats())
	}
}
