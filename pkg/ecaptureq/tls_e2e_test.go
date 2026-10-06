package ecaptureq

import (
	"bufio"
	"bytes"
	"fmt"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Opt-in live eBPF test: only the disposable curl client (UID 424242) is captured.
// No public endpoint, installed service or alternate writer transport is used.
func TestLocalTLSCapture(t *testing.T) {
	binary := os.Getenv("ECAPTUREQ_E2E_BINARY")
	if binary == "" {
		t.Skip("set ECAPTUREQ_E2E_BINARY to a production binary with eBPF assets")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("live eBPF test requires Linux root")
	}
	for _, mode := range []string{"keep-alive", "close"} {
		t.Run(mode, func(t *testing.T) { captureLocalTLS(t, binary, mode) })
	}
}

type capturedStream struct {
	write, read []byte
	fd          string
}

func captureLocalTLS(t *testing.T, binary, mode string) {
	var mu sync.Mutex
	observed := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(body) != `{"lab":"ecaptureQ"}` {
			t.Errorf("request body: %q", body)
		}
		_, port, _ := net.SplitHostPort(r.RemoteAddr)
		number, _ := strconv.Atoi(port)
		mu.Lock()
		observed[r.URL.Path] = number
		mu.Unlock()
		reply := []byte(fmt.Sprintf(`{"path":%q}`, r.URL.Path))
		w.Header().Set("Content-Length", strconv.Itoa(len(reply)))
		w.Header().Set("Connection", mode)
		w.WriteHeader(200)
		// Separate writes reproduce the historical missing response-body bug.
		if flush, ok := w.(http.Flusher); ok {
			flush.Flush()
		}
		w.Write(reply)
	}))
	defer server.Close()
	_, serverPortText, _ := net.SplitHostPort(server.Listener.Addr().String())
	serverPort, _ := strconv.Atoi(serverPortText)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wsAddress := listener.Addr().String()
	listener.Close()
	logPath := filepath.Join(t.TempDir(), "ecapture.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	capture := exec.Command(binary, "tls", "--uid", "424242", "--libssl", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "--btf", "1", "--ecaptureq", "ws://"+wsAddress, "--mapsize", "128")
	capture.Stdout = log
	capture.Stderr = log
	if err = capture.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		capture.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- capture.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				data, _ := os.ReadFile(logPath)
				t.Errorf("capture shutdown: %v\n%s", err, data)
			}
		case <-time.After(10 * time.Second):
			capture.Process.Kill()
			<-done
			t.Error("capture did not shut down")
		}
	}()
	waitFor(t, func() bool {
		data, _ := os.ReadFile(logPath)
		return bytes.Contains(data, []byte("probe started successfully"))
	})
	conn, err := websocket.Dial("ws://"+wsAddress, "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	// The initial heartbeat is sent only after registration has completed.
	for readEntry(t, conn).GetHeartbeatPayload() == nil {
	}
	entries := make(chan *pb.Event, 256)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer close(entries)
		for {
			var data []byte
			if websocket.Message.Receive(conn, &data) != nil {
				return
			}
			entry := new(pb.LogEntry)
			if proto.Unmarshal(data, entry) != nil {
				return
			}
			if event := entry.GetEventPayload(); event != nil {
				entries <- event
			}
		}
	}()
	args := []string{"--http1.1", "-ksS", "--request", "POST", "-H", "Connection: " + mode, "-H", "Content-Type: application/json", "--data", `{"lab":"ecaptureQ"}`}
	for i := 0; i < 3; i++ {
		args = append(args, server.URL+fmt.Sprintf("/local/%d", i))
	}
	curl := exec.Command("curl", args...)
	curl.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 424242, Gid: 424242}}
	if output, err := curl.CombinedOutput(); err != nil {
		t.Fatalf("curl: %v %s", err, output)
	}
	// All local I/O has completed; closing after a short bounded drain also tests
	// disconnect/cleanup while the production capture process is still running.
	time.Sleep(300 * time.Millisecond)
	conn.Close()
	<-readDone
	streams := map[uint32]*capturedStream{}
	header := regexp.MustCompile(`FD:(\d+) (READ|WRITE) \((\d+) bytes\):\n`)
	for event := range entries {
		if event.SrcIp != "127.0.0.1" || event.DstIp != "127.0.0.1" || event.DstPort != uint32(serverPort) || event.SrcPort == 0 || event.Pid == 0 {
			t.Fatalf("bad endpoint metadata: %v", event)
		}
		if int(event.Length) != len(event.Payload) {
			t.Fatal("protobuf length mismatch")
		}
		match := header.FindSubmatchIndex(event.Payload)
		if match == nil {
			t.Fatalf("invalid TLS wrapper: %q", event.Payload)
		}
		size, _ := strconv.Atoi(string(event.Payload[match[6]:match[7]]))
		start := match[1]
		if start+size > len(event.Payload) {
			t.Fatal("truncated plaintext")
		}
		stream := streams[event.SrcPort]
		if stream == nil {
			stream = &capturedStream{fd: string(event.Payload[match[2]:match[3]])}
			streams[event.SrcPort] = stream
		}
		if string(event.Payload[match[4]:match[5]]) == "WRITE" {
			stream.write = append(stream.write, event.Payload[start:start+size]...)
		} else {
			stream.read = append(stream.read, event.Payload[start:start+size]...)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 3 {
		t.Fatal("server did not observe three requests", observed)
	}
	seen := map[string]bool{}
	fds := map[string]int{}
	for port, stream := range streams {
		fds[stream.fd]++
		reqReader, resReader := bufio.NewReader(bytes.NewReader(stream.write)), bufio.NewReader(bytes.NewReader(stream.read))
		for {
			request, err := http.ReadRequest(reqReader)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal("request reconstruction", err)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != `{"lab":"ecaptureQ"}` {
				t.Fatal("request body", err, string(body))
			}
			response, err := http.ReadResponse(resReader, request)
			if err != nil {
				t.Fatal("response reconstruction", err)
			}
			reply, err := io.ReadAll(response.Body)
			expected := fmt.Sprintf(`{"path":%q}`, request.URL.Path)
			if err != nil || response.StatusCode != 200 || string(reply) != expected || observed[request.URL.Path] != int(port) || seen[request.URL.Path] {
				t.Fatalf("response/endpoint mismatch: %s %q", request.URL.Path, reply)
			}
			seen[request.URL.Path] = true
		}
	}
	if len(seen) != 3 {
		t.Fatal("lost HTTP records", seen)
	}
	if mode == "close" {
		reused := false
		for _, connections := range fds {
			if connections > 1 {
				reused = true
			}
		}
		if len(streams) != 3 || !reused {
			t.Fatal("new connections with reused FD were not exercised", fds)
		}
	}
	t.Logf("3/3 complete HTTP transactions; mode=%s connections=%d FD map=%v", mode, len(streams), fds)
	// Verify the test binary did not merely accept data before disconnecting.
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), "TLS socket snapshot unavailable") {
		t.Fatal("live socket snapshot failed")
	}
}
