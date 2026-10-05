// Copyright 2025 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecaptureq

import (
	"github.com/gojue/ecapture/v2/internal/logger"
	"github.com/gojue/ecapture/v2/pkg/util/ws"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
	"io"
	"sync"
	"time"
)

const LogBuffLen = 128
const logBuffBytes = 1 << 20

type Server struct {
	hub         *Hub
	ws          *ws.Server
	mu          sync.Mutex // protects history and makes registration atomic with logs
	logbuff     [][]byte
	logBytes    int
	closed      bool
	logger      *logger.Logger
	lastWarning time.Time
	clients     sync.WaitGroup
	closeOnce   sync.Once
}

func NewServer(addr string, logWriter io.Writer) *Server {
	s := &Server{hub: newHub(), logger: logger.New(logWriter, false)}
	s.hub.onLoss = s.warnLoss
	s.ws = ws.NewServer(addr, s.handleWebSocket)
	go s.hub.run()
	return s
}

func (s *Server) Start() error { return s.ws.Start() }
func (s *Server) Stats() Stats { return s.hub.snapshot() }

func (s *Server) handleWebSocket(conn *websocket.Conn) {
	c := &Client{hub: s.hub, conn: conn, send: make(chan []byte, clientQueueMessages), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed || !s.hub.addClient(c, s.logbuff) {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.clients.Add(1)
	s.mu.Unlock()
	defer s.clients.Done()
	defer conn.Close()
	finished := make(chan struct{})
	go func() { <-c.done; conn.Close() }()
	go func() { c.writePump(); close(finished) }()
	c.readPump()
	<-finished
}

func (s *Server) warnLoss(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastWarning) < time.Second {
		return
	}
	s.lastWarning = time.Now()
	s.logger.Warn().Err(err).Interface("transport_stats", s.Stats()).Msg("ecaptureQ delivery rejected")
}

// Cache a bounded history window, while broadcasting every log immediately.
func (s *Server) WriteLog(data []byte) (int, error) {
	encoded, err := proto.Marshal(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_PROCESS_LOG,
		Payload: &pb.LogEntry_RunLog{RunLog: string(data)}})
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, transportError("server closed")
	}
	if len(encoded) > logBuffBytes {
		s.mu.Unlock()
		return 0, transportError("log exceeds history budget")
	}
	for len(s.logbuff) >= LogBuffLen || s.logBytes+len(encoded) > logBuffBytes {
		s.logBytes -= len(s.logbuff[0])
		s.logbuff[0] = nil
		s.logbuff = s.logbuff[1:]
	}
	s.logbuff = append(s.logbuff, encoded)
	s.logBytes += len(encoded)
	if s.Stats().Clients != 0 {
		err = s.hub.broadcastMessage(encoded)
	}
	s.mu.Unlock()
	if err != nil {
		s.warnLoss(err)
		return 0, err
	}
	return len(data), nil
}

func (s *Server) WriteEvent(data []byte) (int, error) {
	if len(data) > maxMessageBytes-64 {
		s.hub.mu.Lock()
		s.hub.stats.Oversized++
		s.hub.mu.Unlock()
		err := transportError("event exceeds message budget")
		s.warnLoss(err)
		return 0, err
	}
	encoded, err := proto.Marshal(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT,
		Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{Payload: data, Length: uint32(len(data))}}})
	if err == nil {
		err = s.hub.broadcastMessage(encoded)
	}
	if err != nil {
		s.warnLoss(err)
		return 0, err
	}
	return len(data), nil
}

// WriteProtobufEvent preserves sensor-supplied endpoints alongside plaintext.
func (s *Server) WriteProtobufEvent(event *pb.Event) error {
	if event == nil || len(event.Payload) > maxMessageBytes-1024 {
		return transportError("invalid structured event or message exceeds budget")
	}
	if event.SrcIp == "" || event.DstIp == "" || event.SrcPort == 0 || event.DstPort == 0 {
		s.hub.mu.Lock()
		s.hub.stats.MissingEndpoints++
		s.hub.mu.Unlock()
		err := transportError("TLS socket snapshot unavailable; refusing stale endpoint fallback")
		s.warnLoss(err)
		return err
	}
	encoded, err := proto.Marshal(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT,
		Payload: &pb.LogEntry_EventPayload{EventPayload: event}})
	if err == nil {
		err = s.hub.broadcastMessage(encoded)
	}
	if err != nil {
		s.warnLoss(err)
	}
	return err
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.hub.close()
		s.ws.Close()
		s.clients.Wait()
		s.logger.Info().Interface("transport_stats", s.Stats()).Msg("ecaptureQ stopped")
	})
}
