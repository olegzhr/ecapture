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
	"fmt"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
	"time"
)

const socketWriteTimeout = 5 * time.Second

type Client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	done           chan struct{}
	queuedBytes    int // protected by hub.mu
	heartBeatCount int
}

func (c *Client) readPump() {
	defer c.hub.removeClient(c)
	defer c.conn.Close()
	c.conn.MaxPayloadBytes = maxMessageBytes
	for {
		var data []byte
		if websocket.Message.Receive(c.conn, &data) != nil {
			return
		}
	}
}

// The sole socket writer also sends heartbeats, without enqueueing to itself.
func (c *Client) writePump() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer c.hub.removeClient(c)
	defer c.conn.Close()
	if c.Heartbeat() != nil {
		c.hub.writeError()
		return
	}
	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.send:
			if !ok {
				return
			}
			c.hub.consumed(c, message)
			if c.write(message) != nil {
				c.hub.writeError()
				return
			}
		case <-ticker.C:
			if c.Heartbeat() != nil {
				c.hub.writeError()
				return
			}
		}
	}
}

func (c *Client) write(data []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(socketWriteTimeout)); err != nil {
		return err
	}
	return websocket.Message.Send(c.conn, data)
}

// Heartbeat is called only by writePump.
func (c *Client) Heartbeat() error {
	hb := &pb.Heartbeat{Message: fmt.Sprintf("heartbeat:%d", c.heartBeatCount),
		Timestamp: time.Now().Unix(), Count: int64(c.heartBeatCount)}
	encoded, err := proto.Marshal(&pb.LogEntry{LogType: pb.LogType_LOG_TYPE_HEARTBEAT,
		Payload: &pb.LogEntry_HeartbeatPayload{HeartbeatPayload: hb}})
	if err != nil {
		return err
	}
	if err = c.write(encoded); err == nil {
		c.heartBeatCount++
	}
	return err
}
