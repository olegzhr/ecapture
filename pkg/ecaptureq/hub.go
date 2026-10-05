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
	"github.com/gojue/ecapture/v2/internal/errors"
	"sync"
)

const (
	hubQueueMessages    = 1024
	queueBytes          = 8 << 20
	maxMessageBytes     = 4 << 20
	clientQueueMessages = 1024
	maxClients          = 64
)

// Stats covers local transport only. Accepted is admission, not remote receipt.
type Stats struct {
	Accepted, QueueFull, Oversized, NoSubscribers, SlowClients, WriteErrors, ShutdownDropped, MissingEndpoints, SubscriberDropped uint64
	QueuedBytes, Clients                                                                                                          int
}

type queuedMessage struct {
	data    []byte
	clients []*Client
}

type Hub struct {
	mu            sync.Mutex
	clients       map[*Client]bool
	broadcast     chan queuedMessage
	done, stopped chan struct{}
	closed        bool
	stats         Stats
	onLoss        func(error)
}

func newHub() *Hub {
	return &Hub{clients: make(map[*Client]bool), broadcast: make(chan queuedMessage, hubQueueMessages),
		done: make(chan struct{}), stopped: make(chan struct{})}
}

func (h *Hub) snapshot() Stats {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := h.stats
	result.Clients = len(h.clients)
	return result
}

func transportError(message string) error {
	return errors.New(errors.ErrCodeEventDispatch, "ecaptureQ: "+message)
}

// Nonblocking FIFO admission. Reject the newest message on overload and report
// the loss instead of silently dropping whenever the broadcaster is busy.
func (h *Hub) broadcastMessage(message []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return transportError("server closed")
	}
	if len(message) > maxMessageBytes {
		h.stats.Oversized++
		return transportError("message exceeds 4 MiB")
	}
	if len(h.clients) == 0 {
		h.stats.NoSubscribers++
		return transportError("no subscribers")
	}
	if len(h.broadcast) == cap(h.broadcast) || h.stats.QueuedBytes+len(message) > queueBytes {
		h.stats.QueueFull++
		return transportError("broadcast queue full")
	}
	queued := queuedMessage{data: append([]byte(nil), message...)}
	for client := range h.clients {
		queued.clients = append(queued.clients, client)
	}
	h.broadcast <- queued
	h.stats.QueuedBytes += len(message)
	h.stats.Accepted++
	return nil
}

func (h *Hub) addClient(c *Client, history [][]byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.clients) >= maxClients {
		return false
	}
	h.clients[c] = true
	for _, message := range history {
		if !h.enqueue(c, message) {
			return false
		}
	}
	return true
}

// The hub is the only sender/closer. Heartbeats are written by the socket writer.
func (h *Hub) enqueue(c *Client, message []byte) bool {
	if len(c.send) == cap(c.send) || c.queuedBytes+len(message) > queueBytes {
		h.stats.SlowClients++
		h.stats.SubscriberDropped++
		h.removeClientLocked(c)
		return false
	}
	c.send <- message
	c.queuedBytes += len(message)
	return true
}

func (h *Hub) removeClientLocked(c *Client) {
	if !h.clients[c] {
		return
	}
	delete(h.clients, c)
	close(c.send)
	close(c.done)
	h.stats.SubscriberDropped += uint64(len(c.send))
	// Do not continue a partial stream after overflow; discard queued buffers.
	for range c.send {
	}
	c.queuedBytes = 0
}

func (h *Hub) removeClient(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeClientLocked(c)
}

func (h *Hub) consumed(c *Client, message []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c] {
		c.queuedBytes -= len(message)
	}
}

func (h *Hub) writeError() {
	h.mu.Lock()
	h.stats.WriteErrors++
	h.mu.Unlock()
}

func (h *Hub) run() {
	defer close(h.stopped)
	for {
		select {
		case <-h.done:
			return
		case message := <-h.broadcast:
			h.mu.Lock()
			previousSlow := h.stats.SlowClients
			h.stats.QueuedBytes -= len(message.data)
			if h.closed {
				h.stats.ShutdownDropped++
			} else {
				if len(h.clients) == 0 {
					h.stats.NoSubscribers++
				}
				for _, c := range message.clients {
					if h.clients[c] {
						h.enqueue(c, message.data)
					}
				}
			}
			lost := previousSlow != h.stats.SlowClients
			h.mu.Unlock()
			if lost && h.onLoss != nil {
				h.onLoss(transportError("slow subscriber disconnected"))
			}
		}
	}
}

func (h *Hub) close() {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		close(h.done)
		for c := range h.clients {
			h.removeClientLocked(c)
		}
		for {
			select {
			case message := <-h.broadcast:
				h.stats.QueuedBytes -= len(message.data)
				h.stats.ShutdownDropped++
			default:
				h.mu.Unlock()
				<-h.stopped
				return
			}
		}
	}
	h.mu.Unlock()
	<-h.stopped
}
