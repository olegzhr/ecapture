// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package handlers

import (
	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/errors"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
)

// TextHandler handles events by writing their encoded output to a destination.
// It delegates formatting to the event itself via String() or StringHex() methods.
type TextHandler struct {
	writer writers.OutputWriter
	useHex bool
}

func (h *TextHandler) Writer() writers.OutputWriter {
	return h.writer
}

// NewTextHandler creates a new TextHandler with the provided writer.
// Events format themselves via String() or StringHex() methods.
func NewTextHandler(writer writers.OutputWriter, useHex bool) *TextHandler {
	if writer == nil {
		writer = writers.NewStdoutWriter()
	}
	return &TextHandler{
		writer: writer,
		useHex: useHex,
	}
}

// Handle processes an event and writes its formatted output.
// The event is responsible for its own formatting via String() or StringHex() methods.
func (h *TextHandler) Handle(event domain.Event) error {
	if event == nil {
		return errors.New(errors.ErrCodeEventValidation, "event cannot be nil")
	}

	// Let the event format itself based on hex mode
	var output string
	if h.useHex {
		// Try StringHex() method first for hex mode
		type hexStringer interface {
			StringHex() string
		}
		if hs, ok := event.(hexStringer); ok {
			output = hs.StringHex()
		} else {
			// Fallback to regular String() if StringHex() not available
			output = event.String()
		}
	} else {
		// Regular text mode
		output = event.String()
	}

	// Skip empty output (event not ready or filtered out)
	if output == "" {
		return nil
	}

	// Ensure output ends with newline for readability
	if output[len(output)-1] != '\n' {
		output += "\n"
	}

	// Write to output destination
	if source, ok := event.(interface{ ToProtobufEvent() *pb.Event }); ok {
		if writer, ok := h.writer.(interface{ WriteProtobufEvent(*pb.Event) (bool, error) }); ok {
			// Structured TLS captures carry their own endpoints. Standalone lifecycle
			// records can arrive late and overwrite a reused-FD collector cache.
			if event.Type() == domain.EventTypeModuleData {
				if handled, err := writer.WriteProtobufEvent(nil); handled {
					return err
				}
			}
			structured := source.ToProtobufEvent()
			structured.Payload = []byte(output)
			structured.Length = uint32(len(structured.Payload))
			if handled, err := writer.WriteProtobufEvent(structured); handled {
				if err != nil {
					return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write structured event", err)
				}
				return nil
			}
		}
	}
	_, err := h.writer.Write([]byte(output))
	if err != nil {
		return errors.Wrap(errors.ErrCodeEventDispatch, "failed to write event output", err)
	}

	return nil
}

// Close closes the handler and releases resources.
func (h *TextHandler) Close() error {
	if h.writer == nil {
		return nil
	}
	return h.writer.Close()
}

// Name returns the handler's identifier.
func (h *TextHandler) Name() string {
	return ModeText
}
