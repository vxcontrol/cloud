package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vxcontrol/cloud/models"
)

// sseFrame is every field any event this stream sends might carry. Events use
// disjoint subsets of it — decoding all shapes into one struct is simpler than
// a type switch per event name, and unknown fields are just left at zero value.
type sseFrame struct {
	IssueID  string `json:"issue_id"`
	StreamID int    `json:"stream_id"`
	Content  string `json:"content"`
	Message  string `json:"message"`
	Type     string `json:"type"`
	Thinking *struct {
		Content string `json:"content"`
	} `json:"thinking"`
}

// streamRenderer prints an investigation SSE stream to os.Stdout token by
// token, as it arrives — this is what a chat UI would show as "the assistant
// is typing", rather than the single blob of text a client gets from
// io.ReadAll. Each write below goes straight to the terminal (no buffering to
// flush), so output appears in real time as the network delivers it.
type streamRenderer struct {
	answer   strings.Builder
	lastKind string // "" | "thinking" | "content", to label transitions once
}

// enter prints a label the first time output switches into thinking/content,
// and stays silent on every following token of the same kind — otherwise every
// single streamed word would repeat the label.
func (r *streamRenderer) enter(kind, label string) {
	if r.lastKind != kind {
		if r.lastKind != "" {
			fmt.Println()
		}
		fmt.Print(label)
		r.lastKind = kind
	}
}

func (r *streamRenderer) breakLine() {
	if r.lastKind != "" {
		fmt.Println()
		r.lastKind = ""
	}
}

// handle renders one SSE event and reports whether the stream is finished.
func (r *streamRenderer) handle(event, data string) (done bool, err error) {
	var frame sseFrame
	if data != "" {
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			return false, fmt.Errorf("failed to decode %q event data: %w", event, err)
		}
	}

	switch event {
	case "start":
		fmt.Printf("--- investigating issue %s (live stream) ---\n", frame.IssueID)

	case "message":
		r.breakLine()
		switch models.MsgLogType(frame.Type) {
		case models.MsgLogTypeInput:
			fmt.Printf("you> %s\n", frame.Message)
		case models.MsgLogTypeWait:
			// The issue's background log analysis hasn't finished yet — the
			// server is waiting for it before it can answer, inside this same
			// call. See MsgLogTypeWait's doc comment in models/support.go.
			fmt.Printf("... %s\n", frame.Message)
		case models.MsgLogTypeDone:
			// Same text the "content" tokens already rendered live — nothing
			// new to print.
		default:
			// search / agent / code: a tool call the assistant is making.
			fmt.Printf("[%s] %s\n", frame.Type, frame.Message)
		}

	case "thinking":
		r.enter("thinking", "(thinking) ")
		if frame.Thinking != nil {
			fmt.Print(frame.Thinking.Content)
		}

	case "content":
		r.enter("content", "assistant> ")
		fmt.Print(frame.Content)
		r.answer.WriteString(frame.Content)

	case "flush":
		r.breakLine()

	case "update":
		// A full-text replay of the stream_id just finished, for clients that
		// did not accumulate the "thinking"/"content" deltas themselves. This
		// example did, so rendering it again would print everything twice.

	case "heartbeat":
		// Keep-alive ping with no content of its own; nothing to show.

	case "error":
		r.breakLine()
		fmt.Printf("!!! error: %s\n", frame.Message)

	case "done":
		r.breakLine()
		fmt.Println("--- done ---")
		done = true
	}

	return done, nil
}

// readSSEStream parses `event: <name>\ndata: <json>\n\n` frames off r and
// calls handle for each one, stopping at the first error, the first frame
// handle reports as final, or end of stream.
func readSSEStream(r io.Reader, handle func(event, data string) (bool, error)) error {
	scanner := bufio.NewScanner(r)
	// A "content"/"thinking" data line is small, but "update" replays the
	// whole accumulated answer in one line — grow past bufio.Scanner's 64KB
	// default so a long answer doesn't trip ErrTooLong.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			if event == "" {
				continue // blank keep-alive line between frames, not a frame itself
			}
			done, err := handle(event, data)
			event, data = "", ""
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
	}

	return scanner.Err()
}
