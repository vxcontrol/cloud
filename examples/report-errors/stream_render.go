package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk/sse"
)

// streamRenderer prints an investigation stream to os.Stdout token by token, as it
// arrives — this is what a chat UI would show as "the assistant is typing", rather
// than the single blob of text a client gets from io.ReadAll. Each write below goes
// straight to the terminal (no buffering to flush), so output appears in real time
// as the network delivers it.
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

// handle renders one event of the investigation. Of the events of the stream itself
// only `start` gets here: the reader consumes heartbeats, and it reports `done` and
// `error` as the outcome of the read, which is where the caller learns how the stream
// ended.
func (r *streamRenderer) handle(event sse.Event) error {
	decode := func(v any) error {
		if err := json.Unmarshal(event.Data, v); err != nil {
			return fmt.Errorf("failed to decode %q event data: %w", event.Name, err)
		}
		return nil
	}

	switch event.Name {
	case sse.EventStart:
		var start models.SupportStreamStart
		if err := decode(&start); err != nil {
			return err
		}
		fmt.Printf("--- investigating issue %s (live stream) ---\n", start.IssueID)

	case models.SupportStreamEventMessage.String():
		var message models.SupportStreamMessage
		if err := decode(&message); err != nil {
			return err
		}
		r.breakLine()
		switch message.Type {
		case models.MsgLogTypeInput:
			fmt.Printf("you> %s\n", message.Message)
		case models.MsgLogTypeWait:
			// The issue's background log analysis hasn't finished yet — the
			// server is waiting for it before it can answer, inside this same
			// call. See MsgLogTypeWait's doc comment in models/support.go.
			fmt.Printf("... %s\n", message.Message)
		default:
			// search / agent / code: a tool call the assistant is making.
			fmt.Printf("[%s] %s\n", message.Type, message.Message)
		}

	case models.SupportStreamEventThinking.String():
		var thinking models.SupportStreamThinking
		if err := decode(&thinking); err != nil {
			return err
		}
		r.enter("thinking", "(thinking) ")
		if thinking.Thinking != nil {
			fmt.Print(thinking.Thinking.Content)
		}

	case models.SupportStreamEventContent.String():
		var content models.SupportStreamContent
		if err := decode(&content); err != nil {
			return err
		}
		r.enter("content", "assistant> ")
		fmt.Print(content.Content)
		r.answer.WriteString(content.Content)

	case models.SupportStreamEventFlush.String():
		r.breakLine()

	case models.SupportStreamEventUpdate.String():
		// A full-text replay of the stream_id whose deltas the flush above has
		// ended, for clients that did not accumulate the "thinking"/"content"
		// deltas themselves. This example did, so rendering it again would print
		// everything twice.
	}

	// an event this version does not know is skipped: a newer server may send more
	return nil
}
