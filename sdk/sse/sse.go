// Package sse reads the event stream a streamed call of the PentAGI Cloud API answers
// with: the answer of the support assistant and the answer of an LLM call alike.
//
// The stream is a sequence of frames, each an event name and one JSON value:
//
//	event: <name>
//	data: <JSON on one line>
//	<blank line>
//
// It opens with "start", carries any number of "heartbeat" frames and of the events of
// the call, and ends with exactly one of "done" and "error". A reader hands its caller
// "start" and the events of the call; the heartbeats it consumes, and "done" and
// "error" it reports as the outcome of the reading. A stream is a complete
// answer only after "done" and a clean end of the body. "error" is a refusal of the
// server, with the code a refusal before the response began would have carried. The
// end of the body before either of them is a cut stream: what was read is not an answer, and the
// request is not to be sent again on account of it — the server may have done the work.
//
// The package knows the four events of the stream itself and nothing of the events of a
// call; those are named by the package that describes the call.
package sse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// The events of the stream itself, the same for every call.
const (
	EventStart     = "start"     // the first frame; its data identifies the call, and may be {}
	EventHeartbeat = "heartbeat" // sent at a fixed interval, so that no hop sees the connection idle
	EventError     = "error"     // the server refused or failed; nothing follows
	EventDone      = "done"      // the answer is complete; nothing follows
)

// DefaultMaxEventSize is the largest data of one event a Reader accepts unless told
// otherwise: above the largest answer the API sends in one event.
const DefaultMaxEventSize = 8 << 20

var (
	// ErrStreamCut reports a body that ended before an outcome or failed before completion.
	ErrStreamCut = errors.New("event stream was cut before it completed")
	// ErrMalformed reports a frame that is not one event name with one JSON value.
	ErrMalformed = errors.New("malformed event stream")
	// ErrEventTooLarge reports an event whose data exceeds the Reader's limit.
	ErrEventTooLarge = errors.New("event exceeds the size limit")
)

// Event is one frame of the stream.
type Event struct {
	Name string
	Data json.RawMessage
}

// Error is the refusal an "error" event carries. Err is what the Classifier made of
// Code, so errors.Is and errors.As see the same error a refusal answered before the
// response began gives.
type Error struct {
	Code       string
	Message    string
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	switch {
	case e.Code == "" && e.Message == "":
		return "the server reported an error it did not name"
	case e.Message == "":
		return e.Code
	case e.Code == "":
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

// Classifier turns the code of a refusal into the error the caller's package uses for
// it; sdk.ErrorFromCode is the one of the SDK.
type Classifier func(code string, retryAfter time.Duration) error

// Option adjusts a Reader.
type Option func(*Reader)

// WithMaxEventSize sets the largest data of one event the Reader accepts.
func WithMaxEventSize(size int) Option {
	return func(r *Reader) {
		if size > 0 {
			r.maxEventSize = size
		}
	}
}

// Reader reads the frames of one stream. It is not safe for concurrent use, and it
// does not close the body it reads.
type Reader struct {
	body         *bufio.Reader
	classify     Classifier
	maxEventSize int
	err          error // the outcome of the stream once it is known; returned from then on
}

// NewReader returns a Reader of the event stream in body. classify gives the error of
// an "error" event its meaning; with nil the Error has no Err to unwrap.
func NewReader(body io.Reader, classify Classifier, options ...Option) *Reader {
	r := &Reader{body: bufio.NewReader(body), classify: classify, maxEventSize: DefaultMaxEventSize}
	for _, option := range options {
		option(r)
	}
	return r
}

// Next returns the next event: "start" first, then the events of the call. Heartbeats
// are consumed and not returned. It returns io.EOF after "done" and a clean end of the
// body; an *Error for an "error" event; ErrStreamCut, wrapping the cause when there is
// one, for a body that ended before an outcome or failed before completion;
// ErrMalformed or ErrEventTooLarge for a frame it cannot accept. Once the
// outcome is known every later call returns it again, and the body is not read further.
func (r *Reader) Next() (Event, error) {
	for r.err == nil {
		event, err := r.frame()
		switch {
		case err != nil:
			r.err = err
		case event.Name == EventHeartbeat:
			continue
		case event.Name == EventDone:
			// Reading through the buffer also verifies the transport's authenticated end.
			_, err := r.body.ReadByte()
			switch err {
			case io.EOF:
				r.err = io.EOF
			case nil:
				r.err = fmt.Errorf("%w: data after done", ErrMalformed)
			default:
				r.err = fmt.Errorf("%w: %w", ErrStreamCut, err)
			}
		case event.Name == EventError:
			r.err = r.refusal(event.Data)
		default:
			return event, nil
		}
	}
	return Event{}, r.err
}

// Read hands "start" and every event of the call to handle and returns nil only for a
// complete stream. An error of handle ends the reading and is returned as it is.
func Read(body io.Reader, classify Classifier, handle func(Event) error, options ...Option) error {
	r := NewReader(body, classify, options...)
	for {
		event, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := handle(event); err != nil {
			return err
		}
	}
}

// frame reads one frame. Lines end with LF or CRLF; a field other than "event" and
// "data" is skipped, and with it a comment, which is a line that begins with a colon
// and so has no field name; several "data" lines are joined with LF, as the event
// stream format has it.
func (r *Reader) frame() (Event, error) {
	var (
		event            Event
		hasName, hasData bool
	)
	for {
		line, err := r.line()
		if err != nil {
			return Event{}, err
		}

		if len(line) == 0 {
			switch {
			case !hasName && !hasData:
				continue // blank lines between frames
			case !hasName || !hasData:
				return Event{}, fmt.Errorf("%w: a frame needs an event name and data", ErrMalformed)
			case !json.Valid(event.Data):
				return Event{}, fmt.Errorf("%w: the data of %q is not JSON", ErrMalformed, event.Name)
			}
			return event, nil
		}

		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "event":
			event.Name, hasName = string(value), true
		case "data":
			if hasData {
				event.Data = append(event.Data, '\n')
			}
			event.Data, hasData = append(event.Data, value...), true
			if len(event.Data) > r.maxEventSize {
				return Event{}, fmt.Errorf("%w of %d bytes", ErrEventTooLarge, r.maxEventSize)
			}
		}
	}
}

// maxRetryAfter bounds the cooldown an "error" event may ask for; a number beyond it
// is not a time to wait and would not fit a Duration.
const maxRetryAfter = 366 * 24 * time.Hour

// lineOverhead is what a line may hold beside the data of an event: the field name,
// the colon and the space, the line ending.
const lineOverhead = 64

// line reads one line without its ending, and gives up on a line no event of an
// acceptable size could have: the stream is not trusted to end its lines.
func (r *Reader) line() ([]byte, error) {
	var line []byte
	for {
		part, err := r.body.ReadSlice('\n')
		line = append(line, part...)
		// written as a difference: a limit near the largest int must not wrap round
		if len(line)-lineOverhead > r.maxEventSize {
			return nil, fmt.Errorf("%w of %d bytes", ErrEventTooLarge, r.maxEventSize)
		}
		switch {
		case err == nil:
			line = bytes.TrimSuffix(line, []byte("\n"))
			return bytes.TrimSuffix(line, []byte("\r")), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil, ErrStreamCut
		default:
			return nil, fmt.Errorf("%w: %w", ErrStreamCut, err)
		}
	}
}

// refusal builds the error of an "error" event. The code is what the caller acts on,
// so the reserved retry_after (whole seconds) never costs it: a cooldown this version
// cannot read is no cooldown, and only data that is not an object is malformed.
func (r *Reader) refusal(data json.RawMessage) error {
	var refused struct {
		Code       string          `json:"code"`
		Message    string          `json:"message"`
		RetryAfter json.RawMessage `json:"retry_after"`
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) || json.Unmarshal(data, &refused) != nil {
		return fmt.Errorf("%w: the data of %q is not an object", ErrMalformed, EventError)
	}

	var seconds float64
	if json.Unmarshal(refused.RetryAfter, &seconds) != nil || seconds < 0 || seconds > maxRetryAfter.Seconds() {
		seconds = 0
	}
	refusal := &Error{
		Code:       refused.Code,
		Message:    refused.Message,
		RetryAfter: time.Duration(seconds * float64(time.Second)),
	}
	if r.classify != nil {
		refusal.Err = r.classify(refusal.Code, refusal.RetryAfter)
	}
	return refusal
}
