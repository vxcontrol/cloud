package sse

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
	"time"
)

// transcript is a complete answer of the support assistant, byte for byte as the
// server writes it: the forms a reader has to go on reading. The deltas of a model
// call end with flush, and its update follows.
const transcript = "event: start\ndata: {\"issue_id\":\"7f1e4c9a-0b52-4d0e-9c53-2f6a1d3b8e10\"}\n\n" +
	"event: heartbeat\ndata: {\"timestamp\":1781092800}\n\n" +
	"event: message\ndata: {\"message\":\"searching FAQ for startup errors\",\"type\":\"search\"}\n\n" +
	"event: thinking\ndata: {\"stream_id\":1,\"thinking\":{\"content\":\"Analyzing\",\"signature\":\"c2ln\"}}\n\n" +
	"event: content\ndata: {\"content\":\"Based on the logs\",\"stream_id\":1}\n\n" +
	"event: heartbeat\ndata: {\"timestamp\":1781092803}\n\n" +
	"event: flush\ndata: {\"stream_id\":1}\n\n" +
	"event: update\ndata: {\"content\":\"Based on the logs\",\"stream_id\":1,\"thinking\":null}\n\n" +
	"event: done\ndata: {}\n\n"

var errQuota = errors.New("daily quota exceeded")

// classify stands in for the classifier of the SDK.
func classify(code string, retryAfter time.Duration) error {
	if code == "QuotaExceededDaily" {
		return fmt.Errorf("retry in %s: %w", retryAfter, errQuota)
	}
	return fmt.Errorf("%s: unknown", code)
}

// events reads the stream to its outcome.
func events(body io.Reader, options ...Option) (names []string, last Event, err error) {
	err = Read(body, classify, func(event Event) error {
		names, last = append(names, event.Name), event
		return nil
	}, options...)
	return names, last, err
}

func TestReader_Next_ReturnsTheEventsOfACompleteAnswerAndThenEOF(t *testing.T) {
	r := NewReader(strings.NewReader(transcript), classify)

	var names []string
	var thinking string
	for {
		event, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("after %v: %v", names, err)
		}
		names = append(names, event.Name)
		if event.Name == "thinking" {
			thinking = string(event.Data)
		}
	}

	// the heartbeats keep the connection alive and are not events of the call
	want := []string{"start", "message", "thinking", "content", "flush", "update"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("events %v, want %v", names, want)
	}
	if want := `{"stream_id":1,"thinking":{"content":"Analyzing","signature":"c2ln"}}`; thinking != want {
		t.Errorf("the data of an event is not what was sent:\n got %s\nwant %s", thinking, want)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("a finished stream answered %v", err)
	}
}

// A body cut anywhere before "done" is not an answer, however much of it arrived. The
// transport ends a broken response the way it ends a whole one, so this rule is all
// that tells them apart: a reader that took the end of the body for the end of the
// answer handed a truncated answer to its caller as a complete one.
func TestReader_Next_NeverTakesTheEndOfTheBodyForTheEndOfTheAnswer(t *testing.T) {
	for cut := 0; cut < len(transcript); cut++ {
		if _, _, err := events(strings.NewReader(transcript[:cut])); !errors.Is(err, ErrStreamCut) {
			t.Fatalf("the first %d bytes of the stream were read as %v", cut, err)
		}
	}
	if _, _, err := events(strings.NewReader(transcript)); err != nil {
		t.Fatalf("the whole stream: %v", err)
	}
}

// failingReader answers what it holds and then fails.
type failingReader struct {
	held string
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.held == "" {
		return 0, f.err
	}
	n := copy(p, f.held)
	f.held = f.held[n:]
	return n, nil
}

func TestReader_Next_KeepsTheCauseOfACutStream(t *testing.T) {
	cause := errors.New("connection reset by peer")
	_, _, err := events(&failingReader{held: transcript[:120], err: cause})
	if !errors.Is(err, ErrStreamCut) || !errors.Is(err, cause) {
		t.Errorf("got %v", err)
	}
}

// Once "done" or "error" has arrived the answer is known. A reader that went on reading
// would wait on a connection the server may keep open, or fail a complete answer on
// whatever an intermediary appended to it.
func TestReader_Next_DoesNotReadPastTheOutcome(t *testing.T) {
	refusal := "event: start\ndata: {}\n\nevent: error\ndata: {\"code\":\"Internal\",\"message\":\"internal server error\"}\n\n"
	for name, stream := range map[string]string{"done": transcript, "error": refusal} {
		body := &failingReader{held: stream, err: errors.New("the body was read past the outcome")}
		r := NewReader(body, classify)
		var outcome error
		for outcome == nil {
			_, outcome = r.Next()
		}
		if _, again := r.Next(); again != outcome || errors.Is(outcome, ErrStreamCut) {
			t.Errorf("%s: outcome %v, then %v", name, outcome, again)
		}
	}
}

// A refusal inside the stream has to mean to the caller what the same refusal means
// when it is answered before the response begins.
func TestReader_Next_TurnsAnErrorEventIntoTheErrorOfItsCode(t *testing.T) {
	stream := "event: start\ndata: {}\n\n" +
		"event: error\ndata: {\"code\":\"QuotaExceededDaily\",\"message\":\"daily quota exceeded\",\"retry_after\":3600}\n\n"

	names, _, err := events(strings.NewReader(stream))
	if strings.Join(names, " ") != "start" {
		t.Errorf("events before the refusal: %v", names)
	}
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("got %v", err)
	}
	if refusal.Code != "QuotaExceededDaily" || refusal.Message != "daily quota exceeded" || refusal.RetryAfter != time.Hour {
		t.Errorf("got %+v", refusal)
	}
	if !errors.Is(err, errQuota) || !strings.Contains(refusal.Err.Error(), "retry in 1h0m0s") {
		t.Errorf("the classifier's error is not in the chain: %v", refusal.Err)
	}
	if got := err.Error(); got != "QuotaExceededDaily: daily quota exceeded" {
		t.Errorf("the text of the error: %q", got)
	}

	// The cooldown is a reserved field the server does not write yet, and this reader
	// is in released clients by the time it does: whatever arrives there, the code of
	// the refusal survives, and what is not a time to wait is no cooldown.
	for value, want := range map[string]time.Duration{
		`3600.0`: time.Hour, `1.5`: 1500 * time.Millisecond,
		`-5`: 0, `"3600"`: 0, `null`: 0, `{}`: 0, `1e300`: 0,
	} {
		stream := "event: error\ndata: {\"code\":\"QuotaExceededDaily\",\"retry_after\":" + value + "}\n\n"
		_, err = NewReader(strings.NewReader(stream), classify).Next()
		if !errors.As(err, &refusal) || refusal.Code != "QuotaExceededDaily" || refusal.RetryAfter != want {
			t.Errorf("retry_after %s: %v (%+v), want a cooldown of %v", value, err, refusal, want)
		}
	}

	// an error the server did not name still says that it is one
	_, err = NewReader(strings.NewReader("event: error\ndata: {}\n\n"), nil).Next()
	if !errors.As(err, &refusal) || err.Error() == "" {
		t.Errorf("an error without a code: %q", err)
	}

	// without a classifier the code is all the caller gets
	_, err = NewReader(strings.NewReader(stream[strings.Index(stream, "event: error"):]), nil).Next()
	if !errors.As(err, &refusal) || refusal.Err != nil || errors.Is(err, errQuota) {
		t.Errorf("without a classifier: %v", err)
	}
}

func TestReader_Next_RefusesAFrameThatIsNotOneEventWithOneValue(t *testing.T) {
	for name, stream := range map[string]string{
		"data without an event name":       "data: {}\n\n",
		"an event name without data":       "event: start\n\n",
		"data that is not JSON":            "event: start\ndata: {\"issue_id\":\n\n",
		"an error whose data is no object": "event: error\ndata: \"Internal\"\n\n",
		"an error whose data is null":      "event: error\ndata: null\n\n",
		"an error whose data is a list":    "event: error\ndata: [\"Internal\"]\n\n",
		"an error whose code is no text":   "event: error\ndata: {\"code\":500}\n\n",
	} {
		if _, _, err := events(strings.NewReader(stream)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// What the event stream format allows and an intermediary may add: CRLF line endings,
// comment lines, fields this protocol does not use, data split over several lines.
func TestReader_Next_ReadsWhatTheFormatAllows(t *testing.T) {
	stream := ": connected\r\n\r\n" +
		"id: 7\r\nretry: 1000\r\nevent: start\r\ndata: {\"issue_id\":\r\ndata: \"a\"}\r\n\r\n" +
		"\r\n" +
		": keep-alive\r\n" +
		"event:done\r\ndata:{}\r\n\r\n"

	names, first, err := events(strings.NewReader(stream))
	if err != nil || strings.Join(names, " ") != "start" {
		t.Fatalf("events %v, outcome %v", names, err)
	}
	if got := string(first.Data); got != "{\"issue_id\":\n\"a\"}" {
		t.Errorf("data over two lines: %q", got)
	}
}

func TestReader_Next_HoldsNoEventLargerThanItsLimit(t *testing.T) {
	const limit = 100
	frame := func(size int) string {
		return "event: result\ndata: \"" + strings.Repeat("a", size-2) + "\"\n\nevent: done\ndata: {}\n\n"
	}

	if names, last, err := events(strings.NewReader(frame(limit)), WithMaxEventSize(limit)); err != nil ||
		len(names) != 1 || len(last.Data) != limit {
		t.Errorf("an event of the limit: events %v, %d bytes, outcome %v", names, len(last.Data), err)
	}
	if _, _, err := events(strings.NewReader(frame(limit+1)), WithMaxEventSize(limit)); !errors.Is(err, ErrEventTooLarge) {
		t.Errorf("an event one byte over the limit: %v", err)
	}
	// a stream that never ends its line is not read to the end either
	endless := io.MultiReader(strings.NewReader("event: result\ndata: \""), neverEnding{})
	if _, _, err := events(endless, WithMaxEventSize(limit)); !errors.Is(err, ErrEventTooLarge) {
		t.Errorf("a line with no end: %v", err)
	}
	// and the limit is what the option says, not the default
	if _, _, err := events(strings.NewReader(frame(limit+1)), WithMaxEventSize(0)); err != nil {
		t.Errorf("under the default limit: %v", err)
	}
	// a caller that wants no limit asks for the largest: it must not wrap round to none
	if _, _, err := events(strings.NewReader(transcript), WithMaxEventSize(math.MaxInt)); err != nil {
		t.Errorf("under the largest limit: %v", err)
	}
}

// neverEnding is a body of one endless line.
type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestRead_ReturnsTheErrorOfItsHandlerAsItIs(t *testing.T) {
	stop := errors.New("the caller has seen enough")
	seen := 0
	err := Read(strings.NewReader(transcript), classify, func(Event) error {
		seen++
		return stop
	})
	if err != stop || seen != 1 {
		t.Errorf("after %d events: %v", seen, err)
	}
}
