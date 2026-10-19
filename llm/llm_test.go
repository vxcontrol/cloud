package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/sdk/sse"
)

// Answers in the form of the API's event stream.
const (
	chunkA  = `{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"pentagi.coder","choices":[{"index":0,"delta":{"content":"Hel"}}]}`
	chunkB  = `{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"pentagi.coder","choices":[],"usage":{"prompt_tokens":1203,"completion_tokens":288,"total_tokens":1491}}`
	result  = `{"id":"chatcmpl-1","object":"chat.completion","created":1781092800,"model":"pentagi.coder","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1203,"completion_tokens":288,"total_tokens":1491}}`
	vectors = `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.25,-0.5]},{"object":"embedding","index":1,"embedding":[0.5,0.25]}],"model":"pentagi.embedding","usage":{"prompt_tokens":8,"total_tokens":8}}`
	// embeddingAgents is the list of agents of a licence whose one agent of embeddings
	// takes two inputs a call, in its envelope
	embeddingAgents = `{"status":"success","data":{"object":"list","data":[{"id":"pentagi.embedding","object":"model","created":1781092800,"owned_by":"pentagi","type":"embedding","max_input_size":2097152,"supported_parameters":[],"dimensions":1,"max_batch_size":2}]}}`
)

func frames(events ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(events); i += 2 {
		b.WriteString("event: " + events[i] + "\ndata: " + events[i+1] + "\n\n")
	}
	return b.String()
}

// fakeCalls answers the calls with the given streams and records the bodies sent.
type fakeCalls struct {
	answer string
	err    error
	sent   [][]byte
}

func (f *fakeCalls) call(_ context.Context, body []byte) (io.ReadCloser, error) {
	f.sent = append(f.sent, body)
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(strings.NewReader(f.answer)), nil
}

func client(chat, embed *fakeCalls) *Client {
	calls := Calls{}
	if chat != nil {
		calls.ChatCompletions = chat.call
	}
	if embed != nil {
		calls.Embeddings = embed.call
	}
	return NewFromCalls(calls)
}

func post(t *testing.T, c *Client, path, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, BaseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer sk-of-the-library")
	return c.Do(req)
}

// A streamed chat completion is answered once its first chunk has arrived, and its body is the stream of the
// OpenAI API: each chunk as it arrives, then [DONE] once the stream said it was done.
// The request goes to the API as it was written.
func TestClient_Do_StreamsAChatCompletionInTheDialectOfTheOpenAIAPI(t *testing.T) {
	const request = `{"model":"pentagi.coder","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true}}`
	chat := &fakeCalls{answer: frames("start", "{}", "heartbeat", `{"timestamp":1781092800}`, "chunk", chunkA, "chunk", chunkB, "done", "{}")}
	resp, err := post(t, client(chat, nil), "/chat/completions", request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("answered %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if want := "data: " + chunkA + "\n\ndata: " + chunkB + "\n\ndata: [DONE]\n\n"; string(body) != want {
		t.Errorf("the stream reads\n%s\nwant\n%s", body, want)
	}
	if len(chat.sent) != 1 || string(chat.sent[0]) != request {
		t.Errorf("the API was sent %q", chat.sent)
	}
}

// A call that is not streamed is answered with the one object of its answer, once the
// whole of it has arrived; so is an embeddings call.
func TestClient_Do_AnswersACallThatIsNotStreamedWithItsOneResult(t *testing.T) {
	for name, tc := range map[string]struct {
		path, body, answer, want string
	}{
		"a chat completion": {"/chat/completions", `{"model":"pentagi.coder","messages":[]}`, frames("start", "{}", "heartbeat", "{}", "result", result, "done", "{}"), result},
		"stream false":      {"/chat/completions", `{"model":"pentagi.coder","messages":[],"stream":false}`, frames("start", "{}", "result", result, "done", "{}"), result},
		"embeddings":        {"/embeddings", `{"model":"pentagi.embedding","input":["a","b"]}`, frames("start", "{}", "result", vectors, "done", "{}"), vectors},
	} {
		calls := &fakeCalls{answer: tc.answer}
		resp, err := post(t, client(calls, calls), tc.path, tc.body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != tc.want || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: answered %q with %s", name, resp.Header.Get("Content-Type"), body)
		}
	}
}

// What the API refuses is the error of the SDK: before the answer began — before the first
// chunk of a stream too, where an OpenAI-compatible endpoint answers with its status and
// a library of that API retries by it — the error of the call; after, the error a Read of
// the body returns — with the same meaning, so that errors.Is and RetryAfterOf read both
// alike. A stream that ends before it says so is cut, and is never an answer.
func TestClient_Do_ReportsAFailureWithTheErrorsOfTheSDK(t *testing.T) {
	refused := &sdk.QuotaError{Err: sdk.ErrQuotaExceededDaily, Scope: sdk.QuotaScopeDaily, RetryAfter: time.Hour}
	_, err := post(t, client(&fakeCalls{err: refused}, nil), "/chat/completions", `{"model":"pentagi.coder","messages":[]}`)
	if !errors.Is(err, sdk.ErrQuotaExceededDaily) || sdk.RetryAfterOf(err) != time.Hour {
		t.Errorf("a refusal before the answer: %v", err)
	}

	for name, tc := range map[string]struct {
		answer string
		stream bool
		is     error
		read   string // what a stream reads before its failure; a stream that has none fails in Do
	}{
		"a failure after a chunk":             {frames("start", "{}", "chunk", chunkA, "error", `{"code":"BadGateway","message":"bad gateway"}`), true, sdk.ErrBadGateway, "data: " + chunkA + "\n\n"},
		"a stream cut after a chunk":          {frames("start", "{}", "chunk", chunkA), true, sse.ErrStreamCut, "data: " + chunkA + "\n\n"},
		"a refusal before the first chunk":    {frames("start", "{}", "heartbeat", "{}", "error", `{"code":"BadGateway","message":"bad gateway"}`), true, sdk.ErrBadGateway, ""},
		"a stream cut before its first chunk": {frames("start", "{}"), true, sse.ErrStreamCut, ""},
		"a result in a stream":                {frames("start", "{}", "result", result, "done", "{}"), true, sse.ErrMalformed, ""},
		"a chunk over two lines":              {"event: start\ndata: {}\n\nevent: chunk\ndata: {\"a\":\ndata: 1}\n\nevent: done\ndata: {}\n\n", true, sse.ErrMalformed, ""},
		"a failure of a whole answer":         {frames("start", "{}", "error", `{"code":"BadRequest","message":"bad request"}`), false, sdk.ErrBadRequest, ""},
		"a whole answer cut":                  {frames("start", "{}", "result", result), false, sse.ErrStreamCut, ""},
		"a chunk in a whole answer":           {frames("start", "{}", "chunk", chunkA, "result", result, "done", "{}"), false, sse.ErrMalformed, ""},
		"two results":                         {frames("start", "{}", "result", result, "result", result, "done", "{}"), false, sse.ErrMalformed, ""},
		"no result":                           {frames("start", "{}", "done", "{}"), false, sse.ErrMalformed, ""},
	} {
		body := `{"model":"pentagi.coder","messages":[]}`
		if tc.stream {
			body = `{"model":"pentagi.coder","messages":[],"stream":true}`
		}
		resp, err := post(t, client(&fakeCalls{answer: tc.answer}, nil), "/chat/completions", body)
		if !tc.stream || tc.read == "" {
			if !errors.Is(err, tc.is) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		read, err := io.ReadAll(resp.Body)
		if !errors.Is(err, tc.is) {
			t.Errorf("%s: the read ended with %v", name, err)
		}
		if string(read) != tc.read {
			t.Errorf("%s: read %q before the failure", name, read)
		}
		if strings.Contains(string(read), "[DONE]") {
			t.Errorf("%s: a failed stream says it is done", name)
		}
	}
}

// The Client serves the two calls of the OpenAI API it has and nothing else, and never
// for a request whose context has ended.
func TestClient_Do_ServesOnlyTheCallsItHas(t *testing.T) {
	calls := &fakeCalls{answer: frames("start", "{}", "result", result, "done", "{}")}
	c := client(calls, calls)
	for name, req := range map[string]*http.Request{
		"a list of models": func() *http.Request { r, _ := http.NewRequest(http.MethodGet, BaseURL+"/models", nil); return r }(),
		"a completion":     func() *http.Request { r, _ := http.NewRequest(http.MethodPost, BaseURL+"/completions", nil); return r }(),
		"a GET of a chat": func() *http.Request {
			r, _ := http.NewRequest(http.MethodGet, BaseURL+"/chat/completions", nil)
			return r
		}(),
	} {
		if _, err := c.Do(req); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"/chat/completions", strings.NewReader(`{}`))
	if _, err := c.Do(req); !errors.Is(err, context.Canceled) {
		t.Errorf("a request whose context ended: %v", err)
	}
	if len(calls.sent) != 0 {
		t.Errorf("the API was called %d times", len(calls.sent))
	}
}

// The list of agents is read from the envelope of the API, every field of it. A list
// that is not valid is an error and never a shorter list: the envelope is read leniently,
// so the list of a server of an older form would otherwise read as a licence offered no
// agent, and the batches of every agent would go whole to be refused.
func TestClient_Models_ListsTheAgentsOfTheLicence(t *testing.T) {
	const list = `{"object":"list","data":[{"id":"pentagi.coder","object":"model","created":1781092800,"owned_by":"pentagi","type":"completion","description":"Coder","context_window":131072,"max_output_tokens":8192,"max_input_size":2097152,"supported_parameters":["max_completion_tokens","max_tokens","tools"]},{"id":"pentagi.embedding","object":"model","created":1781092800,"owned_by":"pentagi","type":"embedding","max_input_size":2097152,"supported_parameters":[],"dimensions":1024,"max_batch_size":64}]}`
	c := NewFromCalls(Calls{Models: func(context.Context) ([]byte, error) { return []byte(`{"status":"success","data":` + list + `}`), nil }})
	got, err := c.Models(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 2 || got.Data[0].ID != "pentagi.coder" || len(got.Data[0].SupportedParameters) != 3 ||
		*got.Data[1].MaxBatchSize != 64 || got.Data[1].Type != models.LLMModelTypeEmbedding {
		t.Errorf("the list reads as %+v", got)
	}

	refused := NewFromCalls(Calls{Models: func(context.Context) ([]byte, error) { return nil, sdk.ErrForbidden }})
	if _, err := refused.Models(context.Background()); !errors.Is(err, sdk.ErrForbidden) {
		t.Errorf("a licence without the feature: %v", err)
	}
	for name, body := range map[string]string{
		"an agent of a type nobody serves": `{"status":"success","data":{"object":"list","data":[{"id":"x","object":"model","owned_by":"pentagi","type":"chat","max_input_size":1,"supported_parameters":[]}]}}`,
		"the list of an older form":        `{"status":"success","data":{"models":[{"name":"pentagi.embedding","type":"embedding","max_input_size":1,"max_batch_size":2}]}}`,
	} {
		broken := NewFromCalls(Calls{Models: func(context.Context) ([]byte, error) { return []byte(body), nil }})
		if got, err := broken.Models(context.Background()); err == nil {
			t.Errorf("%s is taken as %+v", name, got)
		}
	}
}

// Close ends a Read that waits for the next frame of a stream.
func TestClient_Do_ClosesAStreamThatIsBeingRead(t *testing.T) {
	reader, writer := io.Pipe()
	c := NewFromCalls(Calls{ChatCompletions: func(context.Context, []byte) (io.ReadCloser, error) { return reader, nil }})
	// the first chunk answers the call; the Read after it waits for the next
	go func() { _, _ = io.WriteString(writer, frames("start", "{}", "chunk", chunkA)) }()
	resp, err := post(t, c, "/chat/completions", `{"model":"pentagi.coder","messages":[],"stream":true}`)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("a stream closed in the middle read as whole")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the Read")
	}
}

// partCalls answers each embeddings call with a vector per input, the vector holding the
// input's letter, and fails the call whose number is failOn.
type partCalls struct {
	sent   []string
	failOn int
	short  bool
}

func (p *partCalls) call(_ context.Context, body []byte) (io.ReadCloser, error) {
	p.sent = append(p.sent, string(body))
	if len(p.sent) == p.failOn {
		return nil, sdk.ErrTooManyRequests
	}
	var request struct {
		Input []string `json:"input"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	if p.short {
		request.Input = request.Input[1:]
	}
	var data []string
	for i, input := range request.Input {
		data = append(data, fmt.Sprintf(`{"object":"embedding","index":%d,"embedding":[%d]}`, i, int(input[0])-'a'))
	}
	list := fmt.Sprintf(`{"object":"list","data":[%s],"model":"pentagi.embedding","usage":{"prompt_tokens":%d,"total_tokens":%d}}`,
		strings.Join(data, ","), 4*len(request.Input), 4*len(request.Input))
	return io.NopCloser(strings.NewReader(frames("start", "{}", "result", list, "done", "{}"))), nil
}

// A library of the OpenAI API sends as many inputs as it was given — PentAGI 512 by
// default — and the API refuses a batch larger than the max_batch_size of the agent. So
// such a batch goes in parts of that size and comes back as one list: every vector in the
// place of its input, the usage of all the parts. The rest of the request goes with every
// part, and the list of agents is read once for several calls.
func TestClient_Do_SendsABatchLargerThanTheAgentTakesInParts(t *testing.T) {
	var listed int
	agents := func(context.Context) ([]byte, error) {
		listed++
		return []byte(embeddingAgents), nil
	}
	parts := &partCalls{}
	c := NewFromCalls(Calls{Embeddings: parts.call, Models: agents})

	resp, err := post(t, c, "/embeddings", `{"model":"pentagi.embedding","input":["a","b","c","d","<e>"],"encoding_format":"float"}`)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	want := `{"object":"list","data":[` +
		`{"embedding":[0],"index":0,"object":"embedding"},{"embedding":[1],"index":1,"object":"embedding"},` +
		`{"embedding":[2],"index":2,"object":"embedding"},{"embedding":[3],"index":3,"object":"embedding"},` +
		`{"embedding":[-37],"index":4,"object":"embedding"}],"model":"pentagi.embedding","usage":{"prompt_tokens":20,"total_tokens":20}}`
	if string(body) != want {
		t.Errorf("the answer of the parts\n got: %s\nwant: %s", body, want)
	}
	wantSent := []string{
		`{"encoding_format":"float","input":["a","b"],"model":"pentagi.embedding"}`,
		`{"encoding_format":"float","input":["c","d"],"model":"pentagi.embedding"}`,
		`{"encoding_format":"float","input":["<e>"],"model":"pentagi.embedding"}`,
	}
	if strings.Join(parts.sent, "\n") != strings.Join(wantSent, "\n") {
		t.Errorf("the parts sent\n got: %s\nwant: %s", parts.sent, wantSent)
	}

	// a batch the agent takes goes as it was written, in one call
	parts.sent = nil
	if _, err := post(t, c, "/embeddings", `{"model":"pentagi.embedding", "input":["a","b"]}`); err != nil {
		t.Fatal(err)
	}
	if len(parts.sent) != 1 || parts.sent[0] != `{"model":"pentagi.embedding", "input":["a","b"]}` {
		t.Errorf("a batch within the bound was sent as %q", parts.sent)
	}
	if listed != 1 {
		t.Errorf("the list of agents was read %d times for two calls", listed)
	}
}

// What the client cannot split by is the API's to judge: a batch of an agent the list
// does not name, or sent while the list cannot be read, goes whole. A part that fails
// ends the call with its error and nothing after it is sent; a part answered with fewer
// vectors than it had inputs is a broken answer, never a list with holes.
func TestClient_Do_EndsABatchInPartsOnTheFirstPartThatFails(t *testing.T) {
	const five = `{"model":"pentagi.embedding","input":["a","b","c","d","e"]}`
	agents := func(context.Context) ([]byte, error) {
		return []byte(embeddingAgents), nil
	}

	for name, list := range map[string]func(context.Context) ([]byte, error){
		"the list cannot be read": func(context.Context) ([]byte, error) { return nil, sdk.ErrServerInternal },
		"an agent not listed": func(context.Context) ([]byte, error) {
			return []byte(strings.Replace(embeddingAgents, `"pentagi.embedding"`, `"pentagi.other"`, 1)), nil
		},
	} {
		// a list of another agent must read, or the case is the one above under another name
		if _, err := NewFromCalls(Calls{Models: list}).Models(context.Background()); name == "an agent not listed" && err != nil {
			t.Fatalf("%s: the list does not read: %v", name, err)
		}
		parts := &partCalls{}
		if _, err := post(t, NewFromCalls(Calls{Embeddings: parts.call, Models: list}), "/embeddings", five); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(parts.sent) != 1 || parts.sent[0] != five {
			t.Errorf("%s: sent %q", name, parts.sent)
		}
	}

	failing := &partCalls{failOn: 2}
	if _, err := post(t, NewFromCalls(Calls{Embeddings: failing.call, Models: agents}), "/embeddings", five); !errors.Is(err, sdk.ErrTooManyRequests) {
		t.Errorf("a part refused: %v", err)
	}
	if len(failing.sent) != 2 {
		t.Errorf("%d parts sent after the second failed", len(failing.sent))
	}

	short := &partCalls{short: true}
	if _, err := post(t, NewFromCalls(Calls{Embeddings: short.call, Models: agents}), "/embeddings", five); !errors.Is(err, sse.ErrMalformed) {
		t.Errorf("a part answered with a vector missing: %v", err)
	}
}

// The list of agents may fail to be read again when the bound it gave has aged: the
// bound read before stands, and the list is not asked for at every call meanwhile —
// without it a batch PentAGI sends whole would be refused, every time, until the list
// came back.
func TestClient_Do_KeepsTheBoundItKnowsWhenTheListCannotBeReadAgain(t *testing.T) {
	var listed int
	agents := func(context.Context) ([]byte, error) {
		if listed++; listed > 1 {
			return nil, sdk.ErrTooManyRequests
		}
		return []byte(embeddingAgents), nil
	}
	parts := &partCalls{}
	c := NewFromCalls(Calls{Embeddings: parts.call, Models: agents})
	const five = `{"model":"pentagi.embedding","input":["a","b","c","d","e"]}`

	if _, err := post(t, c, "/embeddings", five); err != nil {
		t.Fatal(err)
	}
	c.batchesAt = time.Now().Add(-2 * batchesTTL)
	parts.sent = nil
	for range 2 {
		if _, err := post(t, c, "/embeddings", five); err != nil {
			t.Fatal(err)
		}
	}
	if len(parts.sent) != 6 {
		t.Errorf("with the list failing, two batches of five went in %d calls, not in parts of the bound read before", len(parts.sent))
	}
	if listed != 2 {
		t.Errorf("the list was asked for %d times: once read, once failed, then not again for a while", listed)
	}
}

// stalling answers with the frames given and then nothing, as a connection that died
// without a word; the test ends it.
func stalling(t *testing.T, after string, heartbeats time.Duration, rest string) func(context.Context, []byte) (io.ReadCloser, error) {
	return func(context.Context, []byte) (io.ReadCloser, error) {
		reader, writer := io.Pipe()
		t.Cleanup(func() { _ = writer.Close() })
		go func() {
			if _, err := io.WriteString(writer, after); err != nil {
				return
			}
			for end := time.Now().Add(heartbeats); time.Now().Before(end); {
				time.Sleep(20 * time.Millisecond)
				if _, err := io.WriteString(writer, frames("heartbeat", `{"timestamp":1}`)); err != nil {
					return
				}
			}
			if rest != "" {
				_, _ = io.WriteString(writer, rest)
				_ = writer.Close()
			}
		}()
		return reader, nil
	}
}

// An answer that goes silent — the connection or the server gone without closing it — is
// cut once it has been silent for the idle timeout, before its first chunk and between
// two, streamed or not, and the read says why. One that keeps receiving heartbeats is
// waited for however long it takes.
func TestClient_Do_CutsAnAnswerThatGoesSilent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		after  string
		beats  time.Duration
		rest   string
		silent bool
	}{
		{name: "silent before the first chunk", body: `{"stream":true}`, after: frames("start", "{}"), silent: true},
		{name: "silent before the result", body: `{}`, after: frames("start", "{}"), silent: true},
		{name: "silent between two chunks", body: `{"stream":true}`, after: frames("start", "{}", "chunk", chunkA), silent: true},
		{
			name: "a long answer that keeps the heartbeats coming", body: `{"stream":true}`,
			after: frames("start", "{}"), beats: 400 * time.Millisecond, rest: frames("chunk", chunkA, "done", "{}"),
		},
		{
			name: "a long result that keeps the heartbeats coming", body: `{}`,
			after: frames("start", "{}"), beats: 400 * time.Millisecond, rest: frames("result", result, "done", "{}"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewFromCalls(Calls{ChatCompletions: stalling(t, tc.after, tc.beats, tc.rest)})
			c.SetIdleTimeout(100 * time.Millisecond)

			began := time.Now()
			resp, err := post(t, c, "/chat/completions", tc.body)
			if err == nil {
				_, err = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}

			if !tc.silent {
				if err != nil {
					t.Fatalf("an answer that kept its heartbeats coming was cut: %v", err)
				}
				return
			}
			if !errors.Is(err, sse.ErrStreamCut) || !errors.Is(err, ErrStreamIdle) {
				t.Fatalf("a silent answer ended with %v, not a cut that names the silence", err)
			}
			if elapsed := time.Since(began); elapsed > 3*time.Second {
				t.Fatalf("a silent answer was cut after %v", elapsed)
			}
		})
	}
}
