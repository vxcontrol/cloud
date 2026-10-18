// Package llm is a client of the language models of the PentAGI Cloud API that speaks
// the OpenAI API to its caller.
//
// A Client is the HTTP client of a library of the OpenAI API: give the library BaseURL
// and the Client, and the chat completions and the embeddings it asks for are made as
// calls of the PentAGI Cloud API, with the licence, the proof of work and the
// encryption of the SDK. `model` in a request names an agent of the licence (Models
// lists them); the rest of the request is the library's, and what the agent does not
// let a client set is not used.
//
//	client, err := llm.New("features.pentagi.com", sdk.WithLicenseKey(key))
//	...
//	// e.g. for langchaingo, whose token is required and not read here:
//	// openai.New(openai.WithBaseURL(llm.BaseURL), openai.WithHTTPClient(client), openai.WithToken("unused"), ...)
//
// The answer of a call is what the OpenAI API answers: a chat completion, its stream of
// `data:` frames ending with `data: [DONE]`, or the list of vectors. A batch of
// embeddings larger than the agent takes is sent in parts and answered as one list. A refusal before
// the answer began is the error of the SDK (errors.Is with its sentinels, RetryAfterOf);
// a failure inside a stream is an *sse.Error with the same meaning, returned by a Read
// of the body; a stream cut before its end is sse.ErrStreamCut. A call whose answer has
// begun is never sent again: a stream that was cut is not an answer, and is not a reason
// to send the request again — the model may have done the work. A refusal before the
// answer that may pass (429, 502, 500) is tried again by the SDK, up to WithMaxRetries.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/sdk/sse"
)

// BaseURL is the base URL to give a library of the OpenAI API whose HTTP client is a
// Client. Its host is never dialled: the Client makes the calls.
const BaseURL = "https://pentagi-cloud.invalid/v1"

// ErrUnsupported reports a request the Client does not serve: anything but a POST of a
// chat completion or of embeddings.
var ErrUnsupported = errors.New("llm: not a call of the OpenAI API this client serves")

// The calls of the API, by the name of their route and their path.
const (
	callChatCompletions = "llm_chat_completions"
	callEmbeddings      = "llm_embeddings"
	callModels          = "llm_models"

	pathChatCompletions = "/api/v1/proxy/llm/chat/completions"
	pathEmbeddings      = "/api/v1/proxy/llm/embeddings"
	pathModels          = "/api/v1/proxy/llm/models"
)

// Calls are the calls of the API a Client makes.
type Calls struct {
	ChatCompletions sdk.CallReqBytesRespReader
	Embeddings      sdk.CallReqBytesRespReader
	Models          sdk.CallReqRespBytes
}

// batchesTTL is how long a Client goes by the batch bounds of the list of agents it
// read: an administrator may change them.
const batchesTTL = 5 * time.Minute

// Client serves the requests of a library of the OpenAI API with the calls of the API.
// It is safe for concurrent use.
type Client struct {
	calls Calls

	mu        sync.Mutex
	batches   map[string]int // max_batch_size by agent of embeddings
	batchesAt time.Time
}

// New builds the calls of the API against host and returns a Client of them. The
// options are those of the SDK: the licence key, the installation, the transport.
func New(host string, options ...sdk.Option) (*Client, error) {
	var calls Calls
	err := sdk.Build([]sdk.CallConfig{
		{Calls: []any{&calls.ChatCompletions}, Host: host, Name: callChatCompletions, Path: pathChatCompletions, Method: sdk.CallMethodPOST},
		{Calls: []any{&calls.Embeddings}, Host: host, Name: callEmbeddings, Path: pathEmbeddings, Method: sdk.CallMethodPOST},
		{Calls: []any{&calls.Models}, Host: host, Name: callModels, Path: pathModels, Method: sdk.CallMethodGET},
	}, options...)
	if err != nil {
		return nil, err
	}
	return NewFromCalls(calls), nil
}

// NewFromCalls returns a Client of calls made elsewhere: by tests and tools.
func NewFromCalls(calls Calls) *Client {
	return &Client{calls: calls}
}

// Models lists the agents the licence may name in `model`: the list object of the OpenAI
// API, each agent a model object of it whose ID is the name to send, with its bounds and
// the parameters it lets a caller set. A list that is not valid in every field is an
// error, never a shorter list.
func (c *Client) Models(ctx context.Context) (models.LLMModelsResponse, error) {
	body, err := c.calls.Models(ctx)
	if err != nil {
		return models.LLMModelsResponse{}, err
	}
	list, err := models.ParseEnvelope[models.LLMModelsResponse](body)
	if err != nil {
		return models.LLMModelsResponse{}, err
	}
	if err := list.Valid(); err != nil {
		return models.LLMModelsResponse{}, fmt.Errorf("the list of models is not valid: %w", err)
	}
	return list, nil
}

// Do serves a request of the OpenAI API: a POST whose path ends with /chat/completions
// or /embeddings. The body goes to the API as it is; the headers of the request are
// not read and do not go anywhere. A chat completion whose `stream` is true is answered
// once its first chunk has arrived, with a body that reads the stream from there as it
// arrives; any other call is read whole first and answered with the one object of its
// answer. Either way a refusal before the answer began — the API refuses before the
// first chunk what it refuses at all but a stream that breaks — is the error of Do, as
// an OpenAI-compatible endpoint answers it with its status before a stream.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var call sdk.CallReqBytesRespReader
	switch {
	case req.Method != http.MethodPost:
		return nil, fmt.Errorf("%w: %s %s", ErrUnsupported, req.Method, req.URL.Path)
	case strings.HasSuffix(req.URL.Path, "/chat/completions"):
		call = c.calls.ChatCompletions
	case strings.HasSuffix(req.URL.Path, "/embeddings"):
		call = c.calls.Embeddings
	default:
		return nil, fmt.Errorf("%w: %s %s", ErrUnsupported, req.Method, req.URL.Path)
	}

	var body []byte
	if req.Body != nil {
		read, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("llm: failed to read the body of the request: %w", err)
		}
		body = read
	}
	// the mode of the answer is the top-level `stream` of the request and nothing
	// else; a body that is not one object is the API's to refuse
	var mode struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &mode)

	if call == nil {
		return nil, fmt.Errorf("%w: %s %s", ErrUnsupported, req.Method, req.URL.Path)
	}
	if strings.HasSuffix(req.URL.Path, "/embeddings") {
		result, err := c.embed(ctx, body)
		if err != nil {
			return nil, err
		}
		return respond(req, "application/json", io.NopCloser(bytes.NewReader(result))), nil
	}

	answer, err := call(ctx, body)
	if err != nil {
		return nil, err
	}
	reader := sse.NewReader(answer, sdk.ErrorFromCode)
	if mode.Stream {
		stream := &streamBody{reader: reader, body: answer}
		if err := stream.fill(); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return respond(req, "text/event-stream", stream), nil
	}

	defer answer.Close()
	result, err := oneResult(reader)
	if err != nil {
		return nil, err
	}
	return respond(req, "application/json", io.NopCloser(bytes.NewReader(result))), nil
}

// oneCall makes a call that is not streamed and returns its one result.
func oneCall(ctx context.Context, call sdk.CallReqBytesRespReader, body []byte) ([]byte, error) {
	answer, err := call(ctx, body)
	if err != nil {
		return nil, err
	}
	defer answer.Close()
	return oneResult(sse.NewReader(answer, sdk.ErrorFromCode))
}

// embed makes an embeddings call. A batch larger than the max_batch_size of the agent
// is refused by the API, and a library of the OpenAI API sends as many inputs as it was
// given, so such a batch is sent in parts of that size, one after another, and answered
// as one list: the vectors in the order of the inputs, the usage added up. A part that
// fails ends the call with its error; the parts before it were served, and are charged.
// A request whose agent or bound is not known is sent as it is: the API decides.
func (c *Client) embed(ctx context.Context, body []byte) ([]byte, error) {
	var request map[string]json.RawMessage
	var inputs []json.RawMessage
	if json.Unmarshal(body, &request) != nil || json.Unmarshal(request["input"], &inputs) != nil {
		return oneCall(ctx, c.calls.Embeddings, body)
	}
	var agent string
	_ = json.Unmarshal(request["model"], &agent)
	size := c.batchSize(ctx, agent)
	if size < 1 || len(inputs) <= size {
		return oneCall(ctx, c.calls.Embeddings, body)
	}

	var (
		vectors []json.RawMessage
		model   json.RawMessage
		usage   struct {
			PromptTokens int64 `json:"prompt_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		}
	)
	for start := 0; start < len(inputs); start += size {
		part, err := encode(inputs[start:min(start+size, len(inputs))])
		if err != nil {
			return nil, err
		}
		request["input"] = part
		partBody, err := encode(request)
		if err != nil {
			return nil, err
		}
		answer, err := oneCall(ctx, c.calls.Embeddings, partBody)
		if err != nil {
			return nil, err
		}

		var list struct {
			Data  []map[string]json.RawMessage `json:"data"`
			Model json.RawMessage              `json:"model"`
			Usage struct {
				PromptTokens int64 `json:"prompt_tokens"`
				TotalTokens  int64 `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(answer, &list); err != nil {
			return nil, fmt.Errorf("%w: the list of vectors of a part: %v", sse.ErrMalformed, err)
		}
		if len(list.Data) != len(inputs[start:min(start+size, len(inputs))]) {
			return nil, fmt.Errorf("%w: %d vectors for a part of %d inputs", sse.ErrMalformed, len(list.Data), min(size, len(inputs)-start))
		}
		for _, vector := range list.Data {
			// the index of a vector is its place in the part; the answer gives its
			// place in the request
			var index int
			if err := json.Unmarshal(vector["index"], &index); err != nil || index < 0 || index >= len(list.Data) {
				return nil, fmt.Errorf("%w: a vector without its place in the part", sse.ErrMalformed)
			}
			if vector["index"], err = json.Marshal(start + index); err != nil {
				return nil, err
			}
			item, err := encode(vector)
			if err != nil {
				return nil, err
			}
			vectors = append(vectors, item)
		}
		model = list.Model
		usage.PromptTokens += list.Usage.PromptTokens
		usage.TotalTokens += list.Usage.TotalTokens
	}
	return encode(struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
		Model  json.RawMessage   `json:"model"`
		Usage  any               `json:"usage"`
	}{"list", vectors, model, usage})
}

// batchSize returns the max_batch_size of an agent of embeddings, or 0 when it is not
// known: the list of agents was never read, or does not name the agent. When the list
// cannot be read again the bounds read before stand.
func (c *Client) batchSize(ctx context.Context, agent string) int {
	c.mu.Lock()
	size, fresh := c.batches[agent], time.Since(c.batchesAt) < batchesTTL
	c.mu.Unlock()
	if fresh || c.calls.Models == nil {
		return size
	}

	list, err := c.Models(ctx)
	if err != nil {
		// a bound read before is a better guess than none, which sends the batch
		// whole to be refused; it is gone by again for another while before the
		// list is asked for anew
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.batches != nil {
			c.batchesAt = time.Now()
		}
		return c.batches[agent]
	}
	batches := make(map[string]int, len(list.Data))
	for _, info := range list.Data {
		if info.MaxBatchSize != nil {
			batches[info.ID] = int(*info.MaxBatchSize)
		}
	}
	c.mu.Lock()
	c.batches, c.batchesAt = batches, time.Now()
	c.mu.Unlock()
	return batches[agent]
}

// encode writes a value as JSON with every character of a string as it is: the inputs
// of a request go to the API as the caller wrote them.
func encode(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func respond(req *http.Request, contentType string, body io.ReadCloser) *http.Response {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {contentType}}, Body: body, ContentLength: -1, Request: req,
	}
}

// oneResult reads the stream of a call that is not streamed: its answer is the one
// result, complete only once the stream says so.
func oneResult(reader *sse.Reader) ([]byte, error) {
	var result []byte
	for {
		event, err := reader.Next()
		switch {
		case err == io.EOF:
			if result == nil {
				return nil, fmt.Errorf("%w: the answer ended without its result", sse.ErrMalformed)
			}
			return result, nil
		case err != nil:
			return nil, err
		case event.Name == models.LLMStreamEventResult && result == nil:
			result = event.Data
		case event.Name == models.LLMStreamEventResult, event.Name == models.LLMStreamEventChunk:
			return nil, fmt.Errorf("%w: a %s event in an answer of one result", sse.ErrMalformed, event.Name)
		}
	}
}

// streamBody is the body of a streamed chat completion: each chunk as a `data:` frame
// of the OpenAI API, as it arrives, and `data: [DONE]` once the stream is complete. A
// Read of it returns the failure of the stream: an *sse.Error, sse.ErrStreamCut. Read
// and Close may be called at once: Close ends a Read that waits.
type streamBody struct {
	reader  *sse.Reader
	body    io.Closer
	pending []byte
	done    bool
	close   sync.Once
}

var streamEnd = []byte("data: [DONE]\n\n")

func (b *streamBody) Read(p []byte) (int, error) {
	if err := b.fill(); err != nil {
		return 0, err
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

// fill reads the stream up to its next frame: a chunk, or [DONE] once the stream said it
// was done, and io.EOF after that.
func (b *streamBody) fill() error {
	for len(b.pending) == 0 {
		if b.done {
			return io.EOF
		}
		event, err := b.reader.Next()
		switch {
		case err == io.EOF:
			b.pending, b.done = streamEnd, true
		case err != nil:
			return err
		case event.Name == models.LLMStreamEventChunk:
			if len(event.Data) == 0 || event.Data[0] != '{' || bytes.IndexByte(event.Data, '\n') >= 0 {
				return fmt.Errorf("%w: a chunk that is not an object on one line", sse.ErrMalformed)
			}
			frame := make([]byte, 0, len(event.Data)+8)
			frame = append(frame, "data: "...)
			frame = append(frame, event.Data...)
			b.pending = append(frame, '\n', '\n')
		case event.Name == models.LLMStreamEventResult:
			return fmt.Errorf("%w: a result in a streamed answer", sse.ErrMalformed)
		}
	}
	return nil
}

func (b *streamBody) Close() error {
	var err error
	b.close.Do(func() { err = b.body.Close() })
	return err
}
