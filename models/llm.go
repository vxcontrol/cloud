package models

import "fmt"

// LLMModelType says which call of the OpenAI API an agent of Cloud LLM serves.
type LLMModelType string

const (
	LLMModelTypeCompletion LLMModelType = "completion"
	LLMModelTypeEmbedding  LLMModelType = "embedding"
)

func (t LLMModelType) Valid() error {
	switch t {
	case LLMModelTypeCompletion, LLMModelTypeEmbedding:
		return nil
	default:
		return fmt.Errorf("invalid LLMModelType: %s", t)
	}
}

// The events of a streamed LLM call, beside the four of the stream itself (sdk/sse):
// one "chunk" for each chat.completion.chunk of a streamed chat completion, and one
// "result" for the whole answer of a call that is not streamed — a chat completion or
// the list of vectors of an embeddings call. Their data are the objects of the OpenAI
// API, with `model` the name of the model that served the call.
const (
	LLMStreamEventChunk  = "chunk"
	LLMStreamEventResult = "result"
)

// LLMModelInfo is what a licensed installation is told of an agent it may name in the
// `model` of a request: the model object of the OpenAI API — ID the name of the agent,
// Created when the agent was created in Unix seconds, OwnedBy "pentagi" — and what a
// caller needs to call it. ContextWindow is of the model that serves the licence,
// MaxOutputTokens the most output a request may ask for, MaxInputSize the largest body
// of a request in bytes. SupportedParameters are the request parameters a caller may
// set — the rest of a request is the agent's and is not used; both spellings of the
// output limit, max_tokens and max_completion_tokens, are taken where one is — and are
// always a list: an empty one is none, never unknown. Dimensions and MaxBatchSize are of
// an agent of embeddings: a batch larger than MaxBatchSize is split by the caller.
type LLMModelInfo struct {
	ID                  string       `json:"id" validate:"required"`
	Object              string       `json:"object" validate:"eq=model"`
	Created             int64        `json:"created" validate:"min=0"`
	OwnedBy             string       `json:"owned_by" validate:"required"`
	Type                LLMModelType `json:"type" validate:"required,valid"`
	Description         string       `json:"description,omitempty"`
	ContextWindow       *int64       `json:"context_window,omitempty"`
	MaxOutputTokens     *int64       `json:"max_output_tokens,omitempty"`
	MaxInputSize        int64        `json:"max_input_size" validate:"min=1"`
	SupportedParameters []string     `json:"supported_parameters" validate:"required"`
	Dimensions          *int64       `json:"dimensions,omitempty"`
	MaxBatchSize        *int64       `json:"max_batch_size,omitempty"`
}

func (i LLMModelInfo) Valid() error {
	return validate.Struct(i)
}

// LLMModelsResponse is the list object of the OpenAI API: the agents a licence may call,
// and only those. Object is "list" — a body of another shape, read leniently, would
// otherwise pass as a licence offered no agent.
type LLMModelsResponse struct {
	Object string         `json:"object" validate:"eq=list"`
	Data   []LLMModelInfo `json:"data"`
}

func (r LLMModelsResponse) Valid() error {
	if err := validate.Struct(r); err != nil {
		return err
	}
	for _, info := range r.Data {
		if err := info.Valid(); err != nil {
			return fmt.Errorf("model %q: %w", info.ID, err)
		}
	}
	return nil
}
