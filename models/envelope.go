package models

import (
	"encoding/json"
	"fmt"
)

// Envelope is the JSON wrapper every non-streaming API answer arrives in.
//
// Unmarshalling a response body straight into its payload type is the mistake
// this type exists to prevent: `{"status":"success","data":{…}}` decodes into
// CheckUpdatesResponse without error and yields an EMPTY list of updates, so a
// client concludes "nothing to install" and never learns it was wrong.
//
// Binary downloads are the one exception — they carry the file itself, with no
// envelope around it.
type Envelope[T any] struct {
	Status string `json:"status"`
	Data   T      `json:"data"`

	// Set on failures instead of Data. Msg and Error are filled in only by a
	// server running in development mode.
	Code  string `json:"code,omitempty"`
	Msg   string `json:"msg,omitempty"`
	Error string `json:"error,omitempty"`
}

// StatusSuccess is the only Status value that carries a payload.
const StatusSuccess = "success"

// APIError is a failure the server described in the response envelope. It is
// returned for a 2xx body whose status is not "success"; transport-level and
// HTTP-status failures surface as SDK errors instead.
type APIError struct {
	Code  string
	Msg   string
	Cause string
}

func (e *APIError) Error() string {
	switch {
	case e.Cause != "":
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Msg, e.Cause)
	case e.Msg != "":
		return fmt.Sprintf("%s: %s", e.Code, e.Msg)
	case e.Code != "":
		return e.Code
	default:
		return "unexpected API response"
	}
}

// ParseEnvelope decodes an API response body and returns its payload.
//
//	resp, err := models.ParseEnvelope[models.CheckUpdatesResponse](body)
//
// A body whose status is not "success" yields an *APIError describing what the
// server reported.
func ParseEnvelope[T any](body []byte) (T, error) {
	var envelope Envelope[T]
	if err := json.Unmarshal(body, &envelope); err != nil {
		var zero T
		return zero, fmt.Errorf("failed to decode API response: %w", err)
	}

	if envelope.Status != StatusSuccess {
		var zero T
		return zero, &APIError{
			Code:  envelope.Code,
			Msg:   envelope.Msg,
			Cause: envelope.Error,
		}
	}

	return envelope.Data, nil
}
