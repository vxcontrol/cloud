package models

import (
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SupportErrorRequest represents public API request to report an error automatically.
//
// Anonymise ErrorDetails and Logs before sending: use the anonymizer package.
// Nothing on the wire is scrubbed for you.
type SupportErrorRequest struct {
	Component    ComponentType `json:"component" validate:"required,valid"`
	Version      string        `json:"version" validate:"required,semver"`
	OS           OSType        `json:"os" validate:"required,valid"`
	Arch         ArchType      `json:"arch" validate:"required,valid"`
	Logs         []SupportLogs `json:"logs" validate:"omitempty,dive,valid"`
	ErrorDetails any           `json:"error_details" validate:"required"`
}

func (p SupportErrorRequest) Valid() error {
	return validate.Struct(p)
}

// SupportErrorResponse represents response for error reporting (empty for now, reserved for future)
type SupportErrorResponse struct {
	// Reserved for future expansion
}

func (ser SupportErrorResponse) Valid() error {
	return validate.Struct(ser)
}

// SupportIssueRequest represents public API request to report an issue manually with AI assistance
type SupportIssueRequest struct {
	Component    ComponentType `json:"component" validate:"required,valid"`
	Version      string        `json:"version" validate:"required,semver"`
	OS           OSType        `json:"os" validate:"required,valid"`
	Arch         ArchType      `json:"arch" validate:"required,valid"`
	Logs         []SupportLogs `json:"logs" validate:"omitempty,dive,valid"`
	ErrorDetails any           `json:"error_details" validate:"required"`
}

func (sir SupportIssueRequest) Valid() error {
	return validate.Struct(sir)
}

// SupportLogs represents logs for a component
type SupportLogs struct {
	Component ComponentType `json:"component" validate:"required,valid"`
	Logs      []string      `json:"logs" validate:"omitempty,dive,min=1,max=8192"`
}

func (sl SupportLogs) Valid() error {
	return validate.Struct(sl)
}

// SupportIssueResponse represents response for issue reporting with AI assistance
type SupportIssueResponse struct {
	IssueID uuid.UUID `json:"issue_id" validate:"required,uuid"`
}

func (sir SupportIssueResponse) Valid() error {
	return validate.Struct(sir)
}

// SupportInvestigationRequest represents public API request to investigate an issue with AI assistance
type SupportInvestigationRequest struct {
	IssueID uuid.UUID `json:"issue_id" validate:"required,uuid"`
	// UseStream switches the answer to a Server-Sent Events stream
	// (`text/event-stream`) instead of a single JSON response. Bind a streaming
	// call type — a reader or a writer — to receive it.
	//
	// The stream opens with a `start` event and ends with `done`; in between come
	// `message`, `thinking`, `content`, `update` and `flush` events carrying the
	// answer as it is produced, plus periodic `heartbeat` events that keep the
	// connection alive and must be ignored. A failure arrives as an `error`
	// event rather than an HTTP status, because the headers are already sent.
	//
	// A streamed answer is NOT wrapped in the response envelope; the non-stream
	// form is.
	UseStream bool   `json:"use_stream,omitempty" validate:"omitempty"`
	UserInput string `json:"user_input" validate:"required,min=1,max=4000"`
}

func (sir SupportInvestigationRequest) Valid() error {
	return validate.Struct(sir)
}

// MsgLogType represents the kind of a conversation message
type MsgLogType string

const (
	MsgLogTypeWait   MsgLogType = "wait"
	MsgLogTypeCode   MsgLogType = "code"
	MsgLogTypeSearch MsgLogType = "search"
	MsgLogTypeAgent  MsgLogType = "agent"
	MsgLogTypeInput  MsgLogType = "input"
	MsgLogTypeDone   MsgLogType = "done"
)

func (mt MsgLogType) String() string {
	return string(mt)
}

func (mt *MsgLogType) Scan(value any) error {
	if value == nil {
		*mt = ""
		return nil
	}
	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*mt = MsgLogType(v)
			return nil
		}
	}
	return fmt.Errorf("cannot scan %T into MsgLogType", value)
}

func (mt MsgLogType) Value() (driver.Value, error) {
	return string(mt), nil
}

func (mt MsgLogType) Valid() error {
	switch mt {
	case MsgLogTypeWait, MsgLogTypeCode, MsgLogTypeSearch, MsgLogTypeAgent,
		MsgLogTypeInput, MsgLogTypeDone:
		return nil
	default:
		return fmt.Errorf("invalid MsgLogType: %s", mt)
	}
}

// SupportMsgLog is one message of an investigation conversation, in anonymised form
type SupportMsgLog struct {
	Type      MsgLogType `json:"type" validate:"required,valid"`
	Message   string     `json:"message" validate:"required"`
	CreatedAt time.Time  `json:"created_at"`
}

func (sm SupportMsgLog) Valid() error {
	return validate.Struct(sm)
}

// SupportInvestigationResponse represents response for investigation of issue with AI assistance
// (the non-streaming form)
type SupportInvestigationResponse struct {
	Answer  string          `json:"answer" validate:"required"`
	MsgLogs []SupportMsgLog `json:"msg_logs,omitempty" validate:"omitempty,dive,valid"`
}

func (sir SupportInvestigationResponse) Valid() error {
	return validate.Struct(sir)
}

// SupportIssueMessagesResponse represents the conversation of a support issue
type SupportIssueMessagesResponse struct {
	Messages []SupportMsgLog `json:"messages" validate:"omitempty,dive,valid"`
}

func (simr SupportIssueMessagesResponse) Valid() error {
	return validate.Struct(simr)
}
