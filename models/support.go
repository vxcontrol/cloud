package models

import (
	"database/sql/driver"
	"encoding/json"
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

// The limits of an issue the server takes. The whole body is at most
// MaxSupportIssueRequestBytes; the lines of logs of all components together are at most
// MaxSupportIssueLogLines, and error_details, as it is written, at most
// MaxSupportIssueDetailsBytes. SupportIssueRequest.Valid checks the last two, which no
// tag can state; a body past any of them is refused by the server.
const (
	MaxSupportIssueRequestBytes = 2 << 20
	MaxSupportIssueLogLines     = 2000
	MaxSupportIssueDetailsBytes = 256 << 10
)

// SupportIssueRequest represents public API request to report an issue manually with AI assistance.
//
// ErrorDetails is any JSON value. The support assistant of PentAGI Cloud reads a
// SupportIssueDetails document as the context of the issue; any other form is kept as it
// is and tells the assistant nothing. Anonymise ErrorDetails and Logs before sending: use
// the anonymizer package.
type SupportIssueRequest struct {
	Component    ComponentType `json:"component" validate:"required,valid"`
	Version      string        `json:"version" validate:"required,semver"`
	OS           OSType        `json:"os" validate:"required,valid"`
	Arch         ArchType      `json:"arch" validate:"required,valid"`
	Logs         []SupportLogs `json:"logs" validate:"omitempty,dive,valid"`
	ErrorDetails any           `json:"error_details" validate:"required"`
}

func (sir SupportIssueRequest) Valid() error {
	if err := validate.Struct(sir); err != nil {
		return err
	}
	return validSupportIssueSize(sir.Logs, sir.ErrorDetails)
}

// validSupportIssueSize checks the limits of an issue a tag cannot state. error_details is
// measured as json.Encoder writes it without escaping HTML — the way to send it, and the
// way the server measures it: json.Marshal writes each <, > and & of tool output as six
// bytes and would refuse a document that travels well inside the limit.
func validSupportIssueSize(logs []SupportLogs, details any) error {
	lines := 0
	for _, component := range logs {
		lines += len(component.Logs)
	}
	if lines > MaxSupportIssueLogLines {
		return fmt.Errorf("an issue carries at most %d lines of logs, not %d", MaxSupportIssueLogLines, lines)
	}

	var size byteCounter
	encoder := json.NewEncoder(&size)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(details); err != nil {
		return fmt.Errorf("error_details: %w", err)
	}
	// Encode ends the value with a newline that is not part of it
	if int(size)-1 > MaxSupportIssueDetailsBytes {
		return fmt.Errorf("error_details is at most %d bytes, not %d", MaxSupportIssueDetailsBytes, int(size)-1)
	}
	return nil
}

// byteCounter is a writer that keeps only the number of bytes written to it.
type byteCounter int

func (c *byteCounter) Write(p []byte) (int, error) {
	*c += byteCounter(len(p))
	return len(p), nil
}

// SupportIssueDetails is the error_details of an issue the product reports: what the user
// wrote about the problem and what the product could tell about itself and the flow
// concerned. Versioned by Schema; it grows by adding fields, and a reader skips fields it
// does not know.
//
// Free text is anonymised by the sender: pass a pointer to the document to
// anonymizer.Anonymize. The fields of closed vocabularies, versions and references carry
// anonymizer:"skip", so that the walk leaves them as a reader matches them; numbers and
// booleans are never touched, nor are the keys of maps, which are names of closed sets.
// No field is []byte or json.RawMessage: the walk leaves their bytes as they are, and raw
// text in them would pass unmasked.
//
// Description is counted in runes; the lists are bounded so that a document stays far
// below MaxSupportIssueDetailsBytes.
type SupportIssueDetails struct {
	Schema       uint16                    `json:"schema" validate:"required,min=1" anonymizer:"skip"`
	Description  string                    `json:"description" validate:"max=4000"`
	CollectedAt  time.Time                 `json:"collected_at"`
	Product      SupportIssueProduct       `json:"product" validate:"valid"`
	Host         *SupportIssueHost         `json:"host,omitempty"`
	License      *SupportIssueLicense      `json:"license,omitempty"`
	Providers    []SupportIssueProvider    `json:"providers,omitempty" validate:"max=32"`
	Installation *SupportIssueInstallation `json:"installation,omitempty"`
	Flow         *SupportIssueFlow         `json:"flow,omitempty"`
	Logs         SupportIssueLogs          `json:"logs"`
	Findings     []SupportIssueFinding     `json:"findings,omitempty" validate:"max=64"`
	Skipped      []string                  `json:"skipped,omitempty" validate:"max=32"`
}

func (d SupportIssueDetails) Valid() error {
	return validate.Struct(d)
}

// SupportIssueProduct is the process of the product that reported the issue. OS and Arch
// are the platform it was built for — always linux for a product in Docker; the machine
// is SupportIssueHost.
type SupportIssueProduct struct {
	Version       string `json:"version" validate:"required,semver" anonymizer:"skip"`
	Develop       bool   `json:"develop"`
	OS            string `json:"os" anonymizer:"skip"`
	Arch          string `json:"arch" anonymizer:"skip"`
	BinaryHash    string `json:"binary_hash" anonymizer:"skip"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Debug         bool   `json:"debug"`
	DockerInside  bool   `json:"docker_inside"`
	DefaultImage  string `json:"default_image"`
	MultiTenant   bool   `json:"multi_tenant"`
}

func (p SupportIssueProduct) Valid() error {
	return validate.Struct(p)
}

// SupportIssueHost is the machine the Docker daemon of the product runs on, as the daemon
// describes it; the name of the host is not part of it.
type SupportIssueHost struct {
	DockerVersion string `json:"docker_version" anonymizer:"skip"`
	OS            string `json:"os" anonymizer:"skip"`
	OSType        string `json:"os_type" anonymizer:"skip"`
	Architecture  string `json:"architecture" anonymizer:"skip"`
	Kernel        string `json:"kernel" anonymizer:"skip"`
	CPUs          int    `json:"cpus"`
	MemoryBytes   int64  `json:"memory_bytes"`
}

// SupportIssueLicense is the licence of the installation as the product last read its
// status; the key is not part of it, masked or not. CheckedAt is nil before the first
// answer of the server.
type SupportIssueLicense struct {
	Tier      string          `json:"tier" anonymizer:"skip"`
	State     string          `json:"state" anonymizer:"skip"`
	Features  LicenseFeatures `json:"features"`
	ExpiresAt time.Time       `json:"expires_at"`
	CheckedAt *time.Time      `json:"checked_at,omitempty"`
}

// SupportIssueProvider is one LLM provider the product can use, without its name, its
// address or its keys. Ref ("p1", "p2", …) is what a flow and the use of a model point to;
// Models maps a type of agent to the model it is given. CreatedAt is set for a provider a
// user added, not for one of the environment.
type SupportIssueProvider struct {
	Ref       string            `json:"ref" anonymizer:"skip"`
	Type      string            `json:"type" anonymizer:"skip"`
	Source    string            `json:"source" anonymizer:"skip"`
	CreatedAt *time.Time        `json:"created_at,omitempty"`
	Models    map[string]string `json:"models,omitempty"`
}

// SupportIssueInstallation is what the installation is made of: its features and its
// counts, each by name. The use of tokens over the whole installation is not part of it.
type SupportIssueInstallation struct {
	EmbeddingProvider string           `json:"embedding_provider" anonymizer:"skip"`
	OAuth             []string         `json:"oauth,omitempty"`
	Features          map[string]bool  `json:"features,omitempty"`
	Counts            map[string]int64 `json:"counts,omitempty"`
}

// SupportIssueFlow is the flow the issue is reported for. No title, input or result of it
// travels: a failure is told by its kind, its status and a class of error. ProviderRef is
// the Ref of the flow's provider in Providers, null when that provider is gone.
type SupportIssueFlow struct {
	ID                int64                    `json:"id"`
	Status            string                   `json:"status" anonymizer:"skip"`
	Language          string                   `json:"language"`
	ProviderRef       *string                  `json:"provider_ref" anonymizer:"skip"`
	ProviderType      string                   `json:"provider_type" anonymizer:"skip"`
	Model             string                   `json:"model"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	TimeBudgetSeconds int64                    `json:"time_budget_seconds"`
	MaxSubtasks       int                      `json:"max_subtasks"`
	MaxSubagents      int                      `json:"max_subagents"`
	Tasks             SupportIssueCounts       `json:"tasks"`
	Subtasks          SupportIssueCounts       `json:"subtasks"`
	Assistants        SupportIssueCounts       `json:"assistants"`
	Usage             SupportIssueUsage        `json:"usage"`
	Toolcalls         SupportIssueToolcalls    `json:"toolcalls"`
	UsageByModel      []SupportIssueModelUsage `json:"usage_by_model,omitempty" validate:"max=10"`
	UsageByAgent      []SupportIssueAgentUsage `json:"usage_by_agent,omitempty"`
	Chains            SupportIssueChains       `json:"chains"`
	Container         *SupportIssueContainer   `json:"container,omitempty"`
	Errors            []SupportIssueFlowError  `json:"errors,omitempty" validate:"max=30"`
}

// SupportIssueCounts counts the things of one kind in a flow, in all and by status.
type SupportIssueCounts struct {
	Total    int64            `json:"total"`
	ByStatus map[string]int64 `json:"by_status,omitempty"`
}

// SupportIssueUsage is a use of tokens and its cost.
type SupportIssueUsage struct {
	In       int64   `json:"in"`
	Out      int64   `json:"out"`
	CacheIn  int64   `json:"cache_in"`
	CacheOut int64   `json:"cache_out"`
	CostIn   float64 `json:"cost_in"`
	CostOut  float64 `json:"cost_out"`
}

// SupportIssueToolcalls are the tool calls of a flow; ByFunction holds the functions
// called most.
type SupportIssueToolcalls struct {
	Total           int64                  `json:"total"`
	Failed          int64                  `json:"failed"`
	DurationSeconds float64                `json:"duration_seconds"`
	ByFunction      []SupportIssueFunction `json:"by_function,omitempty" validate:"max=10"`
}

// SupportIssueFunction are the calls of one function; IsAgent tells a function that
// hands the work to another agent from a tool.
type SupportIssueFunction struct {
	Name    string `json:"name"`
	IsAgent bool   `json:"is_agent"`
	Count   int64  `json:"count"`
	Failed  int64  `json:"failed"`
}

// SupportIssueModelUsage is the use of one model in a flow and the types of agents that
// called it; its numbers are those of SupportIssueUsage, in line.
type SupportIssueModelUsage struct {
	Model       string   `json:"model"`
	ProviderRef *string  `json:"provider_ref" anonymizer:"skip"`
	Agents      []string `json:"agents,omitempty" anonymizer:"skip"`
	SupportIssueUsage
}

// SupportIssueAgentUsage is the use of one type of agent in a flow; its numbers are those
// of SupportIssueUsage, in line.
type SupportIssueAgentUsage struct {
	Agent string `json:"agent" anonymizer:"skip"`
	SupportIssueUsage
}

// SupportIssueChains are the runs of the agents of a flow that tell of trouble when they
// run often or fail.
type SupportIssueChains struct {
	Reflector     SupportIssueTally `json:"reflector"`
	ToolCallFixer SupportIssueTally `json:"tool_call_fixer"`
	Subagents     SupportIssueTally `json:"subagents"`
}

// SupportIssueTally counts runs and the ones of them that failed.
type SupportIssueTally struct {
	Total  int64 `json:"total"`
	Failed int64 `json:"failed"`
}

// SupportIssueContainer is the primary container of a flow: its image, its status as the
// product recorded it, and Live, what the Docker daemon says of it now (running, stopped,
// unknown).
type SupportIssueContainer struct {
	Image  string `json:"image"`
	Status string `json:"status" anonymizer:"skip"`
	Live   string `json:"live" anonymizer:"skip"`
}

// SupportIssueFlowError is one failure in a flow: a tool call, a task or a subtask. The
// text of its result does not travel — it is output of the target, which no anonymiser
// can clean — only its length and ErrorClass, a word of a closed vocabulary the product
// infers from it.
type SupportIssueFlowError struct {
	Kind         string    `json:"kind" anonymizer:"skip"`
	Name         string    `json:"name"`
	Status       string    `json:"status" anonymizer:"skip"`
	ErrorClass   string    `json:"error_class" anonymizer:"skip"`
	ResultLength int       `json:"result_length"`
	CreatedAt    time.Time `json:"created_at"`
}

// SupportIssueLogs describes the lines of logs sent with the issue: Lines sent and Matched
// before repeats were folded, the times of the first and the last, and the counts of the
// patterns of trouble by name.
type SupportIssueLogs struct {
	Available   bool                  `json:"available"`
	Lines       int                   `json:"lines"`
	Matched     int                   `json:"matched"`
	Files       int                   `json:"files"`
	From        *time.Time            `json:"from,omitempty"`
	To          *time.Time            `json:"to,omitempty"`
	Truncated   bool                  `json:"truncated"`
	DroppedLong int                   `json:"dropped_long"`
	Filter      SupportIssueLogFilter `json:"filter"`
	Counts      map[string]int64      `json:"counts,omitempty"`
}

// SupportIssueLogFilter is how the lines were chosen: Scope is the flow they were chosen
// for, nil for none; Admin is a reporter who may send the lines of every user;
// RedactedKeys are the keys whose values were replaced by their length.
type SupportIssueLogFilter struct {
	Scope        *int64   `json:"scope,omitempty"`
	Admin        bool     `json:"admin"`
	RedactedKeys []string `json:"redacted_keys,omitempty"`
}

// SupportIssueFinding is a known problem the product detected in what it collected.
type SupportIssueFinding struct {
	Code     string `json:"code" anonymizer:"skip"`
	Severity string `json:"severity" anonymizer:"skip"`
	Detail   string `json:"detail"`
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
	// UseStream switches the answer to an event stream (`text/event-stream`)
	// instead of a single JSON response. Bind a call type that returns a reader
	// and read the stream with the sdk/sse package.
	//
	// The stream opens with a `start` event (SupportStreamStart) and carries the
	// events of SupportStreamEvent — the answer as it is produced — between
	// `heartbeat` frames that keep the connection alive. It ends with exactly one
	// of `done` and `error`: the answer is complete if and only if `done` arrived.
	// A failure arrives as an `error` event carrying the code of the refusal,
	// because the status is already sent; a stream that ends without either was
	// cut, and what it carried is not an answer.
	//
	// A streamed answer is NOT wrapped in the response envelope; the non-stream
	// form is.
	UseStream bool   `json:"use_stream,omitempty" validate:"omitempty"`
	UserInput string `json:"user_input" validate:"required,min=1,max=4000"`
}

func (sir SupportInvestigationRequest) Valid() error {
	return validate.Struct(sir)
}

// SupportStreamEvent names an event of a streamed investigation, beside the events of
// the stream itself (start, heartbeat, error, done), which the sdk/sse package knows.
type SupportStreamEvent string

const (
	// SupportStreamEventMessage is an entry of the conversation log:
	// SupportStreamMessage.
	SupportStreamEventMessage SupportStreamEvent = "message"
	// SupportStreamEventThinking is a delta of the model's reasoning:
	// SupportStreamThinking.
	SupportStreamEventThinking SupportStreamEvent = "thinking"
	// SupportStreamEventContent is a delta of the answer: SupportStreamContent.
	SupportStreamEventContent SupportStreamEvent = "content"
	// SupportStreamEventFlush ends the deltas of one model call: SupportStreamFlush.
	SupportStreamEventFlush SupportStreamEvent = "flush"
	// SupportStreamEventUpdate is the whole answer and reasoning of one model call,
	// sent after its flush, for a client that did not accumulate the deltas:
	// SupportStreamUpdate.
	SupportStreamEventUpdate SupportStreamEvent = "update"
)

func (sse SupportStreamEvent) String() string {
	return string(sse)
}

func (sse SupportStreamEvent) Valid() error {
	switch sse {
	case SupportStreamEventMessage, SupportStreamEventThinking, SupportStreamEventContent,
		SupportStreamEventUpdate, SupportStreamEventFlush:
		return nil
	default:
		return fmt.Errorf("invalid SupportStreamEvent: %s", sse)
	}
}

// SupportStreamStart is the data of the `start` event of an investigation.
type SupportStreamStart struct {
	IssueID uuid.UUID `json:"issue_id"`
}

// SupportStreamMessage is the data of a `message` event. An entry of type
// MsgLogTypeDone is not sent: the end of the answer is the `done` event.
type SupportStreamMessage struct {
	Message string     `json:"message"`
	Type    MsgLogType `json:"type"`
}

// SupportReasoning is the reasoning a model produced before its answer: the text, and
// the signature some providers issue with it and require back, together with the
// text, on the next turn of a conversation. It has the wire form of langchaingo's
// reasoning.ContentReasoning, so it can be handed to that library as it arrives.
type SupportReasoning struct {
	Content   string `json:"content,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// SupportStreamThinking is the data of a `thinking` event; StreamID numbers the model
// calls of one investigation from 1.
type SupportStreamThinking struct {
	StreamID int64             `json:"stream_id"`
	Thinking *SupportReasoning `json:"thinking"`
}

// SupportStreamContent is the data of a `content` event.
type SupportStreamContent struct {
	Content  string `json:"content"`
	StreamID int64  `json:"stream_id"`
}

// SupportStreamUpdate is the data of an `update` event; Thinking is nil for a model
// call that reasoned nothing.
type SupportStreamUpdate struct {
	Content  string            `json:"content"`
	StreamID int64             `json:"stream_id"`
	Thinking *SupportReasoning `json:"thinking"`
}

// SupportStreamFlush is the data of a `flush` event.
type SupportStreamFlush struct {
	StreamID int64 `json:"stream_id"`
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

// SupportIssueStatus is what runs on a support issue. An issue reported with logs is
// processing until the server has worked through them; a question may be sent once it is
// processed, and the issue is answering while the assistant answers one. A question sent
// at any other time is refused with the code Support.Busy.
type SupportIssueStatus string

const (
	SupportIssueStatusProcessing SupportIssueStatus = "processing" // the logs of the issue are being processed
	SupportIssueStatusProcessed  SupportIssueStatus = "processed"  // nothing runs: a turn may be sent
	SupportIssueStatusAnswering  SupportIssueStatus = "answering"  // a turn of the conversation is running
)

func (s SupportIssueStatus) String() string {
	return string(s)
}

func (s SupportIssueStatus) Valid() error {
	switch s {
	case SupportIssueStatusProcessing, SupportIssueStatusProcessed, SupportIssueStatusAnswering:
		return nil
	default:
		return fmt.Errorf("invalid SupportIssueStatus: %s", s)
	}
}

// SupportIssueStatusResponse is the status of an issue. UpdatedAt is when the
// conversation of the issue last changed — a question asked, a call of the model — and is
// absent before the first question: re-read the messages of the issue when it moves.
type SupportIssueStatusResponse struct {
	Status    SupportIssueStatus `json:"status" validate:"required,valid"`
	UpdatedAt *time.Time         `json:"updated_at,omitempty" validate:"omitempty"`
}

func (r SupportIssueStatusResponse) Valid() error {
	return validate.Struct(r)
}
