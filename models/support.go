package models

import "github.com/google/uuid"

// SupportErrorRequest represents public API request to report an error automatically
type SupportErrorRequest struct {
	Component    ComponentType `json:"component" validate:"required,valid"`
	Version      string        `json:"version" validate:"required,semver"`
	OS           OSType        `json:"os" validate:"required,valid"`
	Arch         ArchType      `json:"arch" validate:"required,valid"`
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
	Logs         []SupportLogs `json:"logs" validate:"omitempty,valid"`
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
	IssueID uuid.UUID `json:"issue_id" validate:"required"`
}

func (sir SupportIssueResponse) Valid() error {
	return validate.Struct(sir)
}

// SupportInvestigationRequest represents public API request to investigate an issue with AI assistance
type SupportInvestigationRequest struct {
	IssueID   uuid.UUID `json:"issue_id" validate:"required"`
	UseSteam  bool      `json:"use_steam,omitempty" validate:"omitempty"`
	UserInput string    `json:"user_input" validate:"required,min=1,max=4000"`
}

func (sir SupportInvestigationRequest) Valid() error {
	return validate.Struct(sir)
}

// SupportInvestigationResponse represents response for investigation of issue with AI assistance (without steam response)
type SupportInvestigationResponse struct {
	Answer string `json:"answer" validate:"required"`
}

func (sir SupportInvestigationResponse) Valid() error {
	return validate.Struct(sir)
}
