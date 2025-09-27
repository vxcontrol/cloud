package models

// CheckUpdatesRequest represents public API request for checking updates
type CheckUpdatesRequest struct {
	InstallerVersion string   `json:"installer_version" validate:"required,semver"`
	InstallerOS      OSType   `json:"installer_os" validate:"required,valid"`
	InstallerArch    ArchType `json:"installer_arch" validate:"required,valid"`

	// Current installed components
	Components []ComponentInfo `json:"components" validate:"dive,valid"`
}

func (p CheckUpdatesRequest) Valid() error {
	return validate.Struct(p)
}

// ComponentInfo represents information about installed component
type ComponentInfo struct {
	Component  ComponentType   `json:"component" validate:"required,valid"`
	Status     ComponentStatus `json:"status" validate:"required,valid"`
	Version    *string         `json:"version,omitempty" validate:"omitempty,semver"`
	Hash       *string         `json:"hash,omitempty" validate:"omitempty,min=1,max=255"`
	Repository *string         `json:"repository,omitempty" validate:"omitempty,min=1,max=255"`
	Tag        *string         `json:"tag,omitempty" validate:"omitempty,min=1,max=100"`
}

func (c ComponentInfo) Valid() error {
	return validate.Struct(c)
}

// CheckUpdatesResponse represents response for update check
type CheckUpdatesResponse struct {
	Updates []UpdateInfo `json:"updates" validate:"dive,valid"`
}

func (c CheckUpdatesResponse) Valid() error {
	return validate.Struct(c)
}

// UpdateInfo represents available update information
type UpdateInfo struct {
	Stack          ProductStack `json:"stack" validate:"required,valid" swaggertype:"string"`
	HasUpdate      bool         `json:"has_update"`
	CurrentVersion *string      `json:"current_version,omitempty" validate:"omitempty,semver"`
	LatestVersion  *string      `json:"latest_version,omitempty" validate:"omitempty,semver"`
	Changelog      *string      `json:"changelog,omitempty" validate:"omitempty"`
	ReleaseNotes   *string      `json:"release_notes,omitempty" validate:"omitempty"`
}

func (u UpdateInfo) Valid() error {
	return validate.Struct(u)
}
