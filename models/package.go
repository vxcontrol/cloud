package models

// PackageInfoRequest represents public API request to get package info
type PackageInfoRequest struct {
	Component ComponentType `json:"component" validate:"required,valid"`
	Version   string        `json:"version" validate:"required,semver"`
	OS        OSType        `json:"os" validate:"required,valid"`
	Arch      ArchType      `json:"arch" validate:"required,valid"`
}

func (p PackageInfoRequest) Valid() error {
	return validate.Struct(p)
}

func (p PackageInfoRequest) Query() map[string]string {
	return map[string]string{
		"component": p.Component.String(),
		"version":   p.Version,
		"os":        p.OS.String(),
		"arch":      p.Arch.String(),
	}
}

// PackageInfoResponse represents response for package info
type PackageInfoResponse struct {
	Size      int64          `json:"size" validate:"required,min=1"`
	Hash      string         `json:"hash" validate:"required,len=64"`
	Version   string         `json:"version" validate:"required,semver"`
	OS        OSType         `json:"os" validate:"required,valid"`
	Arch      ArchType       `json:"arch" validate:"required,valid"`
	Signature SignatureValue `json:"signature,omitempty" validate:"omitempty,valid"`
}

func (p PackageInfoResponse) Valid() error {
	return validate.Struct(p)
}

// DownloadPackageRequest represents public API request to download package
type DownloadPackageRequest struct {
	Component ComponentType `json:"component" validate:"required,valid"`
	Version   string        `json:"version" validate:"required,semver"`
	OS        OSType        `json:"os" validate:"required,valid"`
	Arch      ArchType      `json:"arch" validate:"required,valid"`
}

func (p DownloadPackageRequest) Valid() error {
	return validate.Struct(p)
}

func (p DownloadPackageRequest) Query() map[string]string {
	return map[string]string{
		"component": p.Component.String(),
		"version":   p.Version,
		"os":        p.OS.String(),
		"arch":      p.Arch.String(),
	}
}
