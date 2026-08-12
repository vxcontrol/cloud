package models

// PackageInfoRequest represents public API request to get package info.
//
// Version accepts the literal `latest`, which resolves to the highest published
// version for the requested (component, os, arch).
//
// Only components delivered as files have a package at all, exactly as for
// DownloadPackageRequest below. Validating one and not the other would let the
// SDK send a metadata request the service refuses, while refusing the download
// of the very same artefact locally.
type PackageInfoRequest struct {
	Component ComponentType `json:"component" validate:"required,valid,filecomp"`
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

// PackageInfoResponse represents response for package info.
//
// Hash is the sha256 of the package file and Signature is its Ed25519 signature
// over the file's SHA-512 digest. Both are always present, and both describe the
// PLAINTEXT file — the transport encryption is transparent and does not change
// them. Use Size for a download progress indicator: the encrypted response
// carries no Content-Length.
type PackageInfoResponse struct {
	Size      int64          `json:"size" validate:"required,min=1"`
	Hash      string         `json:"hash" validate:"required,sha256"`
	Version   string         `json:"version" validate:"required,semver"`
	OS        OSType         `json:"os" validate:"required,valid"`
	Arch      ArchType       `json:"arch" validate:"required,valid"`
	Signature SignatureValue `json:"signature" validate:"required,min=1,max=255"`
}

func (p PackageInfoResponse) Valid() error {
	return validate.Struct(p)
}

// DownloadPackageRequest represents public API request to download package.
//
// Only components distributed as downloadable files can be requested here; an
// image component has no package to download. Which components those are is the
// static table in artefacts.go, not a list written out here: the hand-written
// copies had already drifted into three different answers across the two sides,
// and the narrowest of them refused two components the service will serve.
type DownloadPackageRequest struct {
	Component ComponentType `json:"component" validate:"required,valid,filecomp"`
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
