package models

import (
	"encoding/json"
)

// MaxProductInfoBytes bounds the state document an update carries.
const MaxProductInfoBytes = 16384

// ProductUpdateRequest is how a running product asks the update service what it
// should be running, telling it what it currently is so the answer is about this
// installation rather than about a version string alone.
//
// The fields above Info are the ones every such request has and is grouped by, so
// they are typed and validated here. Info is the state summary itself, and it is
// deliberately opaque to this contract: its shape is versioned by the `schema`
// value inside it rather than by this structure, so a product can describe more of
// itself without a contract change and without every client in between needing to
// understand what it is carrying.
//
// The installation this belongs to travels in the SDK headers, as with every other
// call, and is not part of the body.
type ProductUpdateRequest struct {
	// Schema selects the reader for Info. It is outside Info as well as inside it
	// because a document that fails to parse still has to be routed somewhere, and
	// a router that must first parse the thing it is routing is not a router.
	Schema uint16 `json:"schema" validate:"required,min=1"`

	// Version is the product build this describes. It is the one field the service
	// can use even when it has no reader for the document.
	Version string `json:"version" validate:"required,semver"`

	OS   OSType   `json:"os" validate:"required,valid"`
	Arch ArchType `json:"arch" validate:"required,valid"`

	// BinaryHash is the sha256 of the executable that is running, when it can be
	// determined. It is what distinguishes a build from another build carrying the
	// same version string, which is the normal case outside a release.
	BinaryHash string `json:"binary_hash,omitempty" validate:"omitempty,sha256"`

	// Strategy is which channel to answer from, exactly as in CheckUpdatesRequest.
	// Optional: a build made before the field existed sends none, and the service
	// answers such a request under its own default rather than refusing it.
	Strategy UpdateStrategy `json:"strategy,omitempty" validate:"omitempty,valid"`

	// Info is the state document. Bounded because nothing else bounds it.
	Info json.RawMessage `json:"info" validate:"required,max=16384"`
}

func (p ProductUpdateRequest) Valid() error {
	return validate.Struct(p)
}

// ProductUpdateResponse is what the service answers such a request with.
//
// Update is the ordinary per-stack answer of a check-updates call, so a client
// that already reads one reads this. Binary is the same build expressed as a
// downloadable executable, for a product that replaces its own binary instead of
// waiting for its container image to be pulled — the two always describe ONE
// build, because the executable is looked up by the version of the image offered.
type ProductUpdateResponse struct {
	// Update is the pentagi stack's answer, absent only when the service publishes
	// nothing at all for this platform.
	Update *UpdateInfo `json:"update,omitempty" validate:"omitempty,valid"`

	// Version is the product version of the offered image, and it is what Binary
	// is keyed on. Absent when the offered image declares no version.
	Version *string `json:"version,omitempty" validate:"omitempty,semver"`

	// Binary is the executable of that version, when one is published for this
	// platform — exactly what a packages/info call would answer, so a caller can
	// go straight to packages/download.
	Binary *PackageInfoResponse `json:"binary,omitempty" validate:"omitempty,valid"`

	// Identified says the reported build was matched to an image the service
	// published.
	//
	// False is not an error. It means the answer describes the newest published
	// build rather than a step from the one that is running, so `action` reads
	// `install` and the digests in Update must NOT be taken as a statement about
	// what this installation has. It is what a development build, a private
	// rebuild, or an image published before the version label existed gets.
	Identified bool `json:"identified"`
}

func (p ProductUpdateResponse) Valid() error {
	return validate.Struct(p)
}
