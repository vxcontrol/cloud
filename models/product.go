package models

import (
	"encoding/json"
)

// MaxProductInfoBytes bounds the state document an update carries.
const MaxProductInfoBytes = 16384

// ProductUpdateRequest is how a running product tells the update service what it
// currently is, so that update decisions can be made against the installation
// rather than against a version string alone.
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

	// Info is the state document. Bounded because nothing else bounds it.
	Info json.RawMessage `json:"info" validate:"required,max=16384"`
}

func (p ProductUpdateRequest) Valid() error {
	return validate.Struct(p)
}
