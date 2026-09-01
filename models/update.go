package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// UpdateStrategy selects how the server answers each component.
//
//   - nightly: the newest artefact published in the channel the client follows,
//     with no curated release involved and no version metadata in the answer.
//   - preview: the channels decide what is offered, and the stack's latest
//     release contributes only metadata (version, changelog, release notes).
//   - stable: the client stays inside the artefacts of the latest curated
//     stable release, and the tag it reports is not consulted at all. A stack
//     with NO release still follows that tag; a component the release does not
//     cover is answered `unknown` with a reason, never from its channel —
//     answering part of the installation from outside the curated set is the
//     promise `stable` makes, quietly broken.
//
// The field is required and has no default: "which updates do you want" is a
// decision only the client can make.
type UpdateStrategy string

const (
	UpdateStrategyNightly UpdateStrategy = "nightly"
	UpdateStrategyPreview UpdateStrategy = "preview"
	UpdateStrategyStable  UpdateStrategy = "stable"
)

func (us UpdateStrategy) String() string {
	return string(us)
}

func (us UpdateStrategy) Valid() error {
	switch us {
	case UpdateStrategyNightly, UpdateStrategyPreview, UpdateStrategyStable:
		return nil
	default:
		return fmt.Errorf("invalid UpdateStrategy: %s", us)
	}
}

// CheckUpdatesRequest represents public API request for checking updates.
//
// The installation ID and the license key are NOT part of the body: the SDK
// carries them in headers, and the server fills them in.
type CheckUpdatesRequest struct {
	InstallerVersion string         `json:"installer_version" validate:"required,semver"`
	InstallerOS      OSType         `json:"installer_os" validate:"required,valid"`
	InstallerArch    ArchType       `json:"installer_arch" validate:"required,valid"`
	Strategy         UpdateStrategy `json:"strategy" validate:"required,valid"`

	// Images and Files are the two kinds of artefact a client can run, reported
	// separately because they ARE different things: an image is identified by a
	// registry reference and a digest, a file by a version and a hash, and no
	// artefact is ever both.
	//
	// One list of half-filled structures could not say which kind a row was, so
	// the server guessed from which fields happened to be set — and a row that
	// filled none of them (a component the client knows about but has not
	// installed) matched no branch of the guess and fell out of the answer with
	// no error and no trace.
	Images []ImageComponentInfo `json:"images" validate:"max=60,dive,valid"`
	Files  []FileComponentInfo  `json:"files" validate:"max=60,dive,valid"`

	// Stacks is what the installation says about each product stack it knows of.
	// Nothing in the answer depends on it — it is reported for its own sake.
	//
	// The component lists cannot express a stack that runs somewhere else: such a
	// stack contributes no images, because there is no reference to resolve, so
	// "hosted externally" and "not used at all" arrive identical. Report every
	// stack you know of, including the unused ones — saying `unused` is worth
	// more than silence, which cannot be told from a client too old to report.
	Stacks []StackInfo `json:"stacks" validate:"max=16,dive,valid"`

	// Info is what the product reports about its own state, passed through
	// unchanged by whoever collected it. Optional, and its shape is versioned
	// inside the document rather than by this field, so a newer product can
	// describe more without the client that carries it knowing anything about
	// the contents.
	//
	// Bounded, because nothing else bounds it: this endpoint reads the request
	// body without a size limit, and an unbounded passthrough field is an
	// unbounded write into whatever stores it.
	Info json.RawMessage `json:"info,omitempty" validate:"omitempty,max=16384"`
}

// MaxReportedComponents bounds how many artefacts one request may report.
//
// It counts the two lists TOGETHER. Bounding each separately would let a caller
// send twice the limit by splitting the payload, which is not a limit at all —
// which is also why the per-list tags below are the same number rather than half
// of it: a lopsided report is not an abusive one, and a per-list bound under this
// one would refuse a legal request before this rule ever ran.
//
// Sixty rather than the number that fits: a full deployment reports 28 today, and
// the client that assembles the list TRUNCATES at this value rather than being
// refused — so a ceiling close to the inventory silently drops components instead
// of failing loudly. The cost behind it is one query per artefact on the service
// side, which is why it is a bound at all.
const MaxReportedComponents = 60

func (p CheckUpdatesRequest) Valid() error {
	if err := validate.Struct(p); err != nil {
		return err
	}
	if total := len(p.Images) + len(p.Files); total > MaxReportedComponents {
		return fmt.Errorf("a request may report at most %d artefacts, got %d images and %d files",
			MaxReportedComponents, len(p.Images), len(p.Files))
	}
	// Splitting the lists was not on its own enough to make "the wrong list"
	// impossible, and the gap is asymmetric. An image reported under `files`
	// loses its repository and tag — fields FileComponentInfo does not have — and
	// nothing in the per-element rules notices, because the two kinds differ not
	// by which fields are filled but by which artefacts answer them. Only the
	// static table knows, so it is consulted here.
	//
	// FileImage is in both lists: the image an installer pulls, and the file a
	// running product replaces itself with, are two artefacts of one component.
	for i, image := range p.Images {
		if !image.Component.IsImageComponent() {
			return fmt.Errorf("images[%d]: %s is delivered as a %s, report it under files",
				i, image.Component, image.Component.ArtifactKind())
		}
	}
	for i, file := range p.Files {
		if !file.Component.IsFileComponent() {
			return fmt.Errorf("files[%d]: %s is delivered as a %s, report it under images",
				i, file.Component, file.Component.ArtifactKind())
		}
	}
	return nil
}

// ImageComponentInfo describes one container image the client runs.
//
// OS and Arch belong to the ARTEFACT, not to the host running the client: a
// container image is linux even on a darwin or windows host, and its
// architecture is the image's own. Reporting the host platform for an image
// means no published artefact will ever match it.
type ImageComponentInfo struct {
	Component ComponentType   `json:"component" validate:"required,valid"`
	Status    ComponentStatus `json:"status" validate:"required,valid"`
	OS        OSType          `json:"os" validate:"required,valid"`
	Arch      ArchType        `json:"arch" validate:"required,valid"`

	// Repository and Tag are REQUIRED. An update is the newest image under the
	// reference the installation follows, so a component that does not say which
	// reference that is cannot be resolved at all.
	Repository string `json:"repository" validate:"required,min=1,max=255"`
	Tag        string `json:"tag" validate:"required,min=1,max=100"`

	// ImageHash is a bare lowercase 64-char sha256 hex digest — WITHOUT the
	// `sha256:` prefix the Docker daemon reports. Send the config digest
	// (`docker inspect` → `Id`): it is always present, is per-platform, and
	// needs no registry access. The server recognises any of the three image
	// identities, so an index or manifest digest is understood too.
	//
	// Absent means nothing has been pulled yet. That is a real state — the
	// client knows which image it should run and does not have it — and it is
	// answered with the download rather than with silence.
	ImageHash *string `json:"image_hash,omitempty" validate:"omitempty,sha256"`
}

func (i ImageComponentInfo) Valid() error {
	return validate.Struct(i)
}

// FileComponentInfo describes one delivered file the client runs.
//
// There is no repository and no tag: files are not published to a registry, so
// the whole tag-and-channel half of resolution is inapplicable here by
// construction rather than by convention.
//
// Both identifying fields are optional, and each absence means something real: a
// client that has the file but cannot name its build sends only the hash, and a
// fresh installation has neither.
type FileComponentInfo struct {
	Component ComponentType   `json:"component" validate:"required,valid"`
	Status    ComponentStatus `json:"status" validate:"required,valid"`
	OS        OSType          `json:"os" validate:"required,valid"`
	Arch      ArchType        `json:"arch" validate:"required,valid"`

	Version  *string `json:"version,omitempty" validate:"omitempty,semver"`
	FileHash *string `json:"file_hash,omitempty" validate:"omitempty,sha256"`
}

func (f FileComponentInfo) Valid() error {
	return validate.Struct(f)
}

// CheckUpdatesResponse represents response for update check
type CheckUpdatesResponse struct {
	Updates []UpdateInfo `json:"updates" validate:"dive,valid"`
}

func (c CheckUpdatesResponse) Valid() error {
	return validate.Struct(c)
}

// UpdateInfo is the answer for one product stack.
//
// HasUpdate is per STACK. Images and Files carry the artefacts the answer is
// about, split the same way the request is: under the stable strategy every
// artefact of the release that matches a reported component is listed, whether
// or not it differs from what the client runs, so the client can attribute what
// it has to a version with release notes. Membership in a list therefore does
// NOT mean "needs updating" — compare the digests yourself.
type UpdateInfo struct {
	Stack          ProductStack `json:"stack" validate:"required,valid"`
	HasUpdate      bool         `json:"has_update"`
	CurrentVersion *string      `json:"current_version,omitempty" validate:"omitempty,semver"`
	LatestVersion  *string      `json:"latest_version,omitempty" validate:"omitempty,semver"`
	// Changelog and ReleaseNotes carry the TARGET release's text only.
	//
	// Deprecated: use Releases, whose last entry carries the same text plus
	// everything the installation crosses on the way there.
	Changelog    *string `json:"changelog,omitempty" validate:"omitempty"`
	ReleaseNotes *string `json:"release_notes,omitempty" validate:"omitempty"`

	Images []ImageUpdate `json:"images,omitempty" validate:"omitempty,dive,valid"`
	Files  []FileUpdate  `json:"files,omitempty" validate:"omitempty,dive,valid"`

	// Releases is the half-open range this update takes the installation
	// through: strictly above the version it is on, up to and including the
	// target. Oldest first, so the LAST entry is what it will be running.
	//
	// An installation whose version the server could not work out receives the
	// target alone: an unknown position gives no range to claim.
	Releases []ReleaseNote `json:"releases,omitempty" validate:"omitempty,dive,valid"`
	// ReleasesTruncated says the list was cut. The OLDEST entries go — the last
	// one is the target.
	ReleasesTruncated bool `json:"releases_truncated,omitempty"`

	// Resolution says HOW this answer was arrived at, for logs and a diagnostics
	// screen. Do not branch on it: it exists so `has_update: false` can be read
	// rather than guessed at.
	Resolution StackResolution `json:"resolution,omitempty" validate:"omitempty,valid"`
	// CurrentVersionMixed says the stack's components were attributed to
	// DIFFERENT releases, so CurrentVersion is the oldest of them rather than a
	// version this installation as a whole ever was. Legitimate — a component
	// nobody rebuilt stays on its old release — but "you are on 2.1.0" and "the
	// oldest thing you have is from 2.1.0" are different sentences.
	CurrentVersionMixed bool `json:"current_version_mixed,omitempty"`
}

// ReleaseNote is one curated release crossed by applying an update.
//
// It exists because the text of the releases BETWEEN the installed version and
// the target used to be unreachable: only one changelog was sent, and the
// endpoint that holds the rest is behind a privilege no installation has.
type ReleaseNote struct {
	Version  string `json:"version" validate:"required,semver"`
	IsStable bool   `json:"is_stable"`
	// ReleasedAt is absent for a release that was never published explicitly.
	ReleasedAt   *time.Time `json:"released_at,omitempty"`
	Changelog    string     `json:"changelog"`
	ReleaseNotes string     `json:"release_notes"`
}

func (rn ReleaseNote) Valid() error {
	return validate.Struct(rn)
}

// Valid enforces the two invariants no field tag can express.
func (u UpdateInfo) Valid() error {
	if err := validate.Struct(u); err != nil {
		return err
	}
	actionable, unknown := false, false
	for _, image := range u.Images {
		actionable = actionable || image.Action.Actionable()
		unknown = unknown || image.Action == ComponentActionUnknown
	}
	for _, file := range u.Files {
		actionable = actionable || file.Action.Actionable()
		unknown = unknown || file.Action == ComponentActionUnknown
	}
	if u.HasUpdate != actionable {
		return fmt.Errorf(
			"%s: has_update is %t, but %t components carry an action the client can carry out",
			u.Stack, u.HasUpdate, actionable)
	}
	if unknown && u.Resolution == "" {
		return fmt.Errorf("%s: a component is unknown and the stack carries no resolution", u.Stack)
	}
	if u.ReleasesTruncated && len(u.Releases) == 0 {
		return fmt.Errorf("%s: the release list is marked truncated and is empty", u.Stack)
	}
	return nil
}

// ImageUpdate is one container image the answer refers to.
//
// Repository, Tag and ImageHash are not pointers: every one of them is read off
// a published row, so the server always knows all three. The optional fields
// here are the ones that are genuinely unknown sometimes, and nothing else.
type ImageUpdate struct {
	Component ComponentType `json:"component" validate:"required,valid"`
	OS        OSType        `json:"os" validate:"required,valid"`
	Arch      ArchType      `json:"arch" validate:"required,valid"`

	// Action says what to do, and Reason explains it when there is nothing to do
	// because there is nothing to offer. Which of the fields below are present
	// depends on Action; Valid() enforces the dependency.
	Action ComponentAction  `json:"action" validate:"required,valid"`
	Reason *ComponentReason `json:"reason,omitempty" validate:"omitempty,valid"`

	// Pinned marks an artefact that comes from a curated release rather than from
	// a tag this installation follows.
	Pinned bool `json:"pinned"`
	// ReleaseVersion is the release this artefact belongs to, when it can be
	// attributed to one. Absent is a real answer: an artefact nobody released has
	// no version.
	ReleaseVersion *string `json:"release_version,omitempty" validate:"omitempty,semver"`

	Repository string `json:"repository" validate:"required,min=1,max=255"`
	// Tag NAMES the artefact: among all the tags this exact digest was pushed
	// to, the most specific one. Swapping between them is safe by construction —
	// same digest, same bytes — and it is what turns a publication tagged
	// `latest`, `2`, `2.3` and `2.3.4` into the answer "2.3.4".
	Tag string `json:"tag" validate:"required,min=1,max=100"`
	// PullReference is what to write into the compose variable before pulling,
	// ready to use. It is NOT always `repository:tag` above, and the difference
	// is deliberate: under `stable` it pins the immutable, most specific tag so
	// the pull is reproducible, while under `preview` and `nightly` it names the
	// moving tag the artefact was found under, because pinning an immutable one
	// there would stop the installation dead until the strategy changed.
	//
	// Write it as given. What tags mean is the server's business.
	PullReference string `json:"pull_reference" validate:"omitempty,min=1,max=356"`
	// ImageHash is the per-platform manifest digest — the canonical key, which
	// no Docker API reports back, so it cannot be used to verify a pull.
	ImageHash string `json:"image_hash" validate:"omitempty,sha256"`
	// ConfigHash is what `docker inspect` returns as `Id`. It is per-platform,
	// so it confirms both the build and the architecture — this is the value to
	// verify a pulled image against. IndexHash names the whole multi-platform
	// publication and is what a pull by tag records in RepoDigests; it is absent
	// for single-platform images.
	//
	// Both are omitted when the server does not know them. Treat an absent value
	// as "cannot verify", never as a mismatch.
	ConfigHash *string `json:"config_hash,omitempty" validate:"omitempty,sha256"`
	IndexHash  *string `json:"index_hash,omitempty" validate:"omitempty,sha256"`
}

func (iu ImageUpdate) Valid() error {
	if err := validate.Struct(iu); err != nil {
		return err
	}
	return validArtefactAnswer(iu.Component, iu.Action, iu.Reason, iu.ImageHash != "" && iu.PullReference != "")
}

// CarriesDigest reports whether digest names this image by ANY of its three
// identities. A client is free to compare whichever digest its daemon exposes;
// matching a single identity is enough to conclude "I am current".
func (iu ImageUpdate) CarriesDigest(digest string) bool {
	switch {
	case iu.ImageHash == digest:
		return true
	case iu.ConfigHash != nil && *iu.ConfigHash == digest:
		return true
	case iu.IndexHash != nil && *iu.IndexHash == digest:
		return true
	}
	return false
}

// FileUpdate is one delivered file the answer refers to. Every field is read off
// a published row, so none of them is optional.
type FileUpdate struct {
	Component ComponentType `json:"component" validate:"required,valid"`
	OS        OSType        `json:"os" validate:"required,valid"`
	Arch      ArchType      `json:"arch" validate:"required,valid"`

	Action ComponentAction  `json:"action" validate:"required,valid"`
	Reason *ComponentReason `json:"reason,omitempty" validate:"omitempty,valid"`

	Pinned         bool    `json:"pinned"`
	ReleaseVersion *string `json:"release_version,omitempty" validate:"omitempty,semver"`

	PackageName string `json:"package_name" validate:"omitempty,min=1,max=100"`
	Version     string `json:"version" validate:"omitempty,semver"`
	FileHash    string `json:"file_hash" validate:"omitempty,sha256"`
}

func (fu FileUpdate) Valid() error {
	if err := validate.Struct(fu); err != nil {
		return err
	}
	return validArtefactAnswer(fu.Component, fu.Action, fu.Reason, fu.FileHash != "" && fu.Version != "")
}
