package models

import "fmt"

// ComponentAction is what a client should do about one reported artefact.
//
// Exactly one action comes back per reported component, always — including the
// ones the service could resolve nothing for. Before this existed, such a
// component was simply absent from the answer, which made "we have nothing for
// you" byte-identical to "you are up to date".
type ComponentAction string

const (
	// ComponentActionCurrent: what is installed is what is offered.
	ComponentActionCurrent ComponentAction = "current"
	// ComponentActionInstall: nothing is installed and there is something to install.
	ComponentActionInstall ComponentAction = "install"
	// ComponentActionUpgrade: what is installed is older than what is offered.
	ComponentActionUpgrade ComponentAction = "upgrade"
	// ComponentActionDowngrade: the offered artefact carries a LOWER version than
	// what is installed, and is offered anyway because it is not OLDER — a
	// deliberate move onto a release, never a rollback in time.
	ComponentActionDowngrade ComponentAction = "downgrade"
	// ComponentActionUnknown: there is nothing to compare against. Always
	// accompanied by a reason.
	ComponentActionUnknown ComponentAction = "unknown"
)

func (a ComponentAction) String() string { return string(a) }

func (a ComponentAction) Valid() error {
	switch a {
	case ComponentActionCurrent, ComponentActionInstall, ComponentActionUpgrade,
		ComponentActionDowngrade, ComponentActionUnknown:
		return nil
	default:
		return fmt.Errorf("invalid ComponentAction: %s", a)
	}
}

// Actionable reports whether this action is something the client can carry out.
// It is the definition of has_update: `current` and `unknown` neither raise it
// nor clear it.
func (a ComponentAction) Actionable() bool {
	switch a {
	case ComponentActionInstall, ComponentActionUpgrade, ComponentActionDowngrade:
		return true
	default:
		return false
	}
}

// ComponentReason explains an `unknown` action.
type ComponentReason string

const (
	// ReasonTagNotPublished: the component and repository are published, but
	// nothing under the reference this installation follows.
	ReasonTagNotPublished ComponentReason = "tag_not_published"
	// ReasonRepositoryNotTracked: the installation runs an image the service does
	// not publish — usually a private rebuild under a private name.
	ReasonRepositoryNotTracked ComponentReason = "repository_not_tracked"
	// ReasonComponentNotTracked: nothing is published for this component on this
	// platform at all.
	ReasonComponentNotTracked ComponentReason = "component_not_tracked"
	// ReasonNoReleaseArtifactForTag: the component exists, but the release the
	// stack is measured against links no artefact of it.
	ReasonNoReleaseArtifactForTag ComponentReason = "no_release_artifact_for_tag"
)

func (r ComponentReason) String() string { return string(r) }

func (r ComponentReason) Valid() error {
	switch r {
	case ReasonTagNotPublished, ReasonRepositoryNotTracked,
		ReasonComponentNotTracked, ReasonNoReleaseArtifactForTag:
		return nil
	default:
		return fmt.Errorf("invalid ComponentReason: %s", r)
	}
}

// StackResolution says how a stack's answer was arrived at.
//
// DIAGNOSTIC ONLY. Neither an update button nor an application strategy may
// branch on it: it exists so that `has_update: false` can be READ rather than
// guessed at — most of all in the case it used to be silent about, an
// installation running something newer than anything curated.
type StackResolution string

const (
	// StackResolutionRelease: answered from a curated release.
	StackResolutionRelease StackResolution = "release"
	// StackResolutionChannel: answered from the tags the client follows.
	StackResolutionChannel StackResolution = "channel"
	// StackResolutionAheadOfRelease: something installed is newer than what would
	// have been offered, so nothing was. Not an error — the next release catches up.
	StackResolutionAheadOfRelease StackResolution = "ahead_of_release"
	// StackResolutionNoArtifactForTag: at least one component found nothing in its scope.
	StackResolutionNoArtifactForTag StackResolution = "no_artifact_for_tag"
	// StackResolutionNotTracked: at least one component names something not published at all.
	StackResolutionNotTracked StackResolution = "not_tracked"
)

func (r StackResolution) String() string { return string(r) }

func (r StackResolution) Valid() error {
	switch r {
	case StackResolutionRelease, StackResolutionChannel, StackResolutionAheadOfRelease,
		StackResolutionNoArtifactForTag, StackResolutionNotTracked:
		return nil
	default:
		return fmt.Errorf("invalid StackResolution: %s", r)
	}
}

// StackStatus is how an installation relates to one product stack.
//
// Four of the values are exactly the distinctions the pre-SDK contract drew with
// three booleans per stack (connected / installed / external), collapsed into
// one value so that "who runs what, and how" is a single field. The fifth says
// nothing is known, which is a different statement from all four.
type StackStatus string

const (
	// StackStatusUndefined: nothing is known about this stack. It is what a stack
	// nobody spoke about is recorded as, and a client may send it for a stack it
	// cannot observe. It is NOT "not used" — reading it as that turns ignorance
	// into a negative answer, and a fleet of clients too old to report anything
	// then looks like a fleet that uses nothing.
	StackStatusUndefined StackStatus = "undefined"
	// StackStatusUnused: not configured. This is a positive statement — the
	// client looked and there is nothing — and it is worth more than silence.
	StackStatusUnused StackStatus = "unused"
	// StackStatusConnected: configured and in use, but nothing of it deployed by
	// this installation — typically still being set up.
	StackStatusConnected StackStatus = "connected"
	// StackStatusInstalled: deployed and operated by this installation.
	StackStatusInstalled StackStatus = "installed"
	// StackStatusExternal: in use, but deployed and operated elsewhere. There are
	// no images to offer for it; the installation only talks to it.
	StackStatusExternal StackStatus = "external"
)

func (s StackStatus) String() string { return string(s) }

func (s StackStatus) Valid() error {
	switch s {
	case StackStatusUndefined, StackStatusUnused,
		StackStatusConnected, StackStatusInstalled, StackStatusExternal:
		return nil
	default:
		return fmt.Errorf("invalid StackStatus: %s", s)
	}
}

// AllStackStatuses is the vocabulary in one place, for the tests that guard the
// hand-written copies of it.
var AllStackStatuses = []StackStatus{
	StackStatusUndefined, StackStatusUnused,
	StackStatusConnected, StackStatusInstalled, StackStatusExternal,
}

// StackInfo is how one product stack is being used by this installation.
//
// It answers a question the component lists cannot. A stack deployed elsewhere
// reports no images at all — it has no reference that could be resolved — so
// without this field an externally hosted Langfuse is indistinguishable from no
// Langfuse, and that is the difference between "nobody wants this" and
// "everybody runs it their own way".
//
// Nothing in the answer depends on it. Report it anyway: it is the only way the
// service learns how its parts are actually deployed.
type StackInfo struct {
	Stack  ProductStack `json:"stack" validate:"required,valid"`
	Status StackStatus  `json:"status" validate:"required,valid"`
}

func (s StackInfo) Valid() error {
	return validate.Struct(s)
}

// validArtefactAnswer is the invariant field tags cannot express: an entry
// either names an artefact or explains why it does not, and an action the client
// can carry out must always name one.
func validArtefactAnswer(
	component ComponentType, action ComponentAction, reason *ComponentReason, resolved bool,
) error {
	if action == ComponentActionUnknown {
		if resolved {
			return fmt.Errorf("%s: an unknown component must not carry an artefact", component)
		}
		if reason == nil {
			return fmt.Errorf("%s: an unknown component must say why", component)
		}
		return nil
	}
	if reason != nil {
		return fmt.Errorf("%s: a reason explains an unknown component, and this one is %s", component, action)
	}
	if action.Actionable() && !resolved {
		return fmt.Errorf("%s: action %s names no artefact to act on", component, action)
	}
	return nil
}
