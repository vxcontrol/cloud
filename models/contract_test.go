package models

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// GoldenCheckUpdatesRequest is the exact wire form this package produces for an
// update check. The server side keeps a copy of this literal and asserts its own
// models accept it, so a field renamed on either side turns one of the two tests
// red instead of silently producing requests nobody can parse.
const GoldenCheckUpdatesRequest = `{
  "installer_version": "2.0.0-87ac00f",
  "installer_os": "linux",
  "installer_arch": "arm64",
  "strategy": "stable",
  "images": [
    {
      "component": "pentagi",
      "status": "running",
      "os": "linux",
      "arch": "arm64",
      "repository": "vxcontrol/pentagi",
      "tag": "latest",
      "image_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
      "component": "postgres",
      "status": "running",
      "os": "linux",
      "arch": "arm64",
      "repository": "postgres",
      "tag": "15",
      "image_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "stacks": [
    {
      "stack": "langfuse",
      "status": "external"
    },
    {
      "stack": "observability",
      "status": "unused"
    }
  ],
  "files": [
    {
      "component": "installer",
      "status": "installed",
      "os": "darwin",
      "arch": "arm64",
      "version": "2.0.0-87ac00f",
      "file_hash": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    },
    {
      "component": "engine",
      "status": "installed",
      "os": "linux",
      "arch": "arm64",
      "version": "1.0.0"
    }
  ],
  "info": {"schema":1,"version":"0.9.3","counts":{"users":3}}
}`

// GoldenCheckUpdatesResponse is the exact wire form the server answers with,
// wrapped in the envelope every JSON response carries.
//
// It deliberately carries THREE stacks, and two of them resolve to nothing. A
// fixture made only of resolved artefacts pins only the fields a resolved
// artefact has: `reason` and `release_version` are optional, so leaving them out
// leaves both sides free to rename or drop them without a single test noticing.
// An unresolved artefact is the only way to pin `reason` — the server rejects it
// for every action except `unknown` — and `has_update: false` is the answer most
// installations get most of the time, so it is the shape most worth pinning.
//
// The two boolean flags are set rather than left false for the same reason:
// `omitempty` on a bool makes an unset flag invisible on the wire, so a fixture
// that leaves them false pins nothing. `releases` is shortened to two entries to
// keep the literal readable — the truncation flag is what a twenty-one-release
// jump raises, and its presence here is about the field, not the count.
const GoldenCheckUpdatesResponse = `{
  "status": "success",
  "data": {
    "updates": [
      {
        "stack": "engine",
        "has_update": false,
        "resolution": "not_tracked",
        "files": [
          {
            "component": "engine",
            "os": "linux",
            "arch": "arm64",
            "action": "unknown",
            "reason": "component_not_tracked",
            "pinned": false,
            "package_name": "",
            "version": "",
            "file_hash": ""
          }
        ]
      },
      {
        "stack": "langfuse",
        "has_update": false,
        "resolution": "no_artifact_for_tag",
        "images": [
          {
            "component": "postgres",
            "os": "linux",
            "arch": "arm64",
            "action": "unknown",
            "reason": "tag_not_published",
            "pinned": false,
            "repository": "postgres",
            "tag": "15",
            "pull_reference": "",
            "image_hash": ""
          }
        ]
      },
      {
        "stack": "pentagi",
        "has_update": true,
        "resolution": "release",
        "current_version": "2.0.0",
        "current_version_mixed": true,
        "latest_version": "2.1.0",
        "changelog": "fixes",
        "release_notes": "notes",
        "releases": [
          {
            "version": "2.0.5",
            "is_stable": true,
            "released_at": "2026-01-02T03:04:05Z",
            "changelog": "hotfix",
            "release_notes": "hotfix notes"
          },
          {
            "version": "2.1.0",
            "is_stable": true,
            "changelog": "fixes",
            "release_notes": "notes"
          }
        ],
        "releases_truncated": true,
        "images": [
          {
            "component": "pentagi",
            "os": "linux",
            "arch": "arm64",
            "action": "upgrade",
            "pinned": true,
            "release_version": "2.1.0",
            "repository": "vxcontrol/pentagi",
            "tag": "latest",
            "pull_reference": "vxcontrol/pentagi:latest",
            "image_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "config_hash": "2222222222222222222222222222222222222222222222222222222222222222",
            "index_hash": "3333333333333333333333333333333333333333333333333333333333333333"
          }
        ],
        "files": [
          {
            "component": "installer",
            "os": "darwin",
            "arch": "arm64",
            "action": "current",
            "pinned": false,
            "release_version": "2.0.0",
            "package_name": "installer",
            "version": "2.0.0",
            "file_hash": "4444444444444444444444444444444444444444444444444444444444444444"
          }
        ]
      }
    ]
  }
}`

func TestCheckUpdatesRequestMatchesTheGoldenWireForm(t *testing.T) {
	imageHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pinnedHash := strings.Repeat("a", 64)
	version := "2.0.0-87ac00f"
	engineVersion := "1.0.0"
	fileHash := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	request := CheckUpdatesRequest{
		InstallerVersion: "2.0.0-87ac00f",
		InstallerOS:      OSTypeLinux,
		InstallerArch:    ArchTypeARM64,
		Strategy:         UpdateStrategyStable,
		Images: []ImageComponentInfo{
			{
				Component:  ComponentTypePentagi,
				Status:     ComponentStatusRunning,
				OS:         OSTypeLinux,
				Arch:       ArchTypeARM64,
				Repository: "vxcontrol/pentagi",
				Tag:        "latest",
				ImageHash:  &imageHash,
			},
			// An image pinned to a tag the server does not publish. Reporting it
			// is normal, not malformed — it is how the answer `tag_not_published`
			// is reached, and dropping it locally would make the component vanish
			// from the answer instead of being explained.
			{
				Component:  ComponentTypePostgres,
				Status:     ComponentStatusRunning,
				OS:         OSTypeLinux,
				Arch:       ArchTypeARM64,
				Repository: "postgres",
				Tag:        "15",
				ImageHash:  &pinnedHash,
			},
		},
		Stacks: []StackInfo{
			{Stack: ProductStackLangfuse, Status: StackStatusExternal},
			{Stack: ProductStackObservability, Status: StackStatusUnused},
		},
		Files: []FileComponentInfo{
			{
				Component: ComponentTypeInstaller,
				Status:    ComponentStatusInstalled,
				OS:        OSTypeDarwin,
				Arch:      ArchTypeARM64,
				Version:   &version,
				FileHash:  &fileHash,
			},
			// A file installed but never verified: a version and no digest. Both
			// are optional on the wire for exactly this case.
			{
				Component: ComponentTypeEngine,
				Status:    ComponentStatusInstalled,
				OS:        OSTypeLinux,
				Arch:      ArchTypeARM64,
				Version:   &engineVersion,
			},
		},
		// Carried as raw JSON so that whoever collects it need not understand it.
		// Pinned here because a passthrough field is exactly the kind that gets
		// "helpfully" retyped into a map or a struct one day, and the moment it is,
		// every key the retyping does not name disappears without an error.
		Info: json.RawMessage(`{"schema":1,"version":"0.9.3","counts":{"users":3}}`),
	}

	if err := request.Valid(); err != nil {
		t.Fatalf("the golden request must validate: %v", err)
	}

	produced, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got, want any
	if err := json.Unmarshal(produced, &got); err != nil {
		t.Fatalf("unmarshal produced: %v", err)
	}
	if err := json.Unmarshal([]byte(GoldenCheckUpdatesRequest), &want); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("wire form drifted\n produced: %s\n   golden: %s", gotJSON, wantJSON)
	}
}

func TestCheckUpdatesResponseParsesEveryGoldenField(t *testing.T) {
	response, err := ParseEnvelope[CheckUpdatesResponse]([]byte(GoldenCheckUpdatesResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(response.Updates) != 3 {
		t.Fatalf("expected 3 updates, got %d", len(response.Updates))
	}

	// Stacks arrive sorted by name. The order is part of the wire form, and a
	// client that indexes into the list — this test does — has to say so.
	notTracked, unpublishedTag, upToDate := response.Updates[0], response.Updates[1], response.Updates[2]

	if upToDate.Stack != ProductStackPentagi || !upToDate.HasUpdate {
		t.Errorf("stack/has_update lost: %+v", upToDate)
	}
	if upToDate.Resolution != StackResolutionRelease {
		t.Errorf("resolution lost: %q", upToDate.Resolution)
	}
	if upToDate.LatestVersion == nil || *upToDate.LatestVersion != "2.1.0" {
		t.Errorf("latest_version lost: %+v", upToDate.LatestVersion)
	}
	if upToDate.Changelog == nil || upToDate.ReleaseNotes == nil {
		t.Error("changelog/release_notes lost — the update screen has nothing to show")
	}
	if len(upToDate.Images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(upToDate.Images))
	}
	if len(upToDate.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(upToDate.Files))
	}

	// The image list is what makes post-update verification possible: without it
	// a client cannot tell which digest it was supposed to land on.
	image := upToDate.Images[0]
	if image.ConfigHash == nil || image.IndexHash == nil || image.ImageHash == "" {
		t.Fatalf("all three image identities must survive parsing: %+v", image)
	}
	if image.Repository == "" || image.Tag == "" {
		t.Fatalf("the reference to pull must survive parsing: %+v", image)
	}
	// PullReference is NOT repository:tag in general — under `stable` it pins a
	// more specific tag — so a client that rebuilt it locally would write the
	// wrong thing into its compose file.
	if image.PullReference != "vxcontrol/pentagi:latest" {
		t.Errorf("pull_reference lost: %q", image.PullReference)
	}
	if image.Action != ComponentActionUpgrade || !image.Pinned {
		t.Errorf("action/pinned lost: %+v", image)
	}
	if image.ReleaseVersion == nil || *image.ReleaseVersion != "2.1.0" {
		t.Errorf("release_version lost: %+v", image.ReleaseVersion)
	}
	for _, digest := range []string{image.ImageHash, *image.ConfigHash, *image.IndexHash} {
		if !image.CarriesDigest(digest) {
			t.Errorf("CarriesDigest must recognise %s", digest)
		}
	}
	if image.CarriesDigest(strings.Repeat("9", 64)) {
		t.Error("CarriesDigest must not match an unrelated digest")
	}

	// A file carries no reference and no digest triple — its identity is the
	// package, the version and the hash.
	file := upToDate.Files[0]
	if file.PackageName == "" || file.Version == "" || file.FileHash == "" {
		t.Fatalf("file identity fields lost: %+v", file)
	}
	if file.Action != ComponentActionCurrent {
		t.Errorf("a file's action lost: %q", file.Action)
	}
	if file.ReleaseVersion == nil || *file.ReleaseVersion != "2.0.0" {
		t.Errorf("a file's release_version lost: %+v", file.ReleaseVersion)
	}

	// The crossed releases are what the update-overview screen renders, and the
	// two flags beside them are `omitempty` booleans — absent when false, so a
	// fixture that left them unset would pin nothing at all.
	if !upToDate.CurrentVersionMixed {
		t.Error("current_version_mixed lost — the screen cannot tell a uniform installation from a mixed one")
	}
	if !upToDate.ReleasesTruncated {
		t.Error("releases_truncated lost — the screen cannot say the history is incomplete")
	}
	if len(upToDate.Releases) != 2 {
		t.Fatalf("expected 2 crossed releases, got %d", len(upToDate.Releases))
	}
	if upToDate.Releases[1].Version != "2.1.0" {
		t.Errorf("the LAST crossed release is the target: %q", upToDate.Releases[1].Version)
	}
	if upToDate.Releases[0].Changelog != "hotfix" || upToDate.Releases[0].ReleaseNotes != "hotfix notes" {
		t.Errorf("a crossed release must carry its OWN text, not the target's: %+v", upToDate.Releases[0])
	}
	// released_at is absent for a release nobody pressed Publish on, and a client
	// that treats absence as an error would refuse to render half the list.
	if upToDate.Releases[0].ReleasedAt == nil || upToDate.Releases[1].ReleasedAt != nil {
		t.Errorf("released_at is present exactly when the release was published: %+v", upToDate.Releases)
	}

	// An unresolved component comes back with a REASON and no artefact. Dropping
	// the component instead would be byte-identical to "you are up to date", and
	// dropping only the reason leaves a client that must say why it cannot act
	// with nothing to say.
	if len(notTracked.Files) != 1 {
		t.Fatalf("an unresolved component must still be answered: %+v", notTracked)
	}
	unknownFile := notTracked.Files[0]
	if unknownFile.Action != ComponentActionUnknown {
		t.Errorf("a file's unknown action lost: %q", unknownFile.Action)
	}
	if unknownFile.Reason == nil || *unknownFile.Reason != ReasonComponentNotTracked {
		t.Fatalf("a file's reason lost: %+v", unknownFile.Reason)
	}
	if notTracked.Resolution != StackResolutionNotTracked {
		t.Errorf("the stack's resolution lost: %q", notTracked.Resolution)
	}
	if notTracked.HasUpdate {
		t.Error("a stack whose component could not be resolved has no update to offer")
	}

	if len(unpublishedTag.Images) != 1 {
		t.Fatalf("an unresolved image must still be answered: %+v", unpublishedTag)
	}
	unknownImage := unpublishedTag.Images[0]
	if unknownImage.Reason == nil || *unknownImage.Reason != ReasonTagNotPublished {
		t.Fatalf("an image's reason lost: %+v", unknownImage.Reason)
	}
	// The echoed reference is what makes the reason readable without the request
	// beside it: "tag_not_published" alone does not say WHICH tag.
	if unknownImage.Repository != "postgres" || unknownImage.Tag != "15" {
		t.Errorf("the reported reference must be echoed back: %+v", unknownImage)
	}
	if unknownImage.PullReference != "" || unknownImage.ImageHash != "" {
		t.Errorf("an unresolved image must name no artefact: %+v", unknownImage)
	}
	if unpublishedTag.Resolution != StackResolutionNoArtifactForTag {
		t.Errorf("the stack's resolution lost: %q", unpublishedTag.Resolution)
	}
}

// TestCheckUpdatesResponseSurvivesARoundTrip is the half of drift detection that
// field-by-field assertions cannot cover.
//
// Parsing proves this package can READ a field. It says nothing about a field
// the server sends and this package has no home for: an unknown key is silently
// discarded, so a rename on the server side leaves every assertion above green
// while the value never arrives. Re-marshalling what was parsed and comparing it
// against the golden bytes turns that silence into a failure — and it does so
// for every field at once, including ones added after this test was written.
func TestCheckUpdatesResponseSurvivesARoundTrip(t *testing.T) {
	response, err := ParseEnvelope[CheckUpdatesResponse]([]byte(GoldenCheckUpdatesResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := response.Valid(); err != nil {
		t.Fatalf("the golden answer must be one a client accepts: %v", err)
	}

	reproduced, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(GoldenCheckUpdatesResponse), &envelope); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	var got, want any
	if err := json.Unmarshal(reproduced, &got); err != nil {
		t.Fatalf("unmarshal reproduced: %v", err)
	}
	if err := json.Unmarshal(envelope.Data, &want); err != nil {
		t.Fatalf("unmarshal golden payload: %v", err)
	}

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("a field did not survive the round trip — this package cannot hold it\n"+
			" read back: %s\n   golden: %s", gotJSON, wantJSON)
	}
}

// TestTheAnswerVocabulariesAreSpelledTheSameOnBothSides.
//
// The golden forms pin the fields; they cannot pin the VALUES, because one
// fixture carries one value per field and the vocabularies have four and five
// members. That gap is not theoretical: the server spelled `downgrade` as
// `rollback` for a while and nothing was red on either side. This package
// REJECTS an unknown action, so the first installation offered a deliberate move
// onto a release would have failed its whole update check.
//
// The server pins the same list; if you change one, change the other. The rejected column matters as much as the
// accepted one: a vocabulary that accepts everything pins nothing.
func TestTheAnswerVocabulariesAreSpelledTheSameOnBothSides(t *testing.T) {
	for name, vocabulary := range map[string]struct {
		accepted []string
		rejected []string
		valid    func(string) error
	}{
		"ComponentAction": {
			accepted: []string{"current", "install", "upgrade", "downgrade", "unknown"},
			rejected: []string{"rollback", "none", "update", ""},
			valid:    func(v string) error { return ComponentAction(v).Valid() },
		},
		"ComponentReason": {
			accepted: []string{
				"tag_not_published", "repository_not_tracked",
				"component_not_tracked", "no_release_artifact_for_tag",
			},
			rejected: []string{"not_tracked", "tag_not_found", "unknown", ""},
			valid:    func(v string) error { return ComponentReason(v).Valid() },
		},
		"StackResolution": {
			accepted: []string{
				"release", "channel", "ahead_of_release", "no_artifact_for_tag", "not_tracked",
			},
			rejected: []string{"ahead", "tag_not_published", "stable", ""},
			valid:    func(v string) error { return StackResolution(v).Valid() },
		},
		"StackStatus": {
			accepted: []string{"unused", "connected", "installed", "external"},
			rejected: []string{"running", "absent", "disabled", ""},
			valid:    func(v string) error { return StackStatus(v).Valid() },
		},
		"UpdateStrategy": {
			accepted: []string{"nightly", "preview", "stable"},
			rejected: []string{"weekly", "latest", "beta", ""},
			valid:    func(v string) error { return UpdateStrategy(v).Valid() },
		},
		"SupportStreamEvent": {
			accepted: []string{"message", "thinking", "content", "update", "flush"},
			// the events of the stream itself belong to the sdk/sse package
			rejected: []string{"start", "heartbeat", "error", "done", "complete", "delta", ""},
			valid:    func(v string) error { return SupportStreamEvent(v).Valid() },
		},
		"SupportIssueStatus": {
			accepted: []string{"processing", "processed", "answering"},
			// there is no failed status, and the states of a turn a client keeps for itself
			// are not statuses of the server
			rejected: []string{"failed", "starting", "done", "idle", ""},
			valid:    func(v string) error { return SupportIssueStatus(v).Valid() },
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, value := range vocabulary.accepted {
				if err := vocabulary.valid(value); err != nil {
					t.Errorf("%s must accept %q — the server sends or expects it: %v", name, value, err)
				}
			}
			for _, value := range vocabulary.rejected {
				if err := vocabulary.valid(value); err == nil {
					t.Errorf("%s must reject %q", name, value)
				}
			}
		})
	}
}

// TestParsingWithoutTheEnvelopeLosesEverything documents why ParseEnvelope
// exists. Decoding a response body straight into the payload type does not fail
// — it silently yields a zero value, which a client reads as "no updates".
func TestParsingWithoutTheEnvelopeLosesEverything(t *testing.T) {
	var naive CheckUpdatesResponse
	if err := json.Unmarshal([]byte(GoldenCheckUpdatesResponse), &naive); err != nil {
		t.Fatalf("the naive decode is expected to SUCCEED, which is the trap: %v", err)
	}
	if len(naive.Updates) != 0 {
		t.Fatal("test is no longer demonstrating the trap")
	}

	parsed, err := ParseEnvelope[CheckUpdatesResponse]([]byte(GoldenCheckUpdatesResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Updates) == 0 {
		t.Fatal("ParseEnvelope must recover what the naive decode drops")
	}
}

func TestParseEnvelopeReportsServerErrors(t *testing.T) {
	body := `{"status":"error","code":"Updates.InvalidData","msg":"invalid check updates data"}`

	_, err := ParseEnvelope[CheckUpdatesResponse]([]byte(body))
	if err == nil {
		t.Fatal("an error envelope must not be reported as success")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Code != "Updates.InvalidData" {
		t.Errorf("code lost: %q", apiErr.Code)
	}
}

func TestRequestValidationMatchesTheServerRules(t *testing.T) {
	base := func() CheckUpdatesRequest {
		return CheckUpdatesRequest{
			InstallerVersion: "2.0.0",
			InstallerOS:      OSTypeLinux,
			InstallerArch:    ArchTypeAMD64,
			Strategy:         UpdateStrategyStable,
		}
	}

	t.Run("strategy is required and has no default", func(t *testing.T) {
		request := base()
		request.Strategy = ""
		if err := request.Valid(); err == nil {
			t.Error("a request without a strategy must not validate")
		}
		request.Strategy = "weekly"
		if err := request.Valid(); err == nil {
			t.Error("an unknown strategy must not validate")
		}
	})

	t.Run("installer version follows the server pattern", func(t *testing.T) {
		accepted := []string{"2.0.0", "2.0", "2.0.0-87ac00f", "0.0.0"}
		for _, version := range accepted {
			request := base()
			request.InstallerVersion = version
			if err := request.Valid(); err != nil {
				t.Errorf("%q must be accepted: %v", version, err)
			}
		}
		// A development build reports its branch name, which the contract cannot
		// express — normalise it to 0.0.0 before sending.
		for _, version := range []string{"develop", "develop-abc1234", "v2.0.0", ""} {
			request := base()
			request.InstallerVersion = version
			if err := request.Valid(); err == nil {
				t.Errorf("%q must be rejected", version)
			}
		}
	})

	t.Run("digests are bare lowercase hex", func(t *testing.T) {
		bare := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		prefixed := "sha256:" + bare
		upper := strings.ToUpper(bare)

		for name, digest := range map[string]string{"bare": bare, "prefixed": prefixed, "uppercase": upper} {
			request := base()
			request.Images = []ImageComponentInfo{{
				Component:  ComponentTypePentagi,
				Status:     ComponentStatusRunning,
				OS:         OSTypeLinux,
				Arch:       ArchTypeAMD64,
				Repository: "vxcontrol/pentagi",
				Tag:        "latest",
				ImageHash:  &digest,
			}}
			err := request.Valid()
			if name == "bare" && err != nil {
				t.Errorf("a bare digest must be accepted: %v", err)
			}
			if name != "bare" && err == nil {
				t.Errorf("a %s digest must be rejected — strip the prefix and lowercase it", name)
			}
		}
	})

	t.Run("component os and arch are required", func(t *testing.T) {
		request := base()
		request.Images = []ImageComponentInfo{{
			Component:  ComponentTypePentagi,
			Status:     ComponentStatusRunning,
			Repository: "vxcontrol/pentagi",
			Tag:        "latest",
		}}
		if err := request.Valid(); err == nil {
			t.Error("a component without os/arch must not validate")
		}
	})

	t.Run("an image must name the reference it follows", func(t *testing.T) {
		for _, missing := range []string{"repository", "tag"} {
			image := ImageComponentInfo{
				Component:  ComponentTypePentagi,
				Status:     ComponentStatusRunning,
				OS:         OSTypeLinux,
				Arch:       ArchTypeAMD64,
				Repository: "vxcontrol/pentagi",
				Tag:        "latest",
			}
			switch missing {
			case "repository":
				image.Repository = ""
			case "tag":
				image.Tag = ""
			}
			request := base()
			request.Images = []ImageComponentInfo{image}
			if err := request.Valid(); err == nil {
				t.Errorf("an image without a %s must not validate: an update is the newest"+
					" image under the reference the installation follows, and without the"+
					" reference the question has no answer", missing)
			}
		}
	})

	// The bound is read from the constant, never written out here. This subtest
	// carried a literal 30 while the constant said 40, so it passed while ten
	// artefacts more than it describes were being accepted — a test that agrees
	// with itself instead of with the rule.
	t.Run("at most MaxReportedComponents artefacts across BOTH lists", func(t *testing.T) {
		image := ImageComponentInfo{
			Component:  ComponentTypePentagi,
			Status:     ComponentStatusRunning,
			OS:         OSTypeLinux,
			Arch:       ArchTypeAMD64,
			Repository: "vxcontrol/pentagi",
			Tag:        "latest",
		}
		file := FileComponentInfo{
			Component: ComponentTypeInstaller,
			Status:    ComponentStatusRunning,
			OS:        OSTypeLinux,
			Arch:      ArchTypeAMD64,
		}

		request := base()
		for i := 0; i < MaxReportedComponents; i++ {
			request.Images = append(request.Images, image)
		}
		if err := request.Valid(); err != nil {
			t.Errorf("%d artefacts must be accepted: %v", MaxReportedComponents, err)
		}
		request.Images = append(request.Images, image)
		if err := request.Valid(); err == nil {
			t.Errorf("%d artefacts must be rejected", MaxReportedComponents+1)
		}

		// The limit counts the two lists TOGETHER. Bounding each separately
		// would let a caller send twice the limit by splitting the payload,
		// which is not a limit at all.
		split := base()
		for range MaxReportedComponents {
			split.Images = append(split.Images, image)
		}
		for range MaxReportedComponents {
			split.Files = append(split.Files, file)
		}
		if err := split.Valid(); err == nil {
			t.Errorf("%d images plus %d files is twice the limit and must be rejected",
				MaxReportedComponents, MaxReportedComponents)
		}
	})
}

func TestEveryComponentBelongsToAStack(t *testing.T) {
	// The vocabulary itself, not a copy of it. A copy would have to be edited
	// alongside every addition and would go stale silently between them; what is
	// under test here is the STACK MAPPING, and it is the thing that must cover
	// whatever the vocabulary happens to contain. The vocabulary is separately
	// pinned against the server's in component_pairing_test.go.
	all := AllComponentTypes

	for _, component := range all {
		if err := component.Valid(); err != nil {
			t.Errorf("%s must be a valid component: %v", component, err)
		}
		stack, ok := ComponentToStackMapping[component]
		if !ok {
			t.Errorf("%s has no stack — its answer would be attributed to the wrong one", component)
			continue
		}
		if err := stack.Valid(); err != nil {
			t.Errorf("%s maps to an invalid stack %q", component, stack)
		}
	}

	if len(ComponentToStackMapping) != len(all) {
		t.Errorf("the mapping has %d entries but %d components are known",
			len(ComponentToStackMapping), len(all))
	}
}

// GoldenProductUpdateRequest is the exact wire form this package produces when a
// running product asks the update service what it should be running. The server
// side keeps a copy of this literal and asserts its own model accepts it, so a
// field renamed on either side turns one of the two tests red instead of silently
// producing requests nobody can parse.
//
// `info` is deliberately a shape this package does not model. It is versioned by
// the `schema` value inside it, so the contract carries it and never interprets
// it — and this literal is here to prove that a document the SDK knows nothing
// about survives the trip.
const GoldenProductUpdateRequest = `{
  "schema": 1,
  "version": "0.9.3",
  "os": "linux",
  "arch": "amd64",
  "binary_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "strategy": "preview",
  "info": {
    "schema": 1,
    "version": "0.9.3",
    "develop": false,
    "counts": {"users": 3, "flows": 12},
    "providers": [{"type": "openai", "count": 2}]
  }
}`

// GoldenProductUpdateResponse is the exact wire form the service answers with.
// The server keeps a copy of this literal too — this half of the contract is the
// one that only started to exist when the endpoint stopped being write-only, and
// a response nobody pinned is a response the service is free to reshape.
//
// `update` is an ordinary UpdateInfo, deliberately: the client that reads it is
// the same one that reads a check-updates answer, and a second shape for the same
// question would be a second thing to keep in step.
const GoldenProductUpdateResponse = `{
  "update": {
    "stack": "pentagi",
    "has_update": true,
    "latest_version": "2.4.0",
    "images": [
      {
        "component": "pentagi",
        "os": "linux",
        "arch": "amd64",
        "action": "upgrade",
        "pinned": false,
        "release_version": "2.4.0",
        "repository": "vxcontrol/pentagi",
        "tag": "2.4.0",
        "pull_reference": "vxcontrol/pentagi:latest",
        "image_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "config_hash": "2222222222222222222222222222222222222222222222222222222222222222"
      }
    ],
    "resolution": "channel"
  },
  "version": "2.4.0",
  "binary": {
    "size": 50331648,
    "hash": "3333333333333333333333333333333333333333333333333333333333333333",
    "version": "2.4.0",
    "os": "linux",
    "arch": "amd64",
    "signature": "MEUCIQ=="
  },
  "identified": true
}`

func TestProductUpdateResponseMatchesTheGoldenWireForm(t *testing.T) {
	var answer ProductUpdateResponse
	decoder := json.NewDecoder(strings.NewReader(GoldenProductUpdateResponse))
	// A field this package does not know is a contract break: the service
	// believed it was telling the client something.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		t.Fatalf("the golden response must decode into the model: %v", err)
	}
	if err := answer.Valid(); err != nil {
		t.Fatalf("the golden response must pass validation: %v", err)
	}

	if answer.Update == nil {
		t.Fatal("the stack answer must decode")
	}
	if answer.Update.Stack != ProductStackPentagi || !answer.Update.HasUpdate {
		t.Errorf("the stack answer was lost: %+v", answer.Update)
	}
	if len(answer.Update.Images) != 1 || answer.Update.Images[0].Action != ComponentActionUpgrade {
		t.Errorf("the offered image was lost: %+v", answer.Update.Images)
	}
	// The reference to pull is not repository:tag and must not be reconstructed
	// from them: under a moving channel it names the tag the artefact was FOUND
	// under, while `tag` names the artefact itself.
	if answer.Update.Images[0].PullReference != "vxcontrol/pentagi:latest" {
		t.Errorf("the pull reference was lost: %q", answer.Update.Images[0].PullReference)
	}
	if answer.Version == nil || *answer.Version != "2.4.0" {
		t.Errorf("the offered product version was lost: %v", answer.Version)
	}
	if answer.Binary == nil || answer.Binary.Version != "2.4.0" {
		t.Errorf("the executable of that version was lost: %+v", answer.Binary)
	}
	// The two halves describe ONE build. A client that downloaded the binary of a
	// version other than the image it was offered would be running something
	// nobody answered with.
	if answer.Binary.Version != *answer.Version {
		t.Errorf("the executable (%s) and the offered version (%s) disagree",
			answer.Binary.Version, *answer.Version)
	}
	if !answer.Identified {
		t.Error("the golden answer identifies the running build")
	}
}

// TestAnUnidentifiedBuildStillDecodes.
//
// The service cannot always tell which image a product runs — a development
// build, a private rebuild, an image published before the version label existed.
// The answer then describes the newest published build instead, and `identified`
// is the only thing that says so. A client that could not decode that answer
// would treat the one case it must handle carefully as a transport failure.
func TestAnUnidentifiedBuildStillDecodes(t *testing.T) {
	const unidentified = `{
  "update": {
    "stack": "pentagi",
    "has_update": true,
    "images": [
      {
        "component": "pentagi",
        "os": "linux",
        "arch": "amd64",
        "action": "install",
        "pinned": false,
        "repository": "vxcontrol/pentagi",
        "tag": "latest",
        "pull_reference": "vxcontrol/pentagi:latest",
        "image_hash": "1111111111111111111111111111111111111111111111111111111111111111"
      }
    ],
    "resolution": "channel"
  },
  "identified": false
}`

	var answer ProductUpdateResponse
	if err := json.Unmarshal([]byte(unidentified), &answer); err != nil {
		t.Fatalf("an unidentified answer must decode: %v", err)
	}
	if err := answer.Valid(); err != nil {
		t.Fatalf("an unidentified answer must validate: %v", err)
	}
	if answer.Identified {
		t.Error("identified must be false when the service could not match the build")
	}
	if answer.Version != nil || answer.Binary != nil {
		t.Error("nothing may be invented for a build the service could not identify")
	}
}

func TestProductUpdateRequestMatchesTheGoldenWireForm(t *testing.T) {
	var request ProductUpdateRequest
	decoder := json.NewDecoder(strings.NewReader(GoldenProductUpdateRequest))
	// A field this package does not know is a contract break, not something to
	// ignore quietly: the sender believed it was telling the service something.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		t.Fatalf("the golden request must decode into the model: %v", err)
	}
	if err := request.Valid(); err != nil {
		t.Fatalf("the golden request must pass validation: %v", err)
	}

	if request.Schema != 1 {
		t.Errorf("schema lost: %d", request.Schema)
	}
	if request.Version != "0.9.3" {
		t.Errorf("version lost: %q", request.Version)
	}
	if request.OS != OSTypeLinux || request.Arch != ArchTypeAMD64 {
		t.Errorf("platform lost: %s/%s", request.OS, request.Arch)
	}
	if len(request.BinaryHash) != 64 {
		t.Errorf("binary hash lost: %q", request.BinaryHash)
	}
	if request.Strategy != UpdateStrategyPreview {
		t.Errorf("the channel to answer from was lost: %q", request.Strategy)
	}

	// Carried byte for byte, not reshaped. The whole point of the field is that
	// the party sending it need not understand it, so anything that re-encodes it
	// on the way — a map, a typed struct, a normalising decoder — would silently
	// drop whatever this package does not name.
	if !json.Valid(request.Info) {
		t.Fatalf("the state document must arrive as usable JSON: %q", string(request.Info))
	}
	if !strings.Contains(string(request.Info), `"schema": 1`) {
		t.Errorf("the document must survive verbatim, including the version that selects its parser: %q",
			string(request.Info))
	}

	// And back out again with its content intact: a client builds this from a
	// document it did not author either.
	//
	// Content, not bytes. json.Marshal COMPACTS a json.RawMessage on the way out,
	// so an indented document comes back without its whitespace — which is why
	// anything comparing stored documents has to compact both sides first rather
	// than diff the strings.
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("the request must re-encode: %v", err)
	}
	var round ProductUpdateRequest
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatalf("the re-encoded request must decode: %v", err)
	}

	var before, after any
	if err := json.Unmarshal(request.Info, &before); err != nil {
		t.Fatalf("the original document must parse: %v", err)
	}
	if err := json.Unmarshal(round.Info, &after); err != nil {
		t.Fatalf("the round-tripped document must parse: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("the state document did not survive a round trip:\n before %s\n after  %s",
			request.Info, round.Info)
	}
}

// The bound belongs to the contract, not to whoever happens to send the request:
// the endpoint reads the body with no size limit of its own.
func TestProductUpdateRequestRejectsAnOversizedDocument(t *testing.T) {
	oversized := ProductUpdateRequest{
		Schema:  1,
		Version: "0.9.3",
		OS:      OSTypeLinux,
		Arch:    ArchTypeAMD64,
		Info:    json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxProductInfoBytes) + `"}`),
	}
	if err := oversized.Valid(); err == nil {
		t.Fatal("a document past MaxProductInfoBytes must not validate")
	}

	fits := oversized
	fits.Info = json.RawMessage(`{"schema":1}`)
	if err := fits.Valid(); err != nil {
		t.Fatalf("an ordinary document must validate: %v", err)
	}
}

// A development build is named after its branch, and this field is validated as
// a version — so the sender has to normalise it or lose the whole request over a
// field that is decoration. Pinned here because the rule lives on this side.
func TestProductUpdateRequestRequiresASemanticVersion(t *testing.T) {
	request := ProductUpdateRequest{
		Schema:  1,
		Version: "develop",
		OS:      OSTypeLinux,
		Arch:    ArchTypeAMD64,
		Info:    json.RawMessage(`{"schema":1}`),
	}
	if err := request.Valid(); err == nil {
		t.Fatal("a branch name must not pass as a version")
	}

	request.Version = "0.0.0"
	if err := request.Valid(); err != nil {
		t.Fatalf("the normalised placeholder must pass: %v", err)
	}
}

// The strategy arrived after the endpoint shipped, so a deployed build sends
// none. Requiring it would make every one of those requests invalid on this side
// before it even left the process, over a field whose absence has an obviously
// correct meaning on the other.
func TestProductUpdateRequestLeavesTheStrategyOptional(t *testing.T) {
	request := ProductUpdateRequest{
		Schema:  1,
		Version: "0.9.3",
		OS:      OSTypeLinux,
		Arch:    ArchTypeAMD64,
		Info:    json.RawMessage(`{"schema":1}`),
	}
	if err := request.Valid(); err != nil {
		t.Fatalf("a request naming no strategy must validate: %v", err)
	}
	// Omitted rather than sent empty: the service validates the field when it is
	// present, and "" is not a member of the vocabulary.
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("the request must encode: %v", err)
	}
	if strings.Contains(string(encoded), "strategy") {
		t.Errorf("an unset strategy must not reach the wire: %s", encoded)
	}

	request.Strategy = UpdateStrategy("whatever")
	if err := request.Valid(); err == nil {
		t.Fatal("an unrecognised strategy must not validate")
	}
	request.Strategy = UpdateStrategyStable
	if err := request.Valid(); err != nil {
		t.Fatalf("a named strategy must validate: %v", err)
	}
}

// goldenSupportStreamEvents are the data of the events of a streamed investigation,
// byte for byte as the server sends them. The server keeps a copy of these literals
// and asserts its own writer produces them: change one, change the other.
//
// thinking carries the reasoning of a model as an object, text and signature: some
// providers want both back on the next turn. A model call that reasoned nothing
// gives null, not {}.
var goldenSupportStreamEvents = []struct {
	event string
	data  string
	value any
}{
	{"start", `{"issue_id":"7f1e4c9a-0b52-4d0e-9c53-2f6a1d3b8e10"}`, SupportStreamStart{IssueID: uuid.MustParse("7f1e4c9a-0b52-4d0e-9c53-2f6a1d3b8e10")}},
	{"message", `{"message":"searching FAQ for startup errors","type":"search"}`, SupportStreamMessage{Message: "searching FAQ for startup errors", Type: MsgLogTypeSearch}},
	{"thinking", `{"stream_id":1,"thinking":{"content":"Analyzing","signature":"c2ln"}}`, SupportStreamThinking{StreamID: 1, Thinking: &SupportReasoning{Content: "Analyzing", Signature: []byte("sig")}}},
	{"content", `{"content":"Based on the logs","stream_id":1}`, SupportStreamContent{Content: "Based on the logs", StreamID: 1}},
	{"update", `{"content":"Based on the logs","stream_id":1,"thinking":{"content":"Analyzing"}}`, SupportStreamUpdate{Content: "Based on the logs", StreamID: 1, Thinking: &SupportReasoning{Content: "Analyzing"}}},
	{"update", `{"content":"Based on the logs","stream_id":1,"thinking":null}`, SupportStreamUpdate{Content: "Based on the logs", StreamID: 1}},
	{"flush", `{"stream_id":1}`, SupportStreamFlush{StreamID: 1}},
}

// TestSupportStreamEventsParseTheGoldenWireForms proves this package reads every field
// the server writes into an event and writes the same bytes back: a field renamed on
// one side only reaches the caller as an event with nothing in it, with no error.
func TestSupportStreamEventsParseTheGoldenWireForms(t *testing.T) {
	for _, golden := range goldenSupportStreamEvents {
		read := reflect.New(reflect.TypeOf(golden.value))
		decoder := json.NewDecoder(strings.NewReader(golden.data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(read.Interface()); err != nil {
			t.Errorf("%s does not parse: %v", golden.event, err)
			continue
		}
		if !reflect.DeepEqual(read.Elem().Interface(), golden.value) {
			t.Errorf("%s parses as %+v, want %+v", golden.event, read.Elem().Interface(), golden.value)
		}

		written, err := json.Marshal(golden.value)
		if err != nil {
			t.Fatalf("%s: %v", golden.event, err)
		}
		if string(written) != golden.data {
			t.Errorf("%s is written as\n  %s\nwant\n  %s", golden.event, written, golden.data)
		}
	}
}

// goldenLLMModels is the list of agents of Cloud LLM a licensed installation reads,
// byte for byte: the list object of the OpenAI API, each agent a model object of it with
// what a caller needs to call the agent. The server pins the same literal: if you change
// one, change the other. supported_parameters is written for an agent that takes none
// too, as [], so that "none" never reads as "unknown"; the output limit is listed in both
// spellings because the server takes either.
const goldenLLMModels = `{"object":"list","data":[{"id":"pentagi.coder","object":"model","created":1781092800,"owned_by":"pentagi","type":"completion","description":"Coder","context_window":131072,"max_output_tokens":8192,"max_input_size":2097152,"supported_parameters":["max_completion_tokens","max_tokens","response_format","temperature","tool_choice","tools"]},{"id":"pentagi.embedding","object":"model","created":1781092800,"owned_by":"pentagi","type":"embedding","max_input_size":2097152,"supported_parameters":[],"dimensions":1024,"max_batch_size":64}]}`

// TestLLMModelsParseTheGoldenWireForm proves this package reads every field of the list
// of agents and writes the same bytes back: a field renamed on one side only would
// reach the caller as an agent with nothing in it, with no error.
func TestLLMModelsParseTheGoldenWireForm(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(goldenLLMModels))
	decoder.DisallowUnknownFields()
	var list LLMModelsResponse
	if err := decoder.Decode(&list); err != nil {
		t.Fatalf("the golden list does not parse: %v", err)
	}
	if err := list.Valid(); err != nil {
		t.Fatalf("the golden list is not valid: %v", err)
	}
	if len(list.Data) != 2 || list.Data[0].ID != "pentagi.coder" || list.Data[0].Created != 1781092800 ||
		list.Data[0].Type != LLMModelTypeCompletion || *list.Data[0].MaxOutputTokens != 8192 || len(list.Data[0].SupportedParameters) != 6 ||
		list.Data[1].Type != LLMModelTypeEmbedding || *list.Data[1].MaxBatchSize != 64 || *list.Data[1].Dimensions != 1024 {
		t.Errorf("the golden list reads as %+v", list)
	}
	written, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != goldenLLMModels {
		t.Errorf("the list is written as\n  %s\nwant\n  %s", written, goldenLLMModels)
	}
}

// TestLLMModelsRefuseWhatIsNotAListOfAgents proves a list is taken only in its own shape.
// The envelope is read leniently, so a body of any other shape — the list of a server
// that spoke an older form, a list with its agents' names lost — decodes without error
// into a list of no agents, or into agents with nothing in them, and would read as a
// licence offered nothing; and an agent whose supported_parameters is missing would read
// as one that takes nothing, where the server meant it did not say.
func TestLLMModelsRefuseWhatIsNotAListOfAgents(t *testing.T) {
	agent := func() LLMModelInfo {
		return LLMModelInfo{ID: "pentagi.coder", Object: "model", OwnedBy: "pentagi", Type: LLMModelTypeCompletion, MaxInputSize: 1, SupportedParameters: []string{}}
	}
	if err := (LLMModelsResponse{Object: "list", Data: []LLMModelInfo{agent()}}).Valid(); err != nil {
		t.Fatalf("a valid list is refused: %v", err)
	}
	for name, body := range map[string]string{
		"the list of an older form": `{"models":[{"name":"pentagi.coder","type":"completion","max_input_size":1}]}`,
		"a list without its object": `{"data":[]}`,
	} {
		var list LLMModelsResponse
		if err := json.Unmarshal([]byte(body), &list); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if list.Valid() == nil {
			t.Errorf("%s passes as a list of %d agents", name, len(list.Data))
		}
	}
	for name, broken := range map[string]func(*LLMModelInfo){
		"an agent without its name":                func(i *LLMModelInfo) { i.ID = "" },
		"an object that is not a model":            func(i *LLMModelInfo) { i.Object = "list" },
		"an agent without its owner":               func(i *LLMModelInfo) { i.OwnedBy = "" },
		"an agent of a type nobody serves":         func(i *LLMModelInfo) { i.Type = "chat" },
		"an agent that takes no body":              func(i *LLMModelInfo) { i.MaxInputSize = 0 },
		"an agent that does not say what it takes": func(i *LLMModelInfo) { i.SupportedParameters = nil },
	} {
		info := agent()
		broken(&info)
		if (LLMModelsResponse{Object: "list", Data: []LLMModelInfo{info}}).Valid() == nil {
			t.Errorf("%s passes", name)
		}
	}
}

// goldenLicenseStatus is the status of a licence an installation reads, byte for byte: the
// payload of the envelope. The server pins the same literal: if you change one, change the
// other. It carries every kind of share — -1 for no ceiling, 100 for a quota used up, 0
// for one untouched, and the shares between — and `tokens` both absent and 0: absent is a
// limit that meters no tokens, and 0 is a limit that meters them and has used none. A
// fixture with tokens on every quota would leave `omitempty` free to be dropped, and one
// without a zero would leave a 0 free to vanish into "meters no tokens".
const goldenLicenseStatus = `{"tier":"enterprise","features":{"updates":true,"support":true,"knowledge_base":false,"cloud_llm":true},"quotas":[{"limit":"llm_agent","daily":{"requests":-1},"monthly":{"requests":-1}},{"limit":"llm_automation","daily":{"requests":100},"monthly":{"requests":30}},{"limit":"llm_completion","daily":{"requests":1,"tokens":13},"monthly":{"requests":1,"tokens":4}},{"limit":"llm_embedding","daily":{"requests":0,"tokens":0},"monthly":{"requests":1,"tokens":2}}]}`

// TestLicenseStatusParsesTheGoldenWireForm proves this package reads every field of the
// status of a licence and writes the same bytes back. A field renamed on one side only
// would reach the installation as a feature switched off or a quota with nothing used,
// with no error, and the settings of the product would show it as the truth.
func TestLicenseStatusParsesTheGoldenWireForm(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(goldenLicenseStatus))
	decoder.DisallowUnknownFields()
	var status LicenseStatusResponse
	if err := decoder.Decode(&status); err != nil {
		t.Fatalf("the golden status does not parse: %v", err)
	}
	if err := status.Valid(); err != nil {
		t.Fatalf("the golden status is not valid: %v", err)
	}

	if status.Tier != "enterprise" {
		t.Errorf("the tier reads as %q", status.Tier)
	}
	if status.Features != (LicenseFeatures{Updates: true, Support: true, KnowledgeBase: false, CloudLLM: true}) {
		t.Errorf("the features read as %+v", status.Features)
	}
	// The known names are what a caller looks a quota up by; a constant spelled other than
	// the server spells the limit finds nothing, and the quota reads as one not offered.
	known := []string{LicenseQuotaLLMAgent, LicenseQuotaLLMAutomation, LicenseQuotaLLMCompletion, LicenseQuotaLLMEmbedding}
	if len(status.Quotas) != len(known) {
		t.Fatalf("the golden status reads as %d quotas, want %d", len(status.Quotas), len(known))
	}
	for i, limit := range known {
		if status.Quotas[i].Limit != limit {
			t.Errorf("quota %d is %q, want %q", i, status.Quotas[i].Limit, limit)
		}
	}
	agent, automation, completion, embedding := status.Quotas[0], status.Quotas[1], status.Quotas[2], status.Quotas[3]
	if agent.Daily.Requests != LicenseQuotaUnlimited || agent.Daily.Tokens != nil {
		t.Errorf("a quota with no ceiling and no tokens reads as %+v", agent.Daily)
	}
	if automation.Daily.Requests != 100 || automation.Monthly.Requests != 30 {
		t.Errorf("a quota used up today reads as %+v", automation)
	}
	if completion.Daily.Tokens == nil || *completion.Daily.Tokens != 13 || completion.Monthly.Tokens == nil || *completion.Monthly.Tokens != 4 {
		t.Errorf("the share of tokens reads as %+v", completion)
	}
	if embedding.Daily.Tokens == nil || *embedding.Daily.Tokens != 0 {
		t.Errorf("a quota of tokens with none used reads as one that meters no tokens: %+v", embedding.Daily)
	}

	written, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != goldenLicenseStatus {
		t.Errorf("the status is written as\n  %s\nwant\n  %s", written, goldenLicenseStatus)
	}

	// The way a caller reads it: the answer arrives in the envelope of every JSON answer.
	enveloped, err := ParseEnvelope[LicenseStatusResponse]([]byte(`{"status":"success","data":` + goldenLicenseStatus + `}`))
	if err != nil {
		t.Fatalf("the enveloped status does not parse: %v", err)
	}
	if !reflect.DeepEqual(enveloped, status) {
		t.Errorf("the enveloped status reads as %+v, want %+v", enveloped, status)
	}
}

// TestLicenseStatusRefusesWhatIsNotAStatus proves a status is taken only in its own shape.
// The envelope is read leniently, so a body of any other shape — the envelope decoded as
// the status, the answer of a server that spoke another form — decodes without error into
// a status of no tier and no quotas, and would read as a licence with every feature off
// and nothing to watch; a share outside -1..100 is not a share the server computes, and a
// screen that drew it would draw a bar past its end. Every quota is checked, not the first.
func TestLicenseStatusRefusesWhatIsNotAStatus(t *testing.T) {
	share := func(v int) *int { return &v }
	status := func() LicenseStatusResponse {
		return LicenseStatusResponse{
			Tier:     "pro",
			Features: LicenseFeatures{Updates: true, Support: true, CloudLLM: true},
			Quotas: []LicenseQuota{
				{Limit: LicenseQuotaLLMAgent, Daily: LicenseQuotaUsage{Requests: 5}, Monthly: LicenseQuotaUsage{Requests: 1}},
				{
					Limit:   LicenseQuotaLLMCompletion,
					Daily:   LicenseQuotaUsage{Requests: 12, Tokens: share(13)},
					Monthly: LicenseQuotaUsage{Requests: 3, Tokens: share(4)},
				},
			},
		}
	}
	last := func(s *LicenseStatusResponse) *LicenseQuota { return &s.Quotas[len(s.Quotas)-1] }

	for name, accepted := range map[string]func(*LicenseStatusResponse){
		"a status":                       func(*LicenseStatusResponse) {},
		"a licence offered no quota":     func(s *LicenseStatusResponse) { s.Quotas = []LicenseQuota{} },
		"no ceiling":                     func(s *LicenseStatusResponse) { last(s).Daily = LicenseQuotaUsage{Requests: -1, Tokens: share(-1)} },
		"nothing used":                   func(s *LicenseStatusResponse) { last(s).Daily = LicenseQuotaUsage{Requests: 0, Tokens: share(0)} },
		"a quota used up":                func(s *LicenseStatusResponse) { last(s).Monthly = LicenseQuotaUsage{Requests: 100, Tokens: share(100)} },
		"a limit the server names later": func(s *LicenseStatusResponse) { last(s).Limit = "llm_vision" },
		"a tier the server names later":  func(s *LicenseStatusResponse) { s.Tier = "partner" },
		"a quota that meters no tokens":  func(s *LicenseStatusResponse) { last(s).Monthly.Tokens = nil },
	} {
		s := status()
		accepted(&s)
		if err := s.Valid(); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}

	for name, body := range map[string]string{
		"an empty object":                    `{}`,
		"the envelope decoded as the status": `{"status":"success","data":` + goldenLicenseStatus + `}`,
		"a status without its quotas":        `{"tier":"pro","features":{"updates":true,"support":true,"knowledge_base":false,"cloud_llm":false},"quotas":null}`,
		"a status without its tier":          `{"tier":"","features":{"updates":true,"support":true,"knowledge_base":false,"cloud_llm":false},"quotas":[]}`,
	} {
		var read LicenseStatusResponse
		if err := json.Unmarshal([]byte(body), &read); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if read.Valid() == nil {
			t.Errorf("%s passes as the status of a %q licence with %d quotas", name, read.Tier, len(read.Quotas))
		}
	}

	broken := map[string]func(*LicenseStatusResponse){
		"a quota without its limit": func(s *LicenseStatusResponse) { last(s).Limit = "" },
	}
	for _, value := range []int{-2, 101} {
		for period, usage := range map[string]func(*LicenseStatusResponse) *LicenseQuotaUsage{
			"daily":   func(s *LicenseStatusResponse) *LicenseQuotaUsage { return &last(s).Daily },
			"monthly": func(s *LicenseStatusResponse) *LicenseQuotaUsage { return &last(s).Monthly },
		} {
			broken[fmt.Sprintf("%s requests of %d", period, value)] = func(s *LicenseStatusResponse) { usage(s).Requests = value }
			broken[fmt.Sprintf("%s tokens of %d", period, value)] = func(s *LicenseStatusResponse) { usage(s).Tokens = share(value) }
		}
	}
	for name, breaks := range broken {
		s := status()
		breaks(&s)
		if s.Valid() == nil {
			t.Errorf("a status with %s passes", name)
		}
	}
}

// goldenSupportIssueStatus are the two forms of the status of an issue, byte for byte: the
// payload of the envelope before the first question of the conversation, with no
// updated_at, and after it. The server pins the same literals: if you change one, change
// the other. updated_at carries microseconds: a client compares it with the one it read
// before to know the conversation moved, and a form that rounded it would hide a turn that
// ended within the same second.
var goldenSupportIssueStatus = []struct {
	data  string
	value func() SupportIssueStatusResponse
}{
	{`{"status":"processing"}`, func() SupportIssueStatusResponse {
		return SupportIssueStatusResponse{Status: SupportIssueStatusProcessing}
	}},
	{`{"status":"processed","updated_at":"2026-10-16T10:00:00.123456Z"}`, func() SupportIssueStatusResponse {
		updated := time.Date(2026, 10, 16, 10, 0, 0, 123456000, time.UTC)
		return SupportIssueStatusResponse{Status: SupportIssueStatusProcessed, UpdatedAt: &updated}
	}},
}

// TestSupportIssueStatusParsesTheGoldenWireForms proves this package reads every field of
// the status of an issue, in the envelope as a caller reads it, and writes the same bytes
// back: a field renamed on one side only would reach the caller as an issue with no status,
// which it could neither show nor wait on. A status the server does not have is refused,
// and so is the envelope decoded as the status — its "status" is "success".
func TestSupportIssueStatusParsesTheGoldenWireForms(t *testing.T) {
	for _, golden := range goldenSupportIssueStatus {
		decoder := json.NewDecoder(strings.NewReader(golden.data))
		decoder.DisallowUnknownFields()
		var status SupportIssueStatusResponse
		if err := decoder.Decode(&status); err != nil {
			t.Fatalf("%s does not parse: %v", golden.data, err)
		}
		if err := status.Valid(); err != nil {
			t.Fatalf("%s is not valid: %v", golden.data, err)
		}
		if !reflect.DeepEqual(status, golden.value()) {
			t.Errorf("%s parses as %+v, want %+v", golden.data, status, golden.value())
		}
		written, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if string(written) != golden.data {
			t.Errorf("the status is written as\n  %s\nwant\n  %s", written, golden.data)
		}

		enveloped, err := ParseEnvelope[SupportIssueStatusResponse]([]byte(`{"status":"success","data":` + golden.data + `}`))
		if err != nil {
			t.Fatalf("the enveloped status does not parse: %v", err)
		}
		if !reflect.DeepEqual(enveloped, status) {
			t.Errorf("the enveloped status reads as %+v, want %+v", enveloped, status)
		}
	}

	for _, value := range []SupportIssueStatus{"failed", "starting", "success", ""} {
		if (SupportIssueStatusResponse{Status: value}).Valid() == nil {
			t.Errorf("a status of %q passes", value)
		}
	}
	var envelope SupportIssueStatusResponse
	if err := json.Unmarshal([]byte(`{"status":"success","data":`+goldenSupportIssueStatus[1].data+`}`), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Valid() == nil {
		t.Errorf("the envelope decoded as the status passes as the status %q", envelope.Status)
	}
}

// goldenSupportIssueMessages is the conversation of an issue, byte for byte, and the
// conversation of an issue nobody has asked about yet: a list, never null. A caller keeps
// the messages as it reads them, so a field renamed on one side only would leave it a
// conversation of empty messages. The server pins the same literals: change one, change
// the other.
var goldenSupportIssueMessages = []struct {
	data  string
	value func() SupportIssueMessagesResponse
}{
	{`{"messages":[{"type":"input","message":"Why does the terminal of flow 12 never start?","created_at":"2026-10-16T10:01:00Z"},{"type":"search","message":"searching FAQ for terminal startup errors","created_at":"2026-10-16T10:01:02Z"},{"type":"done","message":"The image of the flow could not be pulled; check the registry the installation uses.","created_at":"2026-10-16T10:01:30.5Z"}]}`, func() SupportIssueMessagesResponse {
		return SupportIssueMessagesResponse{Messages: []SupportMsgLog{
			{Type: MsgLogTypeInput, Message: "Why does the terminal of flow 12 never start?", CreatedAt: time.Date(2026, 10, 16, 10, 1, 0, 0, time.UTC)},
			{Type: MsgLogTypeSearch, Message: "searching FAQ for terminal startup errors", CreatedAt: time.Date(2026, 10, 16, 10, 1, 2, 0, time.UTC)},
			{Type: MsgLogTypeDone, Message: "The image of the flow could not be pulled; check the registry the installation uses.", CreatedAt: time.Date(2026, 10, 16, 10, 1, 30, 500000000, time.UTC)},
		}}
	}},
	{`{"messages":[]}`, func() SupportIssueMessagesResponse {
		return SupportIssueMessagesResponse{Messages: []SupportMsgLog{}}
	}},
}

func TestSupportIssueMessagesParseTheGoldenWireForms(t *testing.T) {
	for _, golden := range goldenSupportIssueMessages {
		decoder := json.NewDecoder(strings.NewReader(golden.data))
		decoder.DisallowUnknownFields()
		var messages SupportIssueMessagesResponse
		if err := decoder.Decode(&messages); err != nil {
			t.Fatalf("%s does not parse: %v", golden.data, err)
		}
		if err := messages.Valid(); err != nil {
			t.Fatalf("%s is not valid: %v", golden.data, err)
		}
		if !reflect.DeepEqual(messages, golden.value()) {
			t.Errorf("%s parses as %+v, want %+v", golden.data, messages, golden.value())
		}
		written, err := json.Marshal(messages)
		if err != nil {
			t.Fatal(err)
		}
		if string(written) != golden.data {
			t.Errorf("the messages are written as\n  %s\nwant\n  %s", written, golden.data)
		}
	}
}

// goldenSupportIssueDetailsValue is the document of goldenSupportIssueDetails as a value:
// every part present, every list and map holding something, and both forms of the fields
// that have two — a provider of the environment without created_at beside one a user
// added with it. A part left out would be a part either side may rename unnoticed.
func goldenSupportIssueDetailsValue() SupportIssueDetails {
	at := func(value string) time.Time {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			panic(err)
		}
		return parsed
	}
	atPtr := func(value string) *time.Time { parsed := at(value); return &parsed }
	ref := func(value string) *string { return &value }
	scope := int64(12)

	return SupportIssueDetails{
		Schema:      1,
		Description: `Flows stop after a few minutes with "provider rejected" and the terminal never starts.`,
		CollectedAt: at("2026-10-16T10:00:00Z"),
		Product: SupportIssueProduct{
			Version: "1.2.0", OS: "linux", Arch: "amd64",
			BinaryHash:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			UptimeSeconds: 93600, DockerInside: true, DefaultImage: "debian:latest",
		},
		Host: &SupportIssueHost{
			DockerVersion: "27.3.1", OS: "Ubuntu 24.04.1 LTS", OSType: "linux", Architecture: "x86_64",
			Kernel: "6.8.0-45-generic", CPUs: 8, MemoryBytes: 33608757248,
		},
		License: &SupportIssueLicense{
			Tier: "pro", State: "current", Features: LicenseFeatures{Updates: true, Support: true},
			ExpiresAt: at("2027-10-15T00:00:00Z"), CheckedAt: atPtr("2026-10-16T09:55:00Z"),
		},
		Providers: []SupportIssueProvider{
			{Ref: "p1", Type: "openai", Source: "env", Models: map[string]string{"primary_agent": "gpt-5", "coder": "gpt-5-mini"}},
			{Ref: "p2", Type: "custom", Source: "user", CreatedAt: atPtr("2026-09-01T12:00:00Z"), Models: map[string]string{"primary_agent": "qwen3"}},
		},
		Installation: &SupportIssueInstallation{
			EmbeddingProvider: "openai",
			OAuth:             []string{"github", "google"},
			Features:          map[string]bool{"ask_user": false, "assistant_use_agents": true, "debug": false, "docker_inside": true},
			Counts: map[string]int64{
				"users": 3, "flows": 12, "flows_active": 1, "tasks": 87, "subtasks": 64,
				"containers": 5, "assistants": 2, "toolcalls": 1400,
			},
		},
		Flow: &SupportIssueFlow{
			ID: 12, Status: "failed", Language: "English", ProviderRef: ref("p1"), ProviderType: "openai", Model: "gpt-5",
			CreatedAt: at("2026-10-15T08:05:00Z"), UpdatedAt: at("2026-10-16T09:58:00Z"),
			TimeBudgetSeconds: 7200, MaxSubtasks: 20, MaxSubagents: 4,
			Tasks:      SupportIssueCounts{Total: 4, ByStatus: map[string]int64{"failed": 1, "finished": 3}},
			Subtasks:   SupportIssueCounts{Total: 17, ByStatus: map[string]int64{"failed": 3, "finished": 14}},
			Assistants: SupportIssueCounts{Total: 1, ByStatus: map[string]int64{"finished": 1}},
			Usage:      SupportIssueUsage{In: 1200000, Out: 85000, CacheIn: 640000, CacheOut: 12000, CostIn: 3.6, CostOut: 0.85},
			Toolcalls: SupportIssueToolcalls{Total: 140, Failed: 45, DurationSeconds: 512.5, ByFunction: []SupportIssueFunction{
				{Name: "terminal", Count: 90, Failed: 30},
				{Name: "browser", Count: 30, Failed: 15},
				{Name: "coder", IsAgent: true, Count: 20},
			}},
			UsageByModel: []SupportIssueModelUsage{
				{Model: "gpt-5", ProviderRef: ref("p1"), Agents: []string{"primary_agent", "reflector"}, SupportIssueUsage: SupportIssueUsage{In: 1000000, Out: 70000, CacheIn: 600000, CacheOut: 10000, CostIn: 3.1, CostOut: 0.7}},
				{Model: "gpt-5-mini", ProviderRef: ref("p1"), Agents: []string{"coder"}, SupportIssueUsage: SupportIssueUsage{In: 200000, Out: 15000, CacheIn: 40000, CacheOut: 2000, CostIn: 0.5, CostOut: 0.15}},
			},
			UsageByAgent: []SupportIssueAgentUsage{
				{Agent: "primary_agent", SupportIssueUsage: SupportIssueUsage{In: 900000, Out: 60000, CacheIn: 560000, CacheOut: 9000, CostIn: 2.7, CostOut: 0.6}},
				{Agent: "coder", SupportIssueUsage: SupportIssueUsage{In: 200000, Out: 15000, CacheIn: 40000, CacheOut: 2000, CostIn: 0.5, CostOut: 0.15}},
				{Agent: "reflector", SupportIssueUsage: SupportIssueUsage{In: 100000, Out: 10000, CacheIn: 40000, CacheOut: 1000, CostIn: 0.4, CostOut: 0.1}},
			},
			Chains: SupportIssueChains{
				Reflector:     SupportIssueTally{Total: 12, Failed: 2},
				ToolCallFixer: SupportIssueTally{Total: 3, Failed: 1},
				Subagents:     SupportIssueTally{Total: 6},
			},
			Container: &SupportIssueContainer{Image: "vxcontrol/kali-linux", Status: "running", Live: "running"},
			Errors: []SupportIssueFlowError{
				{Kind: "toolcall", Name: "terminal", Status: "failed", ErrorClass: "timeout", ResultLength: 1000, CreatedAt: at("2026-10-16T09:40:00Z")},
				{Kind: "subtask", Name: "31", Status: "failed", ErrorClass: "provider_rejected", CreatedAt: at("2026-10-16T09:57:00Z")},
			},
		},
		Logs: SupportIssueLogs{
			Available: true, Lines: 487, Matched: 1830, Files: 2,
			From: atPtr("2026-10-15T08:00:00Z"), To: atPtr("2026-10-16T10:00:00Z"), DroppedLong: 1,
			Filter: SupportIssueLogFilter{Scope: &scope, Admin: true, RedactedKeys: []string{"args", "result", "url"}},
			Counts: map[string]int64{"warning": 120, "error": 30, "database": 3},
		},
		Findings: []SupportIssueFinding{
			{Code: "provider_rejections", Severity: "warning", Detail: "14 lines: the provider rejected requests of the flow (6 retries)"},
			{Code: "toolcalls_failing", Severity: "warning", Detail: "45 of 140 tool calls failed, mostly timeout"},
		},
		Skipped: []string{"pentagi-2026-10-14T10-00-00.000.log"},
	}
}

// goldenSupportIssueDetails is the error_details of an issue the product reports, schema
// 1, as json.MarshalIndent writes it: the fields in the order and with the names and the
// types they travel with, compact. The server pins the same literal and renders the
// context of an issue for its support assistant from it. If you change one, change the
// other.
const goldenSupportIssueDetails = `{
  "schema": 1,
  "description": "Flows stop after a few minutes with \"provider rejected\" and the terminal never starts.",
  "collected_at": "2026-10-16T10:00:00Z",
  "product": {
    "version": "1.2.0",
    "develop": false,
    "os": "linux",
    "arch": "amd64",
    "binary_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "uptime_seconds": 93600,
    "debug": false,
    "docker_inside": true,
    "default_image": "debian:latest",
    "multi_tenant": false
  },
  "host": {
    "docker_version": "27.3.1",
    "os": "Ubuntu 24.04.1 LTS",
    "os_type": "linux",
    "architecture": "x86_64",
    "kernel": "6.8.0-45-generic",
    "cpus": 8,
    "memory_bytes": 33608757248
  },
  "license": {
    "tier": "pro",
    "state": "current",
    "features": {
      "updates": true,
      "support": true,
      "knowledge_base": false,
      "cloud_llm": false
    },
    "expires_at": "2027-10-15T00:00:00Z",
    "checked_at": "2026-10-16T09:55:00Z"
  },
  "providers": [
    {
      "ref": "p1",
      "type": "openai",
      "source": "env",
      "models": {
        "coder": "gpt-5-mini",
        "primary_agent": "gpt-5"
      }
    },
    {
      "ref": "p2",
      "type": "custom",
      "source": "user",
      "created_at": "2026-09-01T12:00:00Z",
      "models": {
        "primary_agent": "qwen3"
      }
    }
  ],
  "installation": {
    "embedding_provider": "openai",
    "oauth": [
      "github",
      "google"
    ],
    "features": {
      "ask_user": false,
      "assistant_use_agents": true,
      "debug": false,
      "docker_inside": true
    },
    "counts": {
      "assistants": 2,
      "containers": 5,
      "flows": 12,
      "flows_active": 1,
      "subtasks": 64,
      "tasks": 87,
      "toolcalls": 1400,
      "users": 3
    }
  },
  "flow": {
    "id": 12,
    "status": "failed",
    "language": "English",
    "provider_ref": "p1",
    "provider_type": "openai",
    "model": "gpt-5",
    "created_at": "2026-10-15T08:05:00Z",
    "updated_at": "2026-10-16T09:58:00Z",
    "time_budget_seconds": 7200,
    "max_subtasks": 20,
    "max_subagents": 4,
    "tasks": {
      "total": 4,
      "by_status": {
        "failed": 1,
        "finished": 3
      }
    },
    "subtasks": {
      "total": 17,
      "by_status": {
        "failed": 3,
        "finished": 14
      }
    },
    "assistants": {
      "total": 1,
      "by_status": {
        "finished": 1
      }
    },
    "usage": {
      "in": 1200000,
      "out": 85000,
      "cache_in": 640000,
      "cache_out": 12000,
      "cost_in": 3.6,
      "cost_out": 0.85
    },
    "toolcalls": {
      "total": 140,
      "failed": 45,
      "duration_seconds": 512.5,
      "by_function": [
        {
          "name": "terminal",
          "is_agent": false,
          "count": 90,
          "failed": 30
        },
        {
          "name": "browser",
          "is_agent": false,
          "count": 30,
          "failed": 15
        },
        {
          "name": "coder",
          "is_agent": true,
          "count": 20,
          "failed": 0
        }
      ]
    },
    "usage_by_model": [
      {
        "model": "gpt-5",
        "provider_ref": "p1",
        "agents": [
          "primary_agent",
          "reflector"
        ],
        "in": 1000000,
        "out": 70000,
        "cache_in": 600000,
        "cache_out": 10000,
        "cost_in": 3.1,
        "cost_out": 0.7
      },
      {
        "model": "gpt-5-mini",
        "provider_ref": "p1",
        "agents": [
          "coder"
        ],
        "in": 200000,
        "out": 15000,
        "cache_in": 40000,
        "cache_out": 2000,
        "cost_in": 0.5,
        "cost_out": 0.15
      }
    ],
    "usage_by_agent": [
      {
        "agent": "primary_agent",
        "in": 900000,
        "out": 60000,
        "cache_in": 560000,
        "cache_out": 9000,
        "cost_in": 2.7,
        "cost_out": 0.6
      },
      {
        "agent": "coder",
        "in": 200000,
        "out": 15000,
        "cache_in": 40000,
        "cache_out": 2000,
        "cost_in": 0.5,
        "cost_out": 0.15
      },
      {
        "agent": "reflector",
        "in": 100000,
        "out": 10000,
        "cache_in": 40000,
        "cache_out": 1000,
        "cost_in": 0.4,
        "cost_out": 0.1
      }
    ],
    "chains": {
      "reflector": {
        "total": 12,
        "failed": 2
      },
      "tool_call_fixer": {
        "total": 3,
        "failed": 1
      },
      "subagents": {
        "total": 6,
        "failed": 0
      }
    },
    "container": {
      "image": "vxcontrol/kali-linux",
      "status": "running",
      "live": "running"
    },
    "errors": [
      {
        "kind": "toolcall",
        "name": "terminal",
        "status": "failed",
        "error_class": "timeout",
        "result_length": 1000,
        "created_at": "2026-10-16T09:40:00Z"
      },
      {
        "kind": "subtask",
        "name": "31",
        "status": "failed",
        "error_class": "provider_rejected",
        "result_length": 0,
        "created_at": "2026-10-16T09:57:00Z"
      }
    ]
  },
  "logs": {
    "available": true,
    "lines": 487,
    "matched": 1830,
    "files": 2,
    "from": "2026-10-15T08:00:00Z",
    "to": "2026-10-16T10:00:00Z",
    "truncated": false,
    "dropped_long": 1,
    "filter": {
      "scope": 12,
      "admin": true,
      "redacted_keys": [
        "args",
        "result",
        "url"
      ]
    },
    "counts": {
      "database": 3,
      "error": 30,
      "warning": 120
    }
  },
  "findings": [
    {
      "code": "provider_rejections",
      "severity": "warning",
      "detail": "14 lines: the provider rejected requests of the flow (6 retries)"
    },
    {
      "code": "toolcalls_failing",
      "severity": "warning",
      "detail": "45 of 140 tool calls failed, mostly timeout"
    }
  ],
  "skipped": [
    "pentagi-2026-10-14T10-00-00.000.log"
  ]
}`

// TestSupportIssueDetailsMatchTheGoldenWireForm proves this package writes the document
// as the server reads it and reads it back whole: a field renamed on one side only would
// reach the support assistant as a part of the issue with nothing in it, and the assistant
// would reason from a blank as from a fact. A document of a later schema still reads by
// the fields of schema 1 — the schema grows by adding fields. Valid holds the bounds a
// sender checks: a description counted in runes, not bytes, and every list at its bound
// and not past it, the lists inside the flow included.
func TestSupportIssueDetailsMatchTheGoldenWireForm(t *testing.T) {
	details := goldenSupportIssueDetailsValue()
	if err := details.Valid(); err != nil {
		t.Fatalf("the golden document is not valid: %v", err)
	}
	written, err := json.MarshalIndent(details, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != goldenSupportIssueDetails {
		t.Errorf("the document is written as\n%s\nwant\n%s", written, goldenSupportIssueDetails)
	}

	decoder := json.NewDecoder(strings.NewReader(goldenSupportIssueDetails))
	decoder.DisallowUnknownFields()
	var back SupportIssueDetails
	if err := decoder.Decode(&back); err != nil {
		t.Fatalf("the golden document does not parse: %v", err)
	}
	if !reflect.DeepEqual(back, details) {
		t.Errorf("the golden document parses as another document\n read: %+v\n built: %+v", back, details)
	}

	later := strings.Replace(goldenSupportIssueDetails, `"schema": 1,`, `"schema": 2, "screenshots": [{"name": "flow.png"}],`, 1)
	later = strings.Replace(later, `"flow": {`, `"flow": {"agents_running": 3,`, 1)
	var future SupportIssueDetails
	if err := json.Unmarshal([]byte(later), &future); err != nil {
		t.Fatalf("a document of a later schema does not parse: %v", err)
	}
	future.Schema = details.Schema
	if !reflect.DeepEqual(future, details) {
		t.Errorf("a document of a later schema parses as another document\n read: %+v\n built: %+v", future, details)
	}

	for name, accepted := range map[string]func(*SupportIssueDetails){
		"a description of 4000 runes of two bytes": func(d *SupportIssueDetails) { d.Description = strings.Repeat("ж", 4000) },
		"no description": func(d *SupportIssueDetails) { d.Description = "" },
		"only the parts that are always there": func(d *SupportIssueDetails) {
			*d = SupportIssueDetails{Schema: 1, CollectedAt: d.CollectedAt, Product: d.Product, Logs: SupportIssueLogs{}}
		},
		"32 providers":                       func(d *SupportIssueDetails) { d.Providers = make([]SupportIssueProvider, 32) },
		"64 findings":                        func(d *SupportIssueDetails) { d.Findings = make([]SupportIssueFinding, 64) },
		"32 parts skipped":                   func(d *SupportIssueDetails) { d.Skipped = make([]string, 32) },
		"30 errors of the flow":              func(d *SupportIssueDetails) { d.Flow.Errors = make([]SupportIssueFlowError, 30) },
		"10 functions of the flow":           func(d *SupportIssueDetails) { d.Flow.Toolcalls.ByFunction = make([]SupportIssueFunction, 10) },
		"10 models of the flow":              func(d *SupportIssueDetails) { d.Flow.UsageByModel = make([]SupportIssueModelUsage, 10) },
		"a development build of the product": func(d *SupportIssueDetails) { d.Product.Version = "0.0.0" },
	} {
		document := goldenSupportIssueDetailsValue()
		accepted(&document)
		if err := document.Valid(); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
	for name, broken := range map[string]func(*SupportIssueDetails){
		"schema 0":                    func(d *SupportIssueDetails) { d.Schema = 0 },
		"a description of 4001 runes": func(d *SupportIssueDetails) { d.Description = strings.Repeat("ж", 4001) },
		"33 providers":                func(d *SupportIssueDetails) { d.Providers = make([]SupportIssueProvider, 33) },
		"65 findings":                 func(d *SupportIssueDetails) { d.Findings = make([]SupportIssueFinding, 65) },
		"33 parts skipped":            func(d *SupportIssueDetails) { d.Skipped = make([]string, 33) },
		"31 errors of the flow":       func(d *SupportIssueDetails) { d.Flow.Errors = make([]SupportIssueFlowError, 31) },
		"11 functions of the flow":    func(d *SupportIssueDetails) { d.Flow.Toolcalls.ByFunction = make([]SupportIssueFunction, 11) },
		"11 models of the flow":       func(d *SupportIssueDetails) { d.Flow.UsageByModel = make([]SupportIssueModelUsage, 11) },
		"a product of no version":     func(d *SupportIssueDetails) { d.Product.Version = "" },
		"a product of a branch":       func(d *SupportIssueDetails) { d.Product.Version = "develop" },
	} {
		document := goldenSupportIssueDetailsValue()
		broken(&document)
		if document.Valid() == nil {
			t.Errorf("a document of %s passes", name)
		}
	}
}

// TestTheLimitsOfAnIssueAreTheServers pins the limits of an issue as literals, as the
// server does: the two sides share no code, and a limit changed on one side only would
// have a sender believe a body is allowed that the server refuses with an error of its
// own. error_details is checked in the form a sender passes it, bytes already written.
func TestTheLimitsOfAnIssueAreTheServers(t *testing.T) {
	for name, limit := range map[string]struct{ got, want int }{
		"MaxSupportIssueRequestBytes": {MaxSupportIssueRequestBytes, 2097152},
		"MaxSupportIssueLogLines":     {MaxSupportIssueLogLines, 2000},
		"MaxSupportIssueDetailsBytes": {MaxSupportIssueDetailsBytes, 262144},
	} {
		if limit.got != limit.want {
			t.Errorf("%s is %d, the server says %d", name, limit.got, limit.want)
		}
	}

	request := func(lines [2]int, details json.RawMessage) SupportIssueRequest {
		logs := make([]SupportLogs, 0, len(lines))
		for _, count := range lines {
			component := SupportLogs{Component: ComponentTypePentagi}
			for range count {
				component.Logs = append(component.Logs, `time=2026-10-16T10:00:00Z level=error msg="call failed"`)
			}
			logs = append(logs, component)
		}
		return SupportIssueRequest{
			Component: ComponentTypePentagi, Version: "1.2.0", OS: OSTypeLinux, Arch: ArchTypeAMD64,
			Logs: logs, ErrorDetails: details,
		}
	}
	small := json.RawMessage(`{"schema":1}`)
	// {"d":"…"} is eight bytes around its text; < is one byte on the wire and six in the
	// form json.Marshal writes, so a measure that escaped HTML would refuse this document
	html := func(size int) json.RawMessage {
		return json.RawMessage(`{"d":"` + strings.Repeat("<", size-8) + `"}`)
	}

	for name, issue := range map[string]SupportIssueRequest{
		"2000 lines over two components":           request([2]int{1000, 1000}, small),
		"error_details of exactly the limit, HTML": request([2]int{1, 0}, html(MaxSupportIssueDetailsBytes)),
	} {
		if err := issue.Valid(); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
	for name, issue := range map[string]SupportIssueRequest{
		// neither component is past the limit: only their sum is
		"2001 lines over two components":      request([2]int{1000, 1001}, small),
		"error_details a byte past the limit": request([2]int{1, 0}, html(MaxSupportIssueDetailsBytes+1)),
		"error_details that is not JSON":      request([2]int{1, 0}, json.RawMessage(`{"schema":`)),
	} {
		if issue.Valid() == nil {
			t.Errorf("%s passes", name)
		}
	}
}
