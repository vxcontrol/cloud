package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
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
// The server pins the same list (pkg/server/models/public_contract_test.go); if
// you change one, change the other. The rejected column matters as much as the
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
