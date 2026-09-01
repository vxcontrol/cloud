package models

import (
	"strings"
	"testing"
)

// TestEveryComponentHasAnArtifactKind is the guard that makes the fallback in
// ComponentType.ArtifactKind unreachable for a real component.
//
// Without it, adding a file component and forgetting the table would compile,
// pass every other test, and silently make that component be reported as an
// image — which is the exact failure the table was introduced to remove.
func TestEveryComponentHasAnArtifactKind(t *testing.T) {
	for _, ct := range AllComponentTypes {
		kind, ok := componentArtifactKinds[ct]
		if !ok {
			t.Errorf("%s has no artefact kind; it would silently be treated as an image", ct)
			continue
		}
		if err := kind.Valid(); err != nil {
			t.Errorf("%s is mapped to an invalid kind: %v", ct, err)
		}
	}
	for ct := range componentArtifactKinds {
		if err := ct.Valid(); err != nil {
			t.Errorf("the table maps %q, which is not in the vocabulary", ct)
		}
	}
	if len(componentArtifactKinds) != len(AllComponentTypes) {
		t.Errorf("the table has %d entries, the vocabulary has %d",
			len(componentArtifactKinds), len(AllComponentTypes))
	}
}

// TestTheFileVocabularyIsExactlyTheDeliveredFiles pins which components have a
// published file — the file-only ones plus FileImage — as a literal on both
// sides of the contract.
func TestTheFileVocabularyIsExactlyTheDeliveredFiles(t *testing.T) {
	want := []ComponentType{
		ComponentTypeInstaller,
		ComponentTypeEngine,
		ComponentTypeJaegerClickhouse,
		ComponentTypeEngineRegistry,
		ComponentTypeEngineScenario,
		ComponentTypePentagi,
	}
	got := map[ComponentType]bool{}
	for _, ct := range FileComponentTypes {
		got[ct] = true
	}
	for _, ct := range want {
		if !got[ct] {
			t.Errorf("%s should be delivered as a file", ct)
		}
		delete(got, ct)
	}
	for ct := range got {
		t.Errorf("%s is delivered as a file but is not in the pinned list", ct)
	}
	// FileImage sits in both lists, so the two lengths sum to more than the
	// vocabulary. Every component must still appear in at least one.
	seen := map[ComponentType]struct{}{}
	for _, ct := range FileComponentTypes {
		seen[ct] = struct{}{}
	}
	for _, ct := range ImageComponentTypes {
		seen[ct] = struct{}{}
	}
	if len(seen) != len(AllComponentTypes) {
		t.Errorf("the two kinds cover %d components, the vocabulary has %d",
			len(seen), len(AllComponentTypes))
	}
}

// TestOnlyAFileHasAPackage exercises the `filecomp` tag over the WHOLE
// vocabulary — the shape that catches an omission rather than one that confirms
// the members already present.
//
// The list this replaced named two of the five file-only components, so an SDK
// asking for jaeger-clickhouse, engine-registry or engine-scenario refused
// locally before the request was ever sent. Asking only the image/file delivery
// question then cost one more: pentagi is FileImage, and treating that as "not
// a file" refused the executable a running product replaces itself with.
//
// BOTH package requests are swept. Gating one and not the other is a real state
// this test exists to forbid: the SDK would send a metadata request the service
// refuses, while refusing the download of that same artefact itself.
func TestOnlyAFileHasAPackage(t *testing.T) {
	for _, ct := range AllComponentTypes {
		requests := map[string]IValid{
			"download": DownloadPackageRequest{
				Component: ct,
				Version:   "1.0.0",
				OS:        OSTypeLinux,
				Arch:      ArchTypeAMD64,
			},
			"info": PackageInfoRequest{
				Component: ct,
				Version:   "1.0.0",
				OS:        OSTypeLinux,
				Arch:      ArchTypeAMD64,
			},
		}
		for name, request := range requests {
			err := request.Valid()
			if ct.IsFileComponent() && err != nil {
				t.Errorf("%s has a published file but %s rejects it: %v", ct, name, err)
			}
			if !ct.IsFileComponent() && err == nil {
				t.Errorf("%s has no package, but %s accepted it", ct, name)
			}
		}
	}
}

// TestPentagiIsFileImage pins the one component that is both an image an
// installer pulls and a file a running product downloads.
//
// It must stay in BOTH update-check lists: under `images` the service resolves
// it against its registry reference, under `files` against the published
// executable. Moving it to ArtifactKindFile takes it out of every installer's
// image list; leaving it as ArtifactKindImage refuses the file half. FileImage
// is both answers in the table, not a kind plus a side set.
func TestPentagiIsFileImage(t *testing.T) {
	if got := ComponentTypePentagi.ArtifactKind(); got != ArtifactKindFileImage {
		t.Errorf("pentagi must be file-image, got %s", got)
	}
	if !ComponentTypePentagi.IsImageComponent() {
		t.Error("pentagi must stay an image: an update check resolves it as one")
	}
	if !ComponentTypePentagi.IsFileComponent() {
		t.Error("pentagi ships an executable a running product can replace itself with")
	}

	base := CheckUpdatesRequest{
		InstallerVersion: "1.0.0",
		InstallerOS:      OSTypeLinux,
		InstallerArch:    ArchTypeAMD64,
		Strategy:         UpdateStrategyPreview,
	}
	asFile := base
	asFile.Files = []FileComponentInfo{{
		Component: ComponentTypePentagi,
		Status:    ComponentStatusRunning,
		OS:        OSTypeLinux,
		Arch:      ArchTypeAMD64,
	}}
	if err := asFile.Valid(); err != nil {
		t.Errorf("pentagi reported under `files` must validate: %v", err)
	}
	asImage := base
	asImage.Images = []ImageComponentInfo{{
		Component:  ComponentTypePentagi,
		Status:     ComponentStatusRunning,
		OS:         OSTypeLinux,
		Arch:       ArchTypeAMD64,
		Repository: "vxcontrol/pentagi",
		Tag:        "latest",
	}}
	if err := asImage.Valid(); err != nil {
		t.Errorf("pentagi reported under `images` must validate: %v", err)
	}
	both := base
	both.Images = asImage.Images
	both.Files = asFile.Files
	if err := both.Valid(); err != nil {
		t.Errorf("pentagi reported under both lists must validate: %v", err)
	}
}

// TestAComponentReportedUnderTheWrongKindIsRejected closes the hole that
// splitting the request lists left open.
//
// The asymmetry is the point. A FILE sent under `images` is caught by the
// per-element rules — ImageComponentInfo requires a repository, which a file has
// no way to supply. An IMAGE sent under `files` is not: FileComponentInfo has no
// repository field to leave empty, so every field-level rule is satisfied and
// the artefact is resolved against the wrong kind of thing entirely.
func TestAComponentReportedUnderTheWrongKindIsRejected(t *testing.T) {
	base := func() CheckUpdatesRequest {
		return CheckUpdatesRequest{
			InstallerVersion: "1.0.0",
			InstallerOS:      OSTypeLinux,
			InstallerArch:    ArchTypeAMD64,
			Strategy:         UpdateStrategyStable,
		}
	}
	version := "1.0.0"

	t.Run("an image reported under files", func(t *testing.T) {
		request := base()
		request.Files = []FileComponentInfo{{
			Component: ComponentTypeScraper,
			Status:    ComponentStatusRunning,
			OS:        OSTypeLinux,
			Arch:      ArchTypeAMD64,
			Version:   &version,
		}}
		err := request.Valid()
		if err == nil {
			t.Fatal("scraper is an image; reporting it as a file must not validate")
		}
		if !strings.Contains(err.Error(), "scraper") {
			t.Errorf("the error does not name the component: %v", err)
		}
	})

	t.Run("a file reported under images", func(t *testing.T) {
		request := base()
		request.Images = []ImageComponentInfo{{
			Component:  ComponentTypeInstaller,
			Status:     ComponentStatusRunning,
			OS:         OSTypeLinux,
			Arch:       ArchTypeAMD64,
			Repository: "vxcontrol/pentagi",
			Tag:        "latest",
		}}
		if err := request.Valid(); err == nil {
			t.Fatal("the installer is a file; reporting it as an image must not validate")
		}
	})

	t.Run("each in its own list", func(t *testing.T) {
		request := base()
		request.Images = []ImageComponentInfo{{
			Component:  ComponentTypePentagi,
			Status:     ComponentStatusRunning,
			OS:         OSTypeLinux,
			Arch:       ArchTypeAMD64,
			Repository: "vxcontrol/pentagi",
			Tag:        "latest",
		}}
		request.Files = []FileComponentInfo{{
			Component: ComponentTypeInstaller,
			Status:    ComponentStatusRunning,
			OS:        OSTypeLinux,
			Arch:      ArchTypeAMD64,
			Version:   &version,
		}}
		if err := request.Valid(); err != nil {
			t.Fatalf("a correctly reported pair must validate: %v", err)
		}
	})
}
