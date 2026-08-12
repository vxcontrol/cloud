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

// TestTheFileVocabularyIsExactlyTheDeliveredFiles pins the split itself, as a
// literal, on both sides of the contract.
func TestTheFileVocabularyIsExactlyTheDeliveredFiles(t *testing.T) {
	want := []ComponentType{
		ComponentTypeInstaller,
		ComponentTypeEngine,
		ComponentTypeJaegerClickhouse,
		ComponentTypeEngineRegistry,
		ComponentTypeEngineScenario,
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
	if n := len(FileComponentTypes) + len(ImageComponentTypes); n != len(AllComponentTypes) {
		t.Errorf("the two kinds cover %d components, the vocabulary has %d", n, len(AllComponentTypes))
	}
}

// TestOnlyAFileHasAPackage exercises the `filecomp` tag over the WHOLE
// vocabulary — the shape that catches an omission rather than one that confirms
// the members already present.
//
// The list this replaced named two of the five, so an SDK asking for
// jaeger-clickhouse, engine-registry or engine-scenario refused locally before
// the request was ever sent.
//
// BOTH package requests are swept. Gating one and not the other is a real
// state this test exists to forbid: the SDK would send a metadata request the
// service refuses, while refusing the download of that same artefact itself.
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
			switch ct.ArtifactKind() {
			case ArtifactKindFile:
				if err != nil {
					t.Errorf("%s is delivered as a file but %s rejects it: %v", ct, name, err)
				}
			case ArtifactKindImage:
				if err == nil {
					t.Errorf("%s is an image and has no package, but %s accepted it", ct, name)
				}
			}
		}
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
			Component: ComponentTypePentagi,
			Status:    ComponentStatusRunning,
			OS:        OSTypeLinux,
			Arch:      ArchTypeAMD64,
			Version:   &version,
		}}
		err := request.Valid()
		if err == nil {
			t.Fatal("pentagi is an image; reporting it as a file must not validate")
		}
		if !strings.Contains(err.Error(), "pentagi") {
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
