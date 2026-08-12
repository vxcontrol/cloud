package models

import (
	"fmt"
	"strings"
)

// ArtifactKind is how a component reaches an installation: pulled from a
// registry, or downloaded as a file.
//
// It is a property of the COMPONENT — fixed by how it is built and shipped —
// and not of the request that mentions it. Deriving it from which fields a
// client happened to fill in is exactly what this type replaces: a repository
// and a tag are how an image is NAMED, not evidence that the artefact is an
// image, and a component the client knows about but has not installed fills
// neither.
type ArtifactKind string

const (
	// ArtifactKindImage is pulled from a registry and identified by a digest.
	ArtifactKindImage ArtifactKind = "image"

	// ArtifactKindFile is downloaded and identified by a version and a hash.
	// Files have no repository and no tag, so the whole tag-and-channel half of
	// update resolution is inapplicable to them.
	ArtifactKindFile ArtifactKind = "file"
)

func (ak ArtifactKind) String() string {
	return string(ak)
}

func (ak ArtifactKind) Valid() error {
	switch ak {
	case ArtifactKindImage, ArtifactKindFile:
		return nil
	default:
		return fmt.Errorf("invalid ArtifactKind: %s", ak)
	}
}

// componentArtifactKinds is THE table. Every component of AllComponentTypes has
// an entry here, and TestEveryComponentHasAnArtifactKind fails when one does
// not.
//
// The completeness test is the whole point. Letting a missing entry default to
// "image" would make a newly added FILE component be reported as an image,
// resolved against images, matched against nothing, and answered with silence —
// which is the failure mode this table exists to remove, reintroduced by
// omission.
var componentArtifactKinds = map[ComponentType]ArtifactKind{
	// Delivered as files. Four of them are built and signed by us; the fifth is
	// the Jaeger storage plugin, a binary mounted into the jaeger container
	// rather than an image of its own. The ClickHouse SERVER behind it is a
	// separate component (clickstore) and an image.
	ComponentTypeInstaller:        ArtifactKindFile,
	ComponentTypeEngine:           ArtifactKindFile,
	ComponentTypeEngineRegistry:   ArtifactKindFile,
	ComponentTypeEngineScenario:   ArtifactKindFile,
	ComponentTypeJaegerClickhouse: ArtifactKindFile,

	// Delivered as images: everything published to a registry, plus every
	// third-party service a stack starts from one.
	ComponentTypePentagi:         ArtifactKindImage,
	ComponentTypeScraper:         ArtifactKindImage,
	ComponentTypeWorker:          ArtifactKindImage,
	ComponentTypePgvector:        ArtifactKindImage,
	ComponentTypeGraphiti:        ArtifactKindImage,
	ComponentTypeBrowseruse:      ArtifactKindImage,
	ComponentTypeLangfuseWorker:  ArtifactKindImage,
	ComponentTypeLangfuseWeb:     ArtifactKindImage,
	ComponentTypePostgres:        ArtifactKindImage,
	ComponentTypeClickhouse:      ArtifactKindImage,
	ComponentTypeRedis:           ArtifactKindImage,
	ComponentTypeMinio:           ArtifactKindImage,
	ComponentTypeNeo4j:           ArtifactKindImage,
	ComponentTypeGrafana:         ArtifactKindImage,
	ComponentTypeOtel:            ArtifactKindImage,
	ComponentTypeVictoriametrics: ArtifactKindImage,
	ComponentTypeLoki:            ArtifactKindImage,
	ComponentTypeJaeger:          ArtifactKindImage,
	ComponentTypeClickstore:      ArtifactKindImage,
	ComponentTypePgexporter:      ArtifactKindImage,
	ComponentTypeNodeExporter:    ArtifactKindImage,
	ComponentTypeCadvisor:        ArtifactKindImage,
}

// ArtifactKind reports how this component is delivered.
//
// A component outside the vocabulary answers `image`. That answer is only
// reachable when the caller skipped ComponentType.Valid(), which every request
// path runs first; the table itself is complete by test.
func (ct ComponentType) ArtifactKind() ArtifactKind {
	if kind, ok := componentArtifactKinds[ct]; ok {
		return kind
	}
	return ArtifactKindImage
}

// IsFileComponent reports whether this component is delivered as a file.
func (ct ComponentType) IsFileComponent() bool {
	return ct.ArtifactKind() == ArtifactKindFile
}

// IsImageComponent reports whether this component is delivered as an image.
func (ct ComponentType) IsImageComponent() bool {
	return ct.ArtifactKind() == ArtifactKindImage
}

// FileComponentTypes and ImageComponentTypes are the vocabulary split by kind,
// in vocabulary order. Derived from the table rather than written twice, so
// there is no second list to forget.
var (
	FileComponentTypes  = componentsOfKind(ArtifactKindFile)
	ImageComponentTypes = componentsOfKind(ArtifactKindImage)
)

func componentsOfKind(kind ArtifactKind) []ComponentType {
	out := make([]ComponentType, 0, len(AllComponentTypes))
	for _, ct := range AllComponentTypes {
		if ct.ArtifactKind() == kind {
			out = append(out, ct)
		}
	}
	return out
}

// FileComponentEnum is the file vocabulary as a comma-separated list, the form
// documentation and hand-written enumerations have to match.
func FileComponentEnum() string {
	names := make([]string, 0, len(FileComponentTypes))
	for _, ct := range FileComponentTypes {
		names = append(names, ct.String())
	}
	return strings.Join(names, ",")
}
