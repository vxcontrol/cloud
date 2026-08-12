package models

import "testing"

// The component vocabulary, pinned as a literal.
//
// It is a COPY of the same list in the other repository, duplicated for the same
// reason the golden wire forms are: the update service and the public SDK are
// separate modules, a shared import would tie every service build to a
// published SDK version, and
// pinning the values on both sides catches drift just as well.
//
// Until now nothing related the two lists at all — they were two independent
// hand-written copies of the same vocabulary, and a component added to one was
// simply absent from the other. Absent quietly: the SDK's GetProductStack()
// answers `pentagi` for anything it does not know, so a client correlating its
// components against the update answer would put an observability component in
// the wrong stack and see nothing wrong.
//
// If you change one list, change the other.
var goldenComponentVocabulary = []string{
	"pentagi",
	"scraper",
	"langfuse-worker",
	"langfuse-web",
	"grafana",
	"otel",
	"worker",
	"installer",
	"engine",
	"minio",
	"redis",
	"postgres",
	"pgvector",
	"jaeger-clickhouse",
	"graphiti",
	"neo4j",
	"victoriametrics",
	"clickhouse",
	"loki",
	"jaeger",
	"browseruse",
	"engine-registry",
	"engine-scenario",
	"pgexporter",
	"node-exporter",
	"cadvisor",
	"clickstore",
}

// The stack each component belongs to, pinned the same way. The vocabulary
// agreeing while the stacks disagree would be worse than an outright mismatch:
// both sides would name the same components and route them differently.
var goldenComponentStacks = map[string]string{
	"pentagi":           "pentagi",
	"scraper":           "pentagi",
	"pgvector":          "pentagi",
	"pgexporter":        "pentagi",
	"langfuse-worker":   "langfuse",
	"langfuse-web":      "langfuse",
	"postgres":          "langfuse",
	"clickhouse":        "langfuse",
	"redis":             "langfuse",
	"minio":             "langfuse",
	"grafana":           "observability",
	"otel":              "observability",
	"victoriametrics":   "observability",
	"loki":              "observability",
	"jaeger":            "observability",
	"jaeger-clickhouse": "observability",
	"clickstore":        "observability",
	"node-exporter":     "observability",
	"cadvisor":          "observability",
	"worker":            "worker",
	"installer":         "installer",
	"engine":            "engine",
	"engine-registry":   "engine",
	"engine-scenario":   "engine",
	"graphiti":          "graphiti",
	"neo4j":             "graphiti",
	"browseruse":        "browser",
}

// goldenComponentKinds is how each component is delivered, pinned as a literal
// on both sides for the same reason the vocabulary is.
//
// Kind is not derivable from the name or the stack — jaeger-clickhouse is a
// FILE while clickstore, the ClickHouse server behind it, is an image — so a
// table that drifts between the two sides is a client reporting an artefact in
// a list the service will reject, or worse, in one it will answer wrongly.
var goldenComponentKinds = map[string]string{
	"pentagi":           "image",
	"scraper":           "image",
	"langfuse-worker":   "image",
	"langfuse-web":      "image",
	"grafana":           "image",
	"otel":              "image",
	"worker":            "image",
	"installer":         "file",
	"engine":            "file",
	"minio":             "image",
	"redis":             "image",
	"postgres":          "image",
	"pgvector":          "image",
	"jaeger-clickhouse": "file",
	"graphiti":          "image",
	"neo4j":             "image",
	"victoriametrics":   "image",
	"clickhouse":        "image",
	"loki":              "image",
	"jaeger":            "image",
	"browseruse":        "image",
	"engine-registry":   "file",
	"engine-scenario":   "file",
	"pgexporter":        "image",
	"node-exporter":     "image",
	"cadvisor":          "image",
	"clickstore":        "image",
}

func TestComponentKindsMatchTheOtherSide(t *testing.T) {
	for _, name := range goldenComponentVocabulary {
		want, pinned := goldenComponentKinds[name]
		if !pinned {
			t.Errorf("%s has no pinned artefact kind", name)
			continue
		}
		if got := ComponentType(name).ArtifactKind(); string(got) != want {
			t.Errorf("%s is delivered as %q here and %q in the pinned list", name, got, want)
		}
	}
	if len(goldenComponentKinds) != len(goldenComponentVocabulary) {
		t.Errorf("the pinned kinds cover %d components, the pinned vocabulary has %d",
			len(goldenComponentKinds), len(goldenComponentVocabulary))
	}
}

func TestComponentVocabularyMatchesTheOtherSide(t *testing.T) {
	got := make([]string, 0, len(AllComponentTypes))
	for _, ct := range AllComponentTypes {
		got = append(got, string(ct))
	}

	if len(got) != len(goldenComponentVocabulary) {
		t.Errorf("this side has %d components, the pinned list has %d",
			len(got), len(goldenComponentVocabulary))
	}
	// Order matters as well as membership: it is the order of the PostgreSQL
	// enum and the ClickHouse Enum8, and a reader comparing the three by eye
	// depends on it.
	for i := range min(len(got), len(goldenComponentVocabulary)) {
		if got[i] != goldenComponentVocabulary[i] {
			t.Errorf("component %d is %q here and %q in the pinned list", i, got[i], goldenComponentVocabulary[i])
		}
	}

	for _, name := range goldenComponentVocabulary {
		stack, ok := ComponentToStackMapping[ComponentType(name)]
		if !ok {
			t.Errorf("%s has no stack on this side", name)
			continue
		}
		if want := goldenComponentStacks[name]; string(stack) != want {
			t.Errorf("%s is in stack %q here and %q in the pinned list", name, stack, want)
		}
	}
	if len(ComponentToStackMapping) != len(goldenComponentStacks) {
		t.Errorf("this side maps %d components to stacks, the pinned list maps %d",
			len(ComponentToStackMapping), len(goldenComponentStacks))
	}
}
