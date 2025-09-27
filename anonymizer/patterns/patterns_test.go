package patterns

import (
	"testing"

	"github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"
	"gopkg.in/yaml.v3"
)

func TestLoadPatternsGeneral(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeGeneral)
	if err != nil {
		t.Fatalf("failed to load general patterns: %v", err)
	}

	if patterns == nil {
		t.Fatal("patterns should not be nil")
	}

	if len(patterns.Patterns) == 0 {
		t.Fatal("general patterns should not be empty")
	}

	t.Logf("loaded %d general patterns", len(patterns.Patterns))
}

func TestLoadPatternsPii(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypePii)
	if err != nil {
		t.Fatalf("failed to load pii patterns: %v", err)
	}

	if patterns == nil {
		t.Fatal("patterns should not be nil")
	}

	if len(patterns.Patterns) == 0 {
		t.Fatal("pii patterns should not be empty")
	}

	t.Logf("loaded %d pii patterns", len(patterns.Patterns))
}

func TestLoadPatternsSecrets(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeSecrets)
	if err != nil {
		t.Fatalf("failed to load secrets patterns: %v", err)
	}

	if patterns == nil {
		t.Fatal("patterns should not be nil")
	}

	if len(patterns.Patterns) == 0 {
		t.Fatal("secrets patterns should not be empty")
	}

	t.Logf("loaded %d secrets patterns", len(patterns.Patterns))
}

func TestLoadPatternsAll(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load all patterns: %v", err)
	}

	if patterns == nil {
		t.Fatal("patterns should not be nil")
	}

	if len(patterns.Patterns) == 0 {
		t.Fatal("all patterns should not be empty")
	}

	t.Logf("loaded %d total patterns", len(patterns.Patterns))
}

func TestPatternsMethods(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeGeneral)
	if err != nil {
		t.Fatalf("failed to load patterns: %v", err)
	}

	namesList := patterns.Names()
	regexList := patterns.Regexes()

	if len(namesList) != len(patterns.Patterns) {
		t.Errorf("expected %d names, got %d", len(patterns.Patterns), len(namesList))
	}

	if len(regexList) != len(patterns.Patterns) {
		t.Errorf("expected %d regexes, got %d", len(patterns.Patterns), len(regexList))
	}

	for i, name := range namesList {
		if name == "" {
			t.Errorf("name at index %d is empty", i)
		}
	}

	for i, regex := range regexList {
		if regex == "" {
			t.Errorf("regex at index %d is empty", i)
		}
	}
}

func TestPatternsStructure(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeGeneral)
	if err != nil {
		t.Fatalf("failed to load patterns: %v", err)
	}

	for i, pattern := range patterns.Patterns {
		if pattern.Name == "" {
			t.Errorf("pattern at index %d has empty name", i)
		}
		if pattern.Regex == "" {
			t.Errorf("pattern at index %d has empty regex", i)
		}
	}
}

func TestPatternsDuplicate(t *testing.T) {
	patterns, err := LoadPatterns(PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load patterns: %v", err)
	}

	patternMap := make(map[string]struct{})
	for _, pattern := range patterns.Patterns {
		if _, ok := patternMap[pattern.Name]; ok {
			t.Errorf("duplicate pattern %s", pattern.Name)
		}
		patternMap[pattern.Name] = struct{}{}
	}
}

func TestRawPatternsStructure(t *testing.T) {
	patternsRawData := [][]byte{
		GeneralPatterns,
		PiiPatterns,
		SecretsPatterns,
	}

	for _, patternData := range patternsRawData {
		var patterns map[string][]map[string]string
		if err := yaml.Unmarshal(patternData, &patterns); err != nil {
			t.Fatalf("failed to unmarshal patterns: %v", err)
		}
		if len(patterns) != 1 {
			t.Errorf("patterns has %d fields, expected 1", len(patterns))
		}
		if len(patterns["patterns"]) == 0 {
			t.Errorf("patterns has no patterns")
		}
		for _, pattern := range patterns["patterns"] {
			if len(pattern) != 2 {
				t.Errorf("pattern has %d fields, expected 2", len(pattern))
			}
			if pattern["name"] == "" {
				t.Errorf("pattern has empty name")
			}
			if pattern["regex"] == "" {
				t.Errorf("pattern has empty regex")
			}
		}
	}
}

func TestPatternCompilation(t *testing.T) {
	patternTypes := []struct {
		name  string
		ptype PatternListType
	}{
		{"general", PatternListTypeGeneral},
		{"pii", PatternListTypePii},
		{"secrets", PatternListTypeSecrets},
	}

	for _, pt := range patternTypes {
		t.Run(pt.name, func(t *testing.T) {
			patterns, err := LoadPatterns(pt.ptype)
			if err != nil {
				t.Fatalf("failed to load %s patterns: %v", pt.name, err)
			}

			namesList := patterns.Names()
			regexList := patterns.Regexes()

			for i, regex := range regexList {
				if regex == "" {
					t.Errorf("empty regex at index %d", i)
					continue
				}

				if _, err := re2.Compile(regex); err != nil {
					t.Errorf("failed to compile regex at index %d with name '%s': %s - error: %v",
						i, namesList[i], regex, err)
				}
			}

			if _, err := experimental.CompileSet(regexList); err != nil {
				t.Errorf("failed to compile regex set: %v", err)
			}

			t.Logf("successfully compiled %d %s regexes", len(regexList), pt.name)
		})
	}
}
