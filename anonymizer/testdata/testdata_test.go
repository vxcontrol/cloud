package testdata

import (
	"strings"
	"testing"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
)

func TestLoadAllTestData(t *testing.T) {
	datasets, err := LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	if len(datasets) == 0 {
		t.Fatal("no datasets loaded")
	}

	expectedCategories := []string{
		"credentials", "financial", "network", "personal",
		"crypto", "cloud", "services", "paths", "config",
	}

	if len(datasets) != len(expectedCategories) {
		t.Errorf("expected %d categories, got %d", len(expectedCategories), len(datasets))
	}

	totalEntries := 0
	totalExamples := 0

	for _, dataset := range datasets {
		if dataset.Category == "" {
			t.Error("dataset category should not be empty")
		}

		if len(dataset.Entries) == 0 {
			t.Errorf("dataset %s should have entries", dataset.Category)
		}

		for _, entry := range dataset.Entries {
			if entry.Name == "" {
				t.Errorf("entry name should not be empty in category %s", dataset.Category)
			}
			if entry.Examples == "" {
				t.Errorf("entry %s should have examples", entry.Name)
			}
			exampleLines := strings.Split(entry.Examples, "\n")
			totalExamples += len(exampleLines)
		}

		totalEntries += len(dataset.Entries)
	}

	t.Logf("loaded %d datasets with %d entries and %d examples",
		len(datasets), totalEntries, totalExamples)
}

func TestIndividualDatasetLoaders(t *testing.T) {
	loaders := map[string]func() (*TestDataset, error){
		"credentials": LoadCredentialsData,
		"financial":   LoadFinancialData,
		"network":     LoadNetworkData,
		"personal":    LoadPersonalData,
		"crypto":      LoadCryptoData,
		"cloud":       LoadCloudData,
		"services":    LoadServicesData,
		"paths":       LoadPathsData,
		"config":      LoadConfigData,
		"insensitive": LoadInsensitiveData,
	}

	for name, loader := range loaders {
		t.Run(name, func(t *testing.T) {
			dataset, err := loader()
			if err != nil {
				t.Fatalf("failed to load %s data: %v", name, err)
			}

			if dataset.Category != name {
				t.Errorf("expected category %s, got %s", name, dataset.Category)
			}

			if len(dataset.Entries) == 0 {
				t.Errorf("%s dataset should have entries", name)
			}
		})
	}
}

func TestDatasetDuplicates(t *testing.T) {
	datasets, err := LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	testPatterns := make(map[string]struct{})
	for _, dataset := range datasets {
		for _, entry := range dataset.Entries {
			if _, ok := testPatterns[entry.Name]; ok {
				t.Errorf("duplicate pattern %s in %s", entry.Name, dataset.Category)
			}
			testPatterns[entry.Name] = struct{}{}
		}
	}
}

func TestPatternCoverage(t *testing.T) {
	datasets, err := LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	testPatterns := make(map[string]struct{})
	for _, dataset := range datasets {
		for _, entry := range dataset.Entries {
			testPatterns[entry.Name] = struct{}{}
		}
	}

	allPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load all patterns: %v", err)
	}
	allPatternNames := make(map[string]struct{})
	for _, pattern := range allPatterns.Patterns {
		allPatternNames[pattern.Name] = struct{}{}
	}

	var uncoveredPatterns []string

	for _, pattern := range allPatterns.Patterns {
		if _, ok := testPatterns[pattern.Name]; !ok {
			uncoveredPatterns = append(uncoveredPatterns, "general: "+pattern.Name)
		}
	}

	if len(uncoveredPatterns) > 0 {
		t.Errorf("uncovered patterns found (%d):", len(uncoveredPatterns))
		for _, pattern := range uncoveredPatterns {
			t.Logf("  - %s", pattern)
		}
		t.Error("please add test data for uncovered patterns")
	} else {
		t.Log("100% required patterns covered")
	}

	totalPatterns := len(allPatterns.Patterns)
	coveredPatterns := len(testPatterns)
	coveragePercent := float64(coveredPatterns) / float64(totalPatterns) * 100

	t.Logf("pattern coverage: %d/%d (%.1f%%)",
		coveredPatterns, totalPatterns, coveragePercent)

	if coveragePercent != 100.0 {
		t.Errorf("pattern coverage too low: %.1f%% (expected 100%%)", coveragePercent)
	}

	for _, dataset := range datasets {
		for _, entry := range dataset.Entries {
			if _, ok := allPatternNames[entry.Name]; !ok {
				t.Errorf("pattern '%s' in %s is not covered", entry.Name, dataset.Category)
			}
		}
	}
}

func TestDataFormat(t *testing.T) {
	datasets, err := LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	for _, dataset := range datasets {
		// check that raw content exists
		if dataset.Raw == "" {
			t.Errorf("dataset %s should have raw content", dataset.Category)
		}

		for _, entry := range dataset.Entries {
			if entry.Examples == "" {
				t.Errorf("entry %s in %s has no examples", entry.Name, dataset.Category)
				continue
			}

			// check that examples are not empty when split by lines
			exampleLines := strings.Split(entry.Examples, "\n")
			for i, example := range exampleLines {
				if strings.TrimSpace(example) == "" {
					t.Errorf("empty example at line %d for %s in %s",
						i, entry.Name, dataset.Category)
				}
			}
		}
	}
}
