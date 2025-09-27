package anonymizer

import (
	"fmt"
	"math/rand"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
	"github.com/vxcontrol/cloud/anonymizer/testdata"
)

const testMemoryLimit = 2 * 1024 * 1024 * 1024 // 2GB

func limitMemory() {
	debug.SetMemoryLimit(testMemoryLimit)
	runtime.GC()
}

func TestNewReplacer_ValidPatterns(t *testing.T) {
	patterns := []string{
		`password=([^\s]+)`,
		`\b[a-f0-9]{32}\b`,
		`--token\s+([a-zA-Z0-9]+)\b`,
	}
	names := []string{
		"password",
		"hash",
		"token",
	}

	replacer, err := NewReplacer(patterns, names)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if replacer == nil {
		t.Fatal("Expected replacer to be created")
	}
}

func TestNewReplacer_InvalidPatterns(t *testing.T) {
	patterns := []string{
		`[invalid regex`,
		`(unclosed group`,
		`*invalid quantifier`,
	}

	_, err := NewReplacer(patterns, make([]string, len(patterns)))
	if err == nil {
		t.Fatal("Expected error for invalid patterns")
	}
}

func TestNewReplacer_EmptyPatterns(t *testing.T) {
	replacer, err := NewReplacer([]string{}, []string{})
	if err != nil {
		t.Fatalf("Expected no error for empty patterns, got: %v", err)
	}
	if replacer == nil {
		t.Fatal("Expected replacer to be created")
	}
	result := replacer.ReplaceString("test")
	if result != "test" {
		t.Errorf("Expected test, got: %s", result)
	}
}

func TestReplace_WithCaptureGroups(t *testing.T) {
	patterns := []string{`password=([^\s]+)`}
	replacer, err := NewReplacer(patterns, []string{"PASSWORD"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "mysql -u user password=secret123 -h localhost",
			expected: "mysql -u user password=§*PASSWORD*§ -h localhost",
		},
		{
			input:    "mysql -u user password=toolongsecret123 -h localhost",
			expected: "mysql -u user password=§***PASSWORD***§ -h localhost",
		},
		{
			input:    "mysql -u user password=toolongsecret1234 -h localhost",
			expected: "mysql -u user password=§***PASSWORD****§ -h localhost",
		},
	}

	for _, test := range tests {
		result := replacer.ReplaceString(test.input)
		if result != test.expected {
			t.Errorf("Expected: %s, got: %s", test.expected, result)
		}
	}
}

func TestReplace_WithCaptureGroupReplacement(t *testing.T) {
	patterns := []string{`test([0-9]+)`}
	replacer, err := NewReplacer(patterns, []string{"TEST"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	input := "prefix test123 suffix"
	result := replacer.ReplaceString(input)
	expected := "prefix test§*TEST*§ suffix"

	if result != expected {
		t.Errorf("Expected: %s, got: %s", expected, result)
	}
}

func TestReplace_WithoutCaptureGroups(t *testing.T) {
	patterns := []string{`test\d+`}
	replacer, err := NewReplacer(patterns, []string{"TEST"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	input := "prefix test123 suffix"
	result := replacer.ReplaceString(input)
	expected := "prefix §*TEST*§ suffix"

	if result != expected {
		t.Errorf("Expected: %s, got: %s", expected, result)
	}
}

func TestReplace_WithNamedGroups(t *testing.T) {
	patterns := []string{`password=(?P<replace>[^\s]+)`}
	replacer, err := NewReplacer(patterns, []string{"PASSWORD"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	input := "config password=mysecret123456 end"
	result := replacer.ReplaceString(input)
	expected := "config password=§**PASSWORD**§ end"

	if result != expected {
		t.Errorf("Expected: %s, got: %s", expected, result)
	}
}

func TestReplace_MultipleMatches(t *testing.T) {
	patterns := []string{
		`password=([^\s]+)`,
		`--token\s+([a-zA-Z0-9]+)\b`,
	}
	replacer, err := NewReplacer(patterns, []string{"PASSWORD", "TOKEN"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	input := "password=secret123 --token mytoken4567"
	result := replacer.ReplaceString(input)

	// check that both secrets are masked
	if !strings.Contains(result, "§*PASSWORD*§") {
		t.Errorf("Expected password to be masked, got: %s", result)
	}
	if !strings.Contains(result, "§**TOKEN**§") {
		t.Errorf("Expected token to be masked, got: %s", result)
	}
	if !strings.Contains(result, "password=") || !strings.Contains(result, "--token ") {
		t.Errorf("Expected structure to remain, got: %s", result)
	}
}

func TestReplace_NoMatches(t *testing.T) {
	patterns := []string{`password=([^\s]+)`}
	replacer, err := NewReplacer(patterns, []string{"PASSWORD"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	input := "this string has no sensitive data"
	result := replacer.ReplaceString(input)

	if result != input {
		t.Errorf("Expected unchanged string, got: %s", result)
	}
}

func TestReplace_EmptyString(t *testing.T) {
	patterns := []string{`password=([^\s]+)`}
	replacer, err := NewReplacer(patterns, []string{"PASSWORD"})
	if err != nil {
		t.Fatalf("Failed to create replacer: %v", err)
	}

	result := replacer.ReplaceString("")
	if result != "" {
		t.Errorf("Expected empty string, got: %s", result)
	}
}

func TestReplace_WithInsensitiveDatasets(t *testing.T) {
	insensitiveDataset, err := testdata.LoadInsensitiveData()
	if err != nil {
		t.Fatalf("failed to load insensitive data: %v", err)
	}

	allPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load all patterns: %v", err)
	}

	replacer, err := NewReplacer(allPatterns.Regexes(), allPatterns.Names())
	if err != nil {
		t.Fatalf("failed to create replacer: %v", err)
	}

	// we'll use a simple test to check if any masking occurs
	for _, entry := range insensitiveDataset.Entries {
		t.Run(entry.Name, func(t *testing.T) {
			originalText := entry.Examples
			replacedText := replacer.ReplaceString(originalText)

			if originalText != replacedText {
				t.Logf("original text:\n%s", originalText)
				t.Logf("replaced text:\n%s", replacedText)
				t.Errorf("unexpected replacement for %s", entry.Name)
			}
		})
	}
}

func TestReplace_WithTestDatasets(t *testing.T) {
	datasets, err := testdata.LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	allLoadedPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load all patterns: %v", err)
	}

	// combine patterns
	allPatterns := allLoadedPatterns.Patterns
	patternMap := make(map[string]string)
	for _, p := range allPatterns {
		patternMap[p.Name] = p.Regex
	}

	// test each dataset
	for _, dataset := range datasets {
		t.Run(dataset.Category, func(t *testing.T) {
			for _, entry := range dataset.Entries {
				t.Run(entry.Name, func(t *testing.T) {
					regex, exists := patternMap[entry.Name]
					if !exists {
						t.Skipf("pattern %s not found in loaded patterns", entry.Name)
						return
					}

					// create replacer with single pattern
					replacer, err := NewReplacer([]string{regex}, []string{entry.Name})
					if err != nil {
						// skip regexes that can't be compiled (lookbehind/lookahead)
						if strings.Contains(err.Error(), "invalid perl operator") {
							t.Skipf("skipping regex with unsupported features: %s", entry.Name)
							return
						}
						t.Fatalf("failed to create replacer for %s: %v", entry.Name, err)
					}

					result := replacer.ReplaceString(entry.Examples)

					for line := range strings.Lines(result) {
						// check that masking occurred (should contain §*NAME*§)
						foundLeftPadding := strings.Contains(line, "§*")
						foundRightPadding := strings.Contains(line, "*§")
						foundRegexName := strings.Contains(line, entry.Name)
						if !foundLeftPadding || !foundRightPadding || !foundRegexName {
							// some patterns may not match due to strict conditions, log but don't fail
							t.Errorf("no masking occurred for '%s' in line: %s", entry.Name, line)
						}
					}
				})
			}
		})
	}
}

func TestReplace_WithMixedDatasets(t *testing.T) {
	datasets, err := testdata.LoadAllTestData()
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	insensitiveDataset, err := testdata.LoadInsensitiveData()
	if err != nil {
		t.Fatalf("failed to load insensitive data: %v", err)
	}

	allLoadedPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		t.Fatalf("failed to load all patterns: %v", err)
	}

	replacer, err := NewReplacer(allLoadedPatterns.Regexes(), allLoadedPatterns.Names())
	if err != nil {
		t.Fatalf("failed to create replacer: %v", err)
	}

	rng := rand.New(rand.NewSource(1234567))
	getWrappedDataset := func() (string, string) {
		prefixIdx := rng.Intn(len(insensitiveDataset.Entries))
		suffixIdx := rng.Intn(len(insensitiveDataset.Entries))
		prefix := insensitiveDataset.Entries[prefixIdx].Examples
		suffix := insensitiveDataset.Entries[suffixIdx].Examples
		prefixLines := strings.Split(prefix, "\n")
		suffixLines := strings.Split(suffix, "\n")
		prefixLineIdx := rng.Intn(len(prefixLines))
		suffixLineIdx := rng.Intn(len(suffixLines))
		prefix = prefixLines[prefixLineIdx]
		suffix = suffixLines[suffixLineIdx]
		return prefix, suffix
	}

	// test each dataset
	for _, dataset := range datasets {
		t.Run(dataset.Category, func(t *testing.T) {
			for _, entry := range dataset.Entries {
				t.Run(entry.Name, func(t *testing.T) {
					prefix, suffix := getWrappedDataset()
					sample := fmt.Sprintf("%s %s %s", prefix, entry.Examples, suffix)

					// test masking on examples
					result := replacer.ReplaceString(sample)

					if !strings.Contains(result, prefix) || !strings.Contains(result, suffix) {
						t.Errorf("insensitive dataset was masked: %s", result)
					}

					if strings.Contains(result, entry.Examples) {
						t.Errorf("sensitive dataset was not masked: %s", entry.Examples)
					}

					for line := range strings.Lines(entry.Examples) {
						if strings.Contains(result, line) {
							t.Errorf("sensitive dataset (line: %s) was not masked", line)
						}
					}
				})
			}
		})
	}
}
