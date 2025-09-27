package testdata

import (
	_ "embed"
	"math/rand"
	"regexp"
	"strings"
)

//go:embed dataset/credentials.txt
var credentialsData []byte

//go:embed dataset/financial.txt
var financialData []byte

//go:embed dataset/network.txt
var networkData []byte

//go:embed dataset/personal.txt
var personalData []byte

//go:embed dataset/crypto.txt
var cryptoData []byte

//go:embed dataset/cloud.txt
var cloudData []byte

//go:embed dataset/services.txt
var servicesData []byte

//go:embed dataset/paths.txt
var pathsData []byte

//go:embed dataset/config.txt
var configData []byte

//go:embed dataset/insensitive.txt
var insensitiveData []byte

type TestDataEntry struct {
	Name     string
	Examples string // multiline string with examples
}

type TestDataset struct {
	Category string
	Raw      string // entire file content
	Entries  []TestDataEntry
}

// parseTestDataFile parses test data in format: ===name=== followed by examples
func parseTestDataFile(data []byte, category string) (*TestDataset, error) {
	content := string(data)
	lines := strings.Split(content, "\n")

	dataset := &TestDataset{
		Category: category,
		Raw:      content,
	}
	var currentEntry *TestDataEntry
	var currentExamples []string

	namePattern := regexp.MustCompile(`^===(.+)===\s*$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if matches := namePattern.FindStringSubmatch(line); matches != nil {
			if currentEntry != nil {
				currentEntry.Examples = strings.Join(currentExamples, "\n")
				dataset.Entries = append(dataset.Entries, *currentEntry)
			}
			currentEntry = &TestDataEntry{
				Name: matches[1],
			}
			currentExamples = make([]string, 0)
		} else if line != "" && currentEntry != nil {
			currentExamples = append(currentExamples, line)
		}
	}

	if currentEntry != nil {
		currentEntry.Examples = strings.Join(currentExamples, "\n")
		dataset.Entries = append(dataset.Entries, *currentEntry)
	}

	return dataset, nil
}

func LoadCredentialsData() (*TestDataset, error) {
	return parseTestDataFile(credentialsData, "credentials")
}

func LoadFinancialData() (*TestDataset, error) {
	return parseTestDataFile(financialData, "financial")
}

func LoadNetworkData() (*TestDataset, error) {
	return parseTestDataFile(networkData, "network")
}

func LoadPersonalData() (*TestDataset, error) {
	return parseTestDataFile(personalData, "personal")
}

func LoadCryptoData() (*TestDataset, error) {
	return parseTestDataFile(cryptoData, "crypto")
}

func LoadCloudData() (*TestDataset, error) {
	return parseTestDataFile(cloudData, "cloud")
}

func LoadServicesData() (*TestDataset, error) {
	return parseTestDataFile(servicesData, "services")
}

func LoadPathsData() (*TestDataset, error) {
	return parseTestDataFile(pathsData, "paths")
}

func LoadConfigData() (*TestDataset, error) {
	return parseTestDataFile(configData, "config")
}

func LoadInsensitiveData() (*TestDataset, error) {
	return parseTestDataFile(insensitiveData, "insensitive")
}

func LoadAllTestData() ([]*TestDataset, error) {
	loaders := []func() (*TestDataset, error){
		LoadCredentialsData,
		LoadFinancialData,
		LoadNetworkData,
		LoadPersonalData,
		LoadCryptoData,
		LoadCloudData,
		LoadServicesData,
		LoadPathsData,
		LoadConfigData,
	}

	datasets := make([]*TestDataset, 0, len(loaders))
	for _, loader := range loaders {
		dataset, err := loader()
		if err != nil {
			return nil, err
		}
		datasets = append(datasets, dataset)
	}

	return datasets, nil
}

func GenerateRandomString(rng *rand.Rand, minLen, maxLen int) string {
	length := rng.Intn(maxLen-minLen+1) + minLen
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;':\",./<>?"

	var sb strings.Builder
	sb.Grow(length)
	for i := 0; i < length; i++ {
		sb.WriteByte(charset[rng.Intn(len(charset))])
	}
	return sb.String()
}

func GenerateTestStrings(seed int64, count, minLen, maxLen int) []string {
	rng := rand.New(rand.NewSource(seed))
	strings := make([]string, count)
	for i := 0; i < count; i++ {
		strings[i] = GenerateRandomString(rng, minLen, maxLen)
	}
	return strings
}

func GenerateRegexPatterns(seed int64, count int) ([]string, []string) {
	rng := rand.New(rand.NewSource(seed))

	patterns := []string{
		`\b[a-f0-9]{32}\b`,
		`\b[A-F0-9]{40}\b`,
		`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
		`password=([^\s]+)`,
		`-p\s+([^\s]+)`,
		`--token\s+([a-zA-Z0-9]+)\b`,
		`api[_-]?key[=:]\s*([a-zA-Z0-9]+)`,
		`secret[=:]\s*([^\s]+)`,
		`auth[=:]\s*([^\s]+)`,
		`token[=:]\s*([a-zA-Z0-9]+)`,
	}
	names := []string{
		"md5hash",
		"sha1hash",
		"jwt",
		"password",
		"cmd_passwd",
		"token",
		"api_key",
		"secret",
		"auth",
		"token",
	}

	basePatterns := make([]string, count)
	basePatternNames := make([]string, count)
	for i := 0; i < count; i++ {
		if i < len(patterns) {
			basePatterns[i] = patterns[i]
			basePatternNames[i] = names[i]
		} else {
			// Generate variations
			idx := rng.Intn(len(patterns))
			basePatterns[i] = patterns[idx]
			basePatternNames[i] = names[idx]
		}
	}

	return basePatterns, basePatternNames
}

func CreateTestData() map[string]string {
	return map[string]string{
		"password_command": "mysql -u user -p secretpass123 -h localhost",
		"api_key":          "api_key=abc123def456 config.json",
		"token_flag":       "--token mytoken123 --verbose",
		"email":            "user@example.com sent notification",
		"hash_md5":         "file hash: a1b2c3d4e5f6789012345678901234567890abcd",
		"hash_sha1":        "commit: 1234567890abcdef1234567890abcdef12345678",
		"multiple_secrets": "password=secret123 --token=abc456 api_key=xyz789",
		"no_match":         "this string has no sensitive data",
		"empty":            "",
		"special_chars":    "test!@#$%^&*()_+-=[]{}|;':\",./<>?",
	}
}
