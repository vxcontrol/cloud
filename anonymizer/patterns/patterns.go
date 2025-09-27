package patterns

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed db/general.yml
var GeneralPatterns []byte

//go:embed db/pii.yml
var PiiPatterns []byte

//go:embed db/secrets.yml
var SecretsPatterns []byte

type PatternListType uint8

const (
	PatternListTypeNone    PatternListType = 0
	PatternListTypeGeneral PatternListType = 1
	PatternListTypePii     PatternListType = 2
	PatternListTypeSecrets PatternListType = 4
	PatternListTypeAll     PatternListType = 7
)

type Pattern struct {
	Name  string `json:"name" yaml:"name"`
	Regex string `json:"regex" yaml:"regex"`
}

type Patterns struct {
	Patterns []Pattern `json:"patterns" yaml:"patterns"`
}

func (p *Patterns) Regexes() []string {
	regexes := make([]string, 0, len(p.Patterns))
	for _, pattern := range p.Patterns {
		regexes = append(regexes, pattern.Regex)
	}

	return regexes
}

func (p *Patterns) Names() []string {
	names := make([]string, 0, len(p.Patterns))
	for _, pattern := range p.Patterns {
		names = append(names, pattern.Name)
	}
	return names
}

func LoadPatterns(patternListType PatternListType) (*Patterns, error) {
	var (
		patterns   Patterns
		resultList Patterns
	)

	if patternListType&PatternListTypeGeneral != 0 {
		if err := yaml.Unmarshal(GeneralPatterns, &patterns); err != nil {
			return nil, err
		}
		resultList.Patterns = append(resultList.Patterns, patterns.Patterns...)
	}

	if patternListType&PatternListTypePii != 0 {
		if err := yaml.Unmarshal(PiiPatterns, &patterns); err != nil {
			return nil, err
		}
		resultList.Patterns = append(resultList.Patterns, patterns.Patterns...)
	}

	if patternListType&PatternListTypeSecrets != 0 {
		if err := yaml.Unmarshal(SecretsPatterns, &patterns); err != nil {
			return nil, err
		}
		resultList.Patterns = append(resultList.Patterns, patterns.Patterns...)
	}

	return &resultList, nil
}
