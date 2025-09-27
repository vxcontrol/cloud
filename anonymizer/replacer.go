package anonymizer

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"
)

type Replacer interface {
	ReplaceString(string) string
	ReplaceBytes([]byte) []byte
	WrapReader(io.Reader) io.Reader
}

type replacer struct {
	patterns []Pattern
	regexes  []*re2.Regexp
	set      *experimental.Set
	mx       *sync.Mutex
}

type Pattern struct {
	Name  string
	Regex string
}

func NewReplacer(patterns []string, names []string) (Replacer, error) {
	if len(patterns) != len(names) {
		return nil, fmt.Errorf("patterns and names must have the same length")
	}

	pts := make([]Pattern, 0, len(patterns))
	for i, pt := range patterns {
		pts = append(pts, Pattern{Regex: pt, Name: names[i]})
	}

	// it reduces the size of the state machine and speeds up its compilation
	sort.Slice(pts, func(i, j int) bool {
		return pts[i].Regex < pts[j].Regex
	})

	patterns = patterns[:0]
	for _, pt := range pts {
		patterns = append(patterns, pt.Regex)
	}

	set, err := experimental.CompileSet(patterns)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex set: %w", err)
	}

	regexes := make([]*re2.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		regex, err := re2.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex '%s': %w", pattern, err)
		}
		regexes = append(regexes, regex)
	}

	return &replacer{
		patterns: pts,
		regexes:  regexes,
		set:      set,
		mx:       &sync.Mutex{},
	}, nil
}

func (r *replacer) ReplaceString(s string) string {
	if len(r.regexes) == 0 {
		return s
	}

	// mutex here is to improve the performance because concurrent calls slower then single thread
	r.mx.Lock()
	defer r.mx.Unlock()

	matches := r.set.FindAllString(s, len(r.regexes))
	sort.Ints(matches)

	for _, match := range matches {
		regex := r.regexes[match]
		s = regex.ReplaceAllStringFunc(s, func(se string) string {
			ms := regex.FindStringSubmatch(se)
			if len(ms) < 2 {
				return r.getReplacePattern(r.patterns[match].Name, se)
			}

			replaceIndex := regex.SubexpIndex("replace")
			if replaceIndex == -1 {
				replaceIndex = 1
			}

			replace := r.getReplacePattern(r.patterns[match].Name, ms[replaceIndex])
			return strings.ReplaceAll(se, ms[replaceIndex], replace)
		})
	}

	return s
}

func (r *replacer) ReplaceBytes(b []byte) []byte {
	if len(r.regexes) == 0 {
		return b
	}

	// mutex here is to improve the performance because concurrent calls slower then single thread
	r.mx.Lock()
	defer r.mx.Unlock()

	matches := r.set.FindAll(b, len(r.regexes))
	sort.Ints(matches)

	for _, match := range matches {
		regex := r.regexes[match]
		b = regex.ReplaceAllFunc(b, func(se []byte) []byte {
			ms := regex.FindSubmatch(se)
			if len(ms) < 2 {
				return []byte(r.getReplacePattern(r.patterns[match].Name, string(se)))
			}

			replaceIndex := regex.SubexpIndex("replace")
			if replaceIndex == -1 {
				replaceIndex = 1
			}

			replace := r.getReplacePattern(r.patterns[match].Name, string(ms[replaceIndex]))
			return bytes.ReplaceAll(se, ms[replaceIndex], []byte(replace))
		})
	}

	return b
}

func (r *replacer) WrapReader(reader io.Reader) io.Reader {
	return newWrapper(reader, r)
}

func (r *replacer) getReplacePattern(name, match string) string {
	if len(match) < len(name)+6 { // 4 is the length of the "§**§", 2 extra for "*" left and right
		return fmt.Sprintf("§*%s*§", name)
	}

	paddingLength := min(10, (len(match) - len(name) - 2)) // 2 is the length of the "§" left and right
	paddingLeft := strings.Repeat("*", paddingLength/2)
	paddingRight := strings.Repeat("*", paddingLength-paddingLength/2)
	return fmt.Sprintf("§%s%s%s§", paddingLeft, name, paddingRight)
}
