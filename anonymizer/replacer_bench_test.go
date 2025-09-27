package anonymizer

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
	"github.com/vxcontrol/cloud/anonymizer/testdata"
)

func BenchmarkNewReplacer_1000Patterns(b *testing.B) {
	patterns, names := testdata.GenerateRegexPatterns(12345, 1000)

	b.ResetTimer()
	for b.Loop() {
		_, err := NewReplacer(patterns, names)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewReplacer_5000Patterns(b *testing.B) {
	patterns, names := testdata.GenerateRegexPatterns(12345, 5000)

	b.ResetTimer()
	for b.Loop() {
		_, err := NewReplacer(patterns, names)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewReplacer_10000Patterns(b *testing.B) {
	patterns, names := testdata.GenerateRegexPatterns(12345, 10000)

	b.ResetTimer()
	for b.Loop() {
		_, err := NewReplacer(patterns, names)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkReplace(b *testing.B, patternCount int, stringCount int) {
	// limit memory to avoid swapping
	limitMemory()

	patterns, names := testdata.GenerateRegexPatterns(12345, patternCount)
	testStrings := testdata.GenerateTestStrings(54321, stringCount, 50, 200)

	replacer, err := NewReplacer(patterns, names)
	if err != nil {
		b.Fatal(err)
	}

	totalBytes := 0
	for _, s := range testStrings {
		totalBytes += len(s)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for _, testString := range testStrings {
			_ = replacer.ReplaceString(testString)
		}
	}

	stringsPerSec := float64(b.N*stringCount) / b.Elapsed().Seconds()
	bytesPerSec := float64(b.N*totalBytes) / b.Elapsed().Seconds()

	b.ReportMetric(stringsPerSec, "strings/sec")
	b.ReportMetric(bytesPerSec, "bytes/sec")
}

func benchmarkParallelReplace(b *testing.B, numGoroutines, patternCount int, stringCount int) {
	// limit memory to avoid swapping
	limitMemory()

	patterns, names := testdata.GenerateRegexPatterns(12345, patternCount)
	testStrings := testdata.GenerateTestStrings(54321, stringCount, 50, 200)

	replacer, err := NewReplacer(patterns, names)
	if err != nil {
		b.Fatal(err)
	}

	// calculate average bytes per string for accurate metrics
	totalBytes := 0
	for _, s := range testStrings {
		totalBytes += len(s)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetParallelism(numGoroutines)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, testString := range testStrings {
				_ = replacer.ReplaceString(testString)
			}
		}
	})

	stringsPerSec := float64(b.N*stringCount) / b.Elapsed().Seconds()
	bytesPerSec := float64(b.N*totalBytes) / b.Elapsed().Seconds()

	b.ReportMetric(stringsPerSec, "strings/sec")
	b.ReportMetric(bytesPerSec, "bytes/sec")
}

func BenchmarkReplace_1000Patterns(b *testing.B) {
	benchmarkReplace(b, 1000, 10000)
}

func BenchmarkReplace_5000Patterns(b *testing.B) {
	benchmarkReplace(b, 5000, 10000)
}

func BenchmarkReplace_10000Patterns(b *testing.B) {
	benchmarkReplace(b, 10000, 10000)
}

func BenchmarkParallel4_Replace_1000Patterns(b *testing.B) {
	benchmarkParallelReplace(b, 4, 1000, 10000)
}

func BenchmarkParallel4_Replace_5000Patterns(b *testing.B) {
	benchmarkParallelReplace(b, 4, 5000, 10000)
}

func BenchmarkParallel4_Replace_10000Patterns(b *testing.B) {
	benchmarkParallelReplace(b, 4, 10000, 10000)
}

func BenchmarkReplace_WorstCase(b *testing.B) {
	// limit memory to avoid swapping
	limitMemory()

	// create patterns that will match frequently
	patterns := []string{
		`[a-zA-Z0-9]+`,
		`\w+`,
		`[0-9]+`,
	}

	// generate strings that will have many matches
	rng := rand.New(rand.NewSource(99999))
	testStrings := make([]string, 1000)
	totalBytes := 0
	for i := range len(testStrings) {
		var sb strings.Builder
		length := rng.Intn(151) + 50 // 50-200 chars
		for range length {
			if rng.Float32() < 0.3 {
				sb.WriteByte(' ')
			} else {
				sb.WriteByte(byte('a' + rng.Intn(26)))
			}
		}
		testStrings[i] = sb.String()
		totalBytes += len(testStrings[i])
	}

	replacer, err := NewReplacer(patterns, make([]string, len(patterns)))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for _, testString := range testStrings {
			_ = replacer.ReplaceString(testString)
		}
	}

	stringsPerSec := float64(b.N*len(testStrings)) / b.Elapsed().Seconds()
	bytesPerSec := float64(b.N*totalBytes) / b.Elapsed().Seconds()

	b.ReportMetric(stringsPerSec, "strings/sec")
	b.ReportMetric(bytesPerSec, "bytes/sec")
}

func BenchmarkReplace_BestCase(b *testing.B) {
	// limit memory to avoid swapping
	limitMemory()

	// patterns that won't match
	patterns := []string{
		`xyz123notfound`,
		`veryrarepattern999`,
		`impossiblematch`,
	}

	testStrings := testdata.GenerateTestStrings(77777, 10000, 50, 200)

	replacer, err := NewReplacer(patterns, make([]string, len(patterns)))
	if err != nil {
		b.Fatal(err)
	}

	totalBytes := 0
	for _, s := range testStrings {
		totalBytes += len(s)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for _, testString := range testStrings {
			_ = replacer.ReplaceString(testString)
		}
	}

	stringsPerSec := float64(b.N*len(testStrings)) / b.Elapsed().Seconds()
	bytesPerSec := float64(b.N*totalBytes) / b.Elapsed().Seconds()

	b.ReportMetric(stringsPerSec, "strings/sec")
	b.ReportMetric(bytesPerSec, "bytes/sec")
}

func BenchmarkReplace_Production(b *testing.B) {
	// limit memory to avoid swapping
	limitMemory()

	patterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		b.Fatal(err)
	}

	replacer, err := NewReplacer(patterns.Regexes(), patterns.Names())
	if err != nil {
		b.Fatal(err)
	}

	insensitiveDataset, err := testdata.LoadInsensitiveData()
	if err != nil {
		b.Fatal(err)
	}

	datasets, err := testdata.LoadAllTestData()
	if err != nil {
		b.Fatal(err)
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

	testStrings := make([]string, 0, 10000)
	for _, dataset := range datasets {
		for _, entry := range dataset.Entries {
			prefix, suffix := getWrappedDataset()
			for line := range strings.Lines(entry.Examples) {
				testStrings = append(testStrings, fmt.Sprintf("%s %s %s", prefix, line, suffix))
			}
		}
	}

	totalBytes := 0
	testStringsLength := len(testStrings)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		testString := testStrings[i%testStringsLength]
		_ = replacer.ReplaceString(testString)
		totalBytes += len(testString)
	}

	stringsPerSec := float64(b.N) / b.Elapsed().Seconds()
	bytesPerSec := float64(totalBytes) / b.Elapsed().Seconds()

	b.ReportMetric(stringsPerSec, "strings/sec")
	b.ReportMetric(bytesPerSec, "bytes/sec")
}
