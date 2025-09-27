package anonymizer

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
	"github.com/vxcontrol/cloud/anonymizer/testdata"
)

func BenchmarkWrapper_WithRealReplacer(b *testing.B) {
	datasets, err := testdata.LoadAllTestData()
	if err != nil {
		b.Fatalf("failed to load test data: %v", err)
	}

	insensitiveDataset, err := testdata.LoadInsensitiveData()
	if err != nil {
		b.Fatalf("failed to load insensitive data: %v", err)
	}

	allLoadedPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		b.Fatalf("failed to load all patterns: %v", err)
	}

	replacer, err := NewReplacer(allLoadedPatterns.Regexes(), allLoadedPatterns.Names())
	if err != nil {
		b.Fatalf("failed to create replacer: %v", err)
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

	testDataBuf := bytes.NewBuffer(nil)
	for testDataBuf.Len() < 100*1024 { // at least 100KB
		for _, dataset := range datasets {
			for _, entry := range dataset.Entries {
				prefix, suffix := getWrappedDataset()
				testDataBuf.WriteString(prefix)
				testDataBuf.WriteString(entry.Examples)
				testDataBuf.WriteString(suffix)
				testDataBuf.WriteString(" ")
			}
			testDataBuf.WriteString("\n")
		}
	}

	testData := testDataBuf.Bytes()
	chunkSizes := []int{1024, 4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024}

	for _, size := range chunkSizes {
		b.Run(fmt.Sprintf("single_thread_reader_%dKB", size/1024), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for b.Loop() {
				wrapper := replacer.WrapReader(bytes.NewReader(testData))
				buf := make([]byte, size)
				for {
					_, err := wrapper.Read(buf)
					if err == io.EOF {
						break
					}
				}
			}

			b.ReportMetric(float64(size), "bytes/op")
			b.ReportMetric(float64(size*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
		})
	}

	b.Run("single_thread_reader", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			wrapper := replacer.WrapReader(bytes.NewReader(testData))
			io.Copy(io.Discard, wrapper)
		}

		b.ReportMetric(float64(len(testData)), "bytes/op")
		b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
	})

	b.Run("parallel_reader", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				wrapper := replacer.WrapReader(bytes.NewReader(testData))
				io.Copy(io.Discard, wrapper)
			}
		})

		b.ReportMetric(float64(len(testData)), "bytes/op")
		b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
	})

	b.Run("single_thread_replacer", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = replacer.ReplaceBytes(testData)
		}

		b.ReportMetric(float64(len(testData)), "bytes/op")
		b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
	})

	b.Run("parallel_replacer", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = replacer.ReplaceBytes(testData)
			}
		})

		b.ReportMetric(float64(len(testData)), "bytes/op")
		b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
	})
}

func BenchmarkWrapper_MemoryEfficiency(b *testing.B) {
	// test memory usage with large data and small reads
	testData := strings.Repeat("memory efficiency test data ", 50000) // ~1.4MB
	replacer := &mockReplacer{}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		wrapper := newWrapper(strings.NewReader(testData), replacer)
		buf := make([]byte, 1024) // read in small chunks
		for {
			_, err := wrapper.Read(buf)
			if err == io.EOF {
				break
			}
		}
	}

	b.ReportMetric(float64(len(testData)), "bytes/op")
	b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
}

func BenchmarkWrapper_ReplacementIntensive(b *testing.B) {
	// benchmark with data that has many patterns to replace
	testData := strings.Repeat("password=secret123 token=abc456 api_key=def789 ", 1000)
	patterns := []string{`password=([^\s]+)`, `token=([^\s]+)`, `api_key=([^\s]+)`}
	names := []string{"PASSWORD", "TOKEN", "API_KEY"}

	replacer, err := NewReplacer(patterns, names)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		wrapper := newWrapper(strings.NewReader(testData), replacer)
		io.Copy(io.Discard, wrapper)
	}

	b.ReportMetric(float64(len(testData)), "bytes/op")
	b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
}

func BenchmarkWrapper_NoReplacementNeeded(b *testing.B) {
	// benchmark with data that has no patterns to replace
	testData := strings.Repeat("clean log data with no sensitive information ", 1000)
	patterns := []string{`password=([^\s]+)`, `token=([^\s]+)`}
	names := []string{"PASSWORD", "TOKEN"}

	replacer, err := NewReplacer(patterns, names)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		wrapper := newWrapper(strings.NewReader(testData), replacer)
		io.Copy(io.Discard, wrapper)
	}

	b.ReportMetric(float64(len(testData)), "bytes/op")
	b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
}

func BenchmarkWrapper_OverlapHeavy(b *testing.B) {
	// benchmark scenario where patterns frequently span chunk boundaries
	baseChunk := strings.Repeat("x", chunkSize-10)
	pattern := "password=secret123"
	testData := baseChunk + pattern + baseChunk + pattern + baseChunk

	replacer := &simpleReplacer{
		pattern:     pattern,
		replacement: "password=MASKED",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		wrapper := newWrapper(strings.NewReader(testData), replacer)
		io.Copy(io.Discard, wrapper)
	}

	b.ReportMetric(float64(len(testData)), "bytes/op")
	b.ReportMetric(float64(len(testData)*b.N)/float64(b.Elapsed().Seconds()), "bytes/sec")
}

// helper types for testing
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

type intermittentReader struct {
	data   []byte
	chunks []int
	index  int
	pos    int
}

func (r *intermittentReader) Read(p []byte) (n int, err error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}

	chunkSize := r.chunks[r.index]
	r.index++

	if chunkSize == 0 {
		return 0, nil // empty read
	}

	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	available := len(r.data) - r.pos
	toRead := min(min(chunkSize, len(p)), available)

	copy(p, r.data[r.pos:r.pos+toRead])
	r.pos += toRead

	return toRead, nil
}
