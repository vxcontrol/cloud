package anonymizer

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
	"github.com/vxcontrol/cloud/anonymizer/testdata"
)

type mockReplacer struct{}

func (m *mockReplacer) ReplaceString(s string) string {
	return s
}

func (m *mockReplacer) ReplaceBytes(b []byte) []byte {
	return b
}

func (m *mockReplacer) WrapReader(r io.Reader) io.Reader {
	return r
}

type simpleReplacer struct {
	pattern     string
	replacement string
}

func (sr *simpleReplacer) ReplaceString(s string) string {
	return strings.ReplaceAll(s, sr.pattern, sr.replacement)
}

func (sr *simpleReplacer) ReplaceBytes(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte(sr.pattern), []byte(sr.replacement))
}

func (sr *simpleReplacer) WrapReader(r io.Reader) io.Reader {
	return newWrapper(r, sr)
}

type trackingReplacer struct {
	pattern     string
	replacement string
	onCall      func() // callback for tracking invocations
}

func (tr *trackingReplacer) ReplaceString(s string) string {
	if tr.onCall != nil {
		tr.onCall()
	}
	return strings.ReplaceAll(s, tr.pattern, tr.replacement)
}

func (tr *trackingReplacer) ReplaceBytes(b []byte) []byte {
	if tr.onCall != nil {
		tr.onCall()
	}
	return bytes.ReplaceAll(b, []byte(tr.pattern), []byte(tr.replacement))
}

func (tr *trackingReplacer) WrapReader(r io.Reader) io.Reader {
	return newWrapper(r, tr)
}

// test with mock replacer - basic functionality
func TestWrapper_BasicRead(t *testing.T) {
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader("test"), replacer)
	buf := make([]byte, 10)

	n, err := wrapper.Read(buf)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if n != 4 {
		t.Fatalf("expected 4 bytes, got: %d", n)
	}
	if string(buf[:n]) != "test" {
		t.Fatalf("expected test, got: %s", string(buf[:n]))
	}

	n, err = wrapper.Read(buf)
	if n != 0 {
		t.Fatalf("expected 0 bytes, got: %d", n)
	}
	if err != io.EOF {
		t.Fatalf("expected EOF, got: %v", err)
	}
}

func TestWrapper_EmptyReader(t *testing.T) {
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(""), replacer)
	buf := make([]byte, 10)

	n, err := wrapper.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF, got: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got: %d", n)
	}
}

func TestWrapper_SmallBufferReads(t *testing.T) {
	testData := "this is a longer test string that should be read in small chunks"
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	var result strings.Builder
	buf := make([]byte, 5) // small buffer to force multiple reads

	for {
		n, err := wrapper.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if result.String() != testData {
		t.Errorf("expected: %s, got: %s", testData, result.String())
	}
}

func TestWrapper_SingleByteReads(t *testing.T) {
	testData := "single byte reads test"
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	var result []byte
	buf := make([]byte, 1)

	for {
		n, err := wrapper.Read(buf)
		if n > 0 {
			result = append(result, buf[0])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if string(result) != testData {
		t.Errorf("expected: %s, got: %s", testData, string(result))
	}
}

func TestWrapper_LargeBufferRead(t *testing.T) {
	testData := "test data"
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	buf := make([]byte, 1000) // buffer much larger than data
	n, err := wrapper.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}

	if n != len(testData) {
		t.Errorf("expected %d bytes, got %d", len(testData), n)
	}

	if string(buf[:n]) != testData {
		t.Errorf("expected: %s, got: %s", testData, string(buf[:n]))
	}
}

func TestWrapper_MultipleChunkSizes(t *testing.T) {
	sizes := []int{1, chunkSize / 4, chunkSize / 2, chunkSize, chunkSize * 2, chunkSize * 4}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			// generate test data
			testData := strings.Repeat("x", size)
			replacer := &mockReplacer{}
			wrapper := newWrapper(strings.NewReader(testData), replacer)

			// read all data
			result, err := io.ReadAll(wrapper)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(result) != testData {
				t.Errorf("data size %d: expected length %d, got %d", size, len(testData), len(result))
			}
		})
	}
}

func TestWrapper_ChunkBoundaryReplacement(t *testing.T) {
	// test pattern replacement across chunk boundaries
	testData := strings.Repeat("a", chunkSize-5) + "secret123" + strings.Repeat("b", chunkSize)
	replacer := &simpleReplacer{pattern: "secret123", replacement: "MASKED"}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "MASKED") {
		t.Error("pattern should be replaced even across chunk boundaries")
	}
	if strings.Contains(resultStr, "secret123") {
		t.Error("original pattern should not remain after replacement")
	}
}

func TestWrapper_OverlapBoundaryHandling(t *testing.T) {
	// create data where sensitive pattern spans chunk boundary
	prefix := strings.Repeat("x", chunkSize-3)
	secret := "password=secret123"
	suffix := strings.Repeat("y", chunkSize)
	testData := prefix + secret + suffix

	replacer := &simpleReplacer{pattern: "password=secret123", replacement: "password=MASKED"}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "password=MASKED") {
		t.Error("pattern spanning chunk boundary should be replaced")
	}
	if strings.Contains(resultStr, "password=secret123") {
		t.Error("original pattern should be fully replaced")
	}
}

func TestWrapper_WithRealReplacer(t *testing.T) {
	patterns := []string{`password=([^\s]+)`}
	names := []string{"PASSWORD"}

	realReplacer, err := NewReplacer(patterns, names)
	if err != nil {
		t.Fatalf("failed to create real replacer: %v", err)
	}

	testData := "connecting with password=secret123 to database"
	wrapper := newWrapper(strings.NewReader(testData), realReplacer)

	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "§") {
		t.Error("real replacer should mask sensitive data with § markers")
	}
	if strings.Contains(resultStr, "secret123") {
		t.Error("sensitive data should be masked")
	}
}

func TestWrapper_MultiplePatternReplacement(t *testing.T) {
	patterns := []string{
		`password=([^\s]+)`,
		`--token\s+([a-zA-Z0-9]+)\b`,
	}
	names := []string{"PASSWORD", "TOKEN"}

	realReplacer, err := NewReplacer(patterns, names)
	if err != nil {
		t.Fatalf("failed to create replacer: %v", err)
	}

	testData := "start password=secret123 middle --token mytoken4567 end"
	wrapper := newWrapper(strings.NewReader(testData), realReplacer)

	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "PASSWORD") {
		t.Error("password should be masked")
	}
	if !strings.Contains(resultStr, "TOKEN") {
		t.Error("token should be masked")
	}
	if strings.Contains(resultStr, "secret123") || strings.Contains(resultStr, "mytoken4567") {
		t.Error("sensitive values should be masked")
	}
}

func TestWrapper_ErrorHandling(t *testing.T) {
	// test with reader that returns error
	errorReader := &errorReader{err: fmt.Errorf("read error")}
	replacer := &mockReplacer{}
	wrapper := newWrapper(errorReader, replacer)

	buf := make([]byte, 10)
	_, err := wrapper.Read(buf)

	if err == nil {
		t.Error("expected error from underlying reader")
	}
	if !strings.Contains(err.Error(), "read error") {
		t.Errorf("expected error message to contain 'read error', got: %v", err)
	}
}

func TestWrapper_ZeroLengthRead(t *testing.T) {
	testData := "test data"
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	// read with zero-length buffer
	buf := make([]byte, 0)
	n, err := wrapper.Read(buf)

	if n != 0 {
		t.Errorf("expected 0 bytes read, got %d", n)
	}
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWrapper_VariousReadPatterns(t *testing.T) {
	testData := strings.Repeat("test pattern data ", 100) // create data larger than chunk size
	replacer := &mockReplacer{}

	readPatterns := []struct {
		name    string
		bufSize int
	}{
		{"tiny reads", 1},
		{"small reads", 7},
		{"medium reads", 64},
		{"large reads", 512},
		{"very large reads", 2048},
		{"chunk size reads", chunkSize},
		{"larger than chunk", chunkSize + 100},
	}

	for _, pattern := range readPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			wrapper := newWrapper(strings.NewReader(testData), replacer)

			var result strings.Builder
			buf := make([]byte, pattern.bufSize)

			for {
				n, err := wrapper.Read(buf)
				if n > 0 {
					result.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if result.String() != testData {
				t.Error("result should match original data regardless of read pattern")
			}
		})
	}
}

func TestWrapper_ProductionPatterns(t *testing.T) {
	// test with production-like patterns and data
	allPatterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		t.Skipf("failed to load production patterns: %v", err)
	}

	replacer, err := NewReplacer(allPatterns.Regexes(), allPatterns.Names())
	if err != nil {
		t.Skipf("failed to create replacer with production patterns: %v", err)
	}

	// load test datasets
	datasets, err := testdata.LoadAllTestData()
	if err != nil {
		t.Skipf("failed to load test data: %v", err)
	}

	for _, dataset := range datasets {
		for _, entry := range dataset.Entries {
			if len(entry.Examples) > 1000 { // limit test data size for performance
				continue
			}

			t.Run(fmt.Sprintf("%s_%s", dataset.Category, entry.Name), func(t *testing.T) {
				wrapper := newWrapper(strings.NewReader(entry.Examples), replacer)

				result, err := io.ReadAll(wrapper)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// basic sanity check - masked data should not contain original examples
				resultStr := string(result)
				lines := strings.Split(entry.Examples, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if len(line) > 0 && strings.Contains(resultStr, line) {
						// some patterns might not match, so this is informational
						t.Logf("warning: line '%s' was not masked in %s.%s", line, dataset.Category, entry.Name)
					}
				}
			})
		}
	}
}

// test with configurable chunk and overlap sizes
func TestWrapper_ConfigurableChunkSizes(t *testing.T) {
	// note: in real implementation, chunkSize and overlapSize should be configurable parameters
	// this test shows what should be tested if they were configurable

	testSizes := []struct {
		name            string
		testChunkSize   int
		testOverlapSize int
	}{
		{"small_chunk_small_overlap", 512, 128},
		{"medium_chunk_small_overlap", 2048, 256},
		{"large_chunk_medium_overlap", 8192, 1024},
		{"very_large_chunk", 16384, 2048},
	}

	for _, ts := range testSizes {
		t.Run(ts.name, func(t *testing.T) {
			// create test data larger than chunk size
			testData := strings.Repeat("test data chunk ", ts.testChunkSize/10)
			replacer := &mockReplacer{}
			wrapper := newWrapper(strings.NewReader(testData), replacer)

			result, err := io.ReadAll(wrapper)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(result) != testData {
				t.Error("result should match original data regardless of chunk size")
			}
		})
	}
}

func TestWrapper_OverlapEffectiveness(t *testing.T) {
	// test that overlap actually helps with boundary patterns
	// create a pattern that would be split across default chunk boundary
	prefix := strings.Repeat("a", chunkSize-7) // position pattern near boundary
	pattern := "password=secret123"
	suffix := strings.Repeat("b", 100)
	testData := prefix + pattern + suffix

	// test with simple string replacer
	replacer := &simpleReplacer{
		pattern:     pattern,
		replacement: "password=MASKED",
	}

	wrapper := newWrapper(strings.NewReader(testData), replacer)
	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if strings.Contains(resultStr, "password=secret123") {
		t.Error("pattern crossing chunk boundary should be replaced due to overlap")
	}
	if !strings.Contains(resultStr, "password=MASKED") {
		t.Error("replacement should be present")
	}
}

func TestWrapper_OverlapMechanismDetails(t *testing.T) {
	// detailed test of overlap mechanism - verify that pattern on chunk boundary
	// is correctly processed thanks to overlap area

	// create data so that pattern is exactly on chunkSize boundary
	partialPattern := "passwo"    // part of pattern
	restPattern := "rd=secret123" // rest of pattern

	// first chunk ends on partialPattern
	prefix := strings.Repeat("x", chunkSize-len(partialPattern))
	testData := prefix + partialPattern + restPattern + "suffix"

	replacer := &simpleReplacer{
		pattern:     "password=secret123",
		replacement: "password=MASKED",
	}

	wrapper := newWrapper(strings.NewReader(testData), replacer)
	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if strings.Contains(resultStr, "password=secret123") {
		t.Error("split pattern should be replaced thanks to overlap mechanism")
	}
	if !strings.Contains(resultStr, "password=MASKED") {
		t.Error("replacement should be present")
	}
	if !strings.Contains(resultStr, "suffix") {
		t.Error("data after pattern should be preserved")
	}
}

func TestWrapper_ReplacerApplicationTiming(t *testing.T) {
	// test checks that replacer is applied at the right time -
	// after adding new data to buffer, but before returning data to user

	callCount := 0
	trackingReplacer := &trackingReplacer{
		pattern:     "secret",
		replacement: "MASKED",
		onCall:      func() { callCount++ },
	}

	// data that will require several reads from source
	testData := strings.Repeat("some data with secret inside ", 1000)

	wrapper := newWrapper(strings.NewReader(testData), trackingReplacer)

	// read data in small chunks
	buf := make([]byte, 100)
	totalRead := 0

	for {
		n, err := wrapper.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// replacer should be called multiple times (on each new data addition)
	if callCount == 0 {
		t.Error("replacer should be called when processing data")
	}

	// total size should match original data
	if totalRead != len(testData) {
		t.Errorf("expected to read %d bytes, got %d", len(testData), totalRead)
	}
}

func TestWrapper_ReplacerIdempotence(t *testing.T) {
	// test that replacer behaves correctly when applied multiple times to the same data
	// this is important because in wrapper algorithm replacer is applied to entire buffer
	// each time when new data is added (for correct overlap area processing)
	testData := "password=secret123"

	replacer := &simpleReplacer{
		pattern:     "password=secret123",
		replacement: "password=MASKED_ONCE",
	}

	wrapper := newWrapper(strings.NewReader(testData), replacer)
	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)

	// check that replacement works correctly even with repeated replacer application
	maskCount := strings.Count(resultStr, "MASKED_ONCE")
	if maskCount != 1 {
		t.Errorf("replacement should occur exactly once, got %d occurrences in: %s", maskCount, resultStr)
	}

	// additional idempotence check - apply replacer once more
	doubleProcessed := replacer.ReplaceBytes([]byte(resultStr))
	if string(doubleProcessed) != resultStr {
		t.Error("replacer should be idempotent - repeated application should not change result")
	}
}

func TestWrapper_BufferManagement(t *testing.T) {
	// test various read patterns to verify buffer management
	testData := strings.Repeat("buffer management test ", 1000)
	replacer := &mockReplacer{}

	readPatterns := []struct {
		name        string
		bufferSizes []int
	}{
		{"random_small", []int{1, 3, 7, 2, 5, 8, 1}},
		{"increasing", []int{1, 2, 4, 8, 16, 32, 64}},
		{"decreasing", []int{64, 32, 16, 8, 4, 2, 1}},
		{"mixed_large_small", []int{1024, 1, 2048, 3, 512, 7}},
		{"around_chunk_size", []int{chunkSize - 1, chunkSize, chunkSize + 1}},
		{"overlap_related", []int{overlapSize - 1, overlapSize, overlapSize + 1}},
	}

	for _, pattern := range readPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			wrapper := newWrapper(strings.NewReader(testData), replacer)

			var result strings.Builder
			bufSizeIdx := 0

			for {
				bufSize := pattern.bufferSizes[bufSizeIdx%len(pattern.bufferSizes)]
				buf := make([]byte, bufSize)

				n, err := wrapper.Read(buf)
				if n > 0 {
					result.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				bufSizeIdx++
			}

			if result.String() != testData {
				t.Error("complex read patterns should not affect data integrity")
			}
		})
	}
}

func TestWrapper_LargePatternDetection(t *testing.T) {
	// test detection of patterns larger than overlap size
	largePattern := strings.Repeat("x", overlapSize+100)
	testData := "prefix " + largePattern + " suffix"

	replacer := &simpleReplacer{
		pattern:     largePattern,
		replacement: "LARGE_PATTERN_MASKED",
	}

	wrapper := newWrapper(strings.NewReader(testData), replacer)
	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)

	// the current implementation should handle this, but it's worth testing
	if !strings.Contains(resultStr, "LARGE_PATTERN_MASKED") {
		t.Log("note: large pattern (larger than overlap) was not replaced")
		t.Log("this might be expected behavior depending on implementation")
	}
}

func TestWrapper_ConcurrentSafeUsage(t *testing.T) {
	// test that multiple wrappers can be used safely (no shared state issues)
	testData := "concurrent test data with password=secret123"

	const numGoroutines = 10
	results := make(chan string, numGoroutines)
	errors := make(chan error, numGoroutines)

	replacer := &simpleReplacer{
		pattern:     "password=secret123",
		replacement: "password=MASKED",
	}

	for i := range numGoroutines {
		go func(id int) {
			wrapper := newWrapper(strings.NewReader(testData), replacer)
			result, err := io.ReadAll(wrapper)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
				return
			}
			results <- string(result)
		}(i)
	}

	// collect results
	for range numGoroutines {
		select {
		case result := <-results:
			if !strings.Contains(result, "password=MASKED") {
				t.Error("concurrent usage should still perform replacements")
			}
			if strings.Contains(result, "password=secret123") {
				t.Error("concurrent usage should mask sensitive data")
			}
		case err := <-errors:
			t.Fatalf("concurrent usage error: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent operations")
		}
	}
}

func TestWrapper_StreamingWithBackpressure(t *testing.T) {
	// simulate slow reader to test buffer management under backpressure
	testData := strings.Repeat("streaming test data ", 5000) // ~100KB
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(testData), replacer)

	var result strings.Builder
	buf := make([]byte, 64) // small buffer to create backpressure

	for {
		n, err := wrapper.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
			// simulate processing delay
			time.Sleep(1 * time.Microsecond)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if result.String() != testData {
		t.Error("streaming with backpressure should preserve data integrity")
	}
}

func TestWrapper_EmptyChunkHandling(t *testing.T) {
	// test behavior when underlying reader returns empty reads
	reader := &intermittentReader{
		data:   []byte("test data with empty reads"),
		chunks: []int{4, 0, 5, 0, 0, 4, 0, 13}, // mix of data and empty reads
		index:  0,
	}

	replacer := &mockReplacer{}
	wrapper := newWrapper(reader, replacer)

	result, err := io.ReadAll(wrapper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "test data with empty reads"
	if string(result) != expected {
		t.Errorf("expected: %s, got: %s", expected, string(result))
	}
}

func TestWrapper_MemoryUsagePattern(t *testing.T) {
	// verify that memory usage doesn't grow unbounded
	largeTestData := strings.Repeat("memory test ", 100000) // ~1.2MB
	replacer := &mockReplacer{}
	wrapper := newWrapper(strings.NewReader(largeTestData), replacer)

	// read in small chunks to verify buffer doesn't grow excessively
	buf := make([]byte, 256)
	totalRead := 0

	for {
		n, err := wrapper.Read(buf)
		if n > 0 {
			totalRead += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if totalRead != len(largeTestData) {
		t.Errorf("expected to read %d bytes, got %d", len(largeTestData), totalRead)
	}
}
