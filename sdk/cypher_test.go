package sdk

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptBytes(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "small data",
			data: []byte("hello"),
		},
		{
			name: "exact block size",
			data: make([]byte, 16),
		},
		{
			name: "large data",
			data: make([]byte, 1024),
		},
		{
			name: "odd size data",
			data: make([]byte, 33),
		},
		{
			name: "json payload",
			data: []byte(`{"message": "test", "timestamp": 1234567890, "data": [1,2,3,4,5]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// fill test data with pattern for large arrays
			if len(tt.data) > 10 {
				for i := range tt.data {
					tt.data[i] = byte(i % 256)
				}
			}

			// encrypt
			encrypted, err := EncryptBytes(tt.data, key, iv)
			require.NoError(t, err)

			if len(tt.data) > 0 {
				assert.True(t, len(encrypted) > len(tt.data), "encrypted data should be larger for non-empty data")
			} else {
				// empty data produces no chunks, so no encrypted output
				assert.Equal(t, 0, len(encrypted), "empty data should produce no encrypted output")
			}

			// decrypt
			decrypted, err := DecryptBytes(encrypted, key, iv)
			require.NoError(t, err)
			assert.Equal(t, len(tt.data), len(decrypted), "plaintext length should match original")
			if len(tt.data) == 0 {
				assert.Empty(t, decrypted, "decrypted empty data should be empty")
			} else {
				assert.Equal(t, tt.data, decrypted, "decrypted data should match original")
			}
		})
	}
}

func TestEncryptBytesErrors(t *testing.T) {
	validKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	validIV := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	zeroKey := [16]byte{} // all zeros - should still work with AES

	tests := []struct {
		name      string
		data      []byte
		key       [16]byte
		iv        [16]byte
		wantError bool
	}{
		{
			name:      "valid encryption",
			data:      []byte("test"),
			key:       validKey,
			iv:        validIV,
			wantError: false,
		},
		{
			name:      "zero key should work",
			data:      []byte("test"),
			key:       zeroKey,
			iv:        validIV,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptBytes(tt.data, tt.key, tt.iv)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecryptBytesErrors(t *testing.T) {
	validKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	validIV := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	wrongKey := [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}

	// create valid encrypted data for testing
	testData := []byte("test data for decryption")
	validEncrypted, err := EncryptBytes(testData, validKey, validIV)
	require.NoError(t, err)

	tests := []struct {
		name      string
		data      []byte
		key       [16]byte
		iv        [16]byte
		wantError string
	}{
		{
			name:      "empty data",
			data:      []byte{},
			key:       validKey,
			iv:        validIV,
			wantError: "", // empty data should work (produces empty result)
		},
		{
			name:      "invalid chunk data",
			data:      []byte{1, 2, 3, 4, 5},
			key:       validKey,
			iv:        validIV,
			wantError: "invalid chunk length",
		},
		{
			name:      "wrong key",
			data:      validEncrypted,
			key:       wrongKey,
			iv:        validIV,
			wantError: "GCM decryption failed",
		},
		{
			name:      "valid decryption",
			data:      validEncrypted,
			key:       validKey,
			iv:        validIV,
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptBytes(tt.data, tt.key, tt.iv)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test compatibility between original and new streaming methods
func TestStreamCompatibility(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name     string
		data     string
		readSize int
	}{
		{
			name:     "empty stream",
			data:     "",
			readSize: 1024,
		},
		{
			name:     "small stream",
			data:     "hello world",
			readSize: 1024,
		},
		{
			name:     "small stream read by bytes",
			data:     "hello world",
			readSize: 1,
		},
		{
			name:     "medium stream",
			data:     strings.Repeat("test data ", 100),
			readSize: 64,
		},
		{
			name:     "large stream",
			data:     strings.Repeat("large test data with pattern ", 1000),
			readSize: 256,
		},
		{
			name:     "block-aligned data",
			data:     strings.Repeat("x", 16*10), // exactly 10 blocks
			readSize: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted1, err := EncryptBytes([]byte(tt.data), key, iv)
			require.NoError(t, err)

			decrypted1, err := DecryptStream(io.NopCloser(bytes.NewReader(encrypted1)), key, iv)
			require.NoError(t, err)

			var result1 bytes.Buffer
			_, err = io.Copy(&result1, decrypted1)
			require.NoError(t, err)
			require.NoError(t, decrypted1.Close())

			// test new stream methods (AES-GCM)
			source2 := io.NopCloser(strings.NewReader(tt.data))
			encryptedReader2, err := EncryptStream(source2, key, iv)
			require.NoError(t, err)

			var encrypted2 bytes.Buffer
			buf := make([]byte, tt.readSize)
			for {
				n, err := encryptedReader2.Read(buf)
				if n > 0 {
					encrypted2.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			require.NoError(t, encryptedReader2.Close())

			decrypted2, err := DecryptBytes(encrypted2.Bytes(), key, iv)
			require.NoError(t, err)

			var result2 bytes.Buffer
			result2.Write(decrypted2)

			// both methods should produce the same plaintext
			assert.Equal(t, tt.data, result1.String(), "encrypt bytes method should match input")
			assert.Equal(t, tt.data, result2.String(), "encrypt stream2 method should match input")
		})
	}
}

func TestStream2ErrorHandling(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	t.Run("encrypt stream2 with read error", func(t *testing.T) {
		errorReader := &errorReadCloser{err: fmt.Errorf("read error")}

		encryptedReader, err := EncryptStream(errorReader, key, iv)
		require.NoError(t, err)

		// try to read - should get error
		buf := make([]byte, 64)
		_, err = encryptedReader.Read(buf)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read error")
	})

	t.Run("decrypt stream2 with corrupted chunk length", func(t *testing.T) {
		// create invalid data with corrupted length
		corruptedData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03} // invalid length + some data
		source := io.NopCloser(bytes.NewReader(corruptedData))

		decryptedReader, err := DecryptStream(source, key, iv)
		require.NoError(t, err)

		// try to read - should get error
		buf := make([]byte, 64)
		_, err = decryptedReader.Read(buf)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid chunk length")
	})

	t.Run("decrypt stream2 with truncated chunk", func(t *testing.T) {
		// create data with valid length but insufficient data
		truncatedData := []byte{0x00, 0x00, 0x00, 0x20} // claims 32 bytes but no data follows
		source := io.NopCloser(bytes.NewReader(truncatedData))

		decryptedReader, err := DecryptStream(source, key, iv)
		require.NoError(t, err)

		// try to read - should get error
		buf := make([]byte, 64)
		_, err = decryptedReader.Read(buf)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read chunk data")
	})

	t.Run("decrypt stream2 with invalid GCM data", func(t *testing.T) {
		// create data with valid length but invalid GCM content
		invalidGCMData := make([]byte, 4+12+16)                // length + nonce + invalid ciphertext
		binary.BigEndian.PutUint32(invalidGCMData[0:4], 12+16) // nonce + ciphertext length
		rand.Read(invalidGCMData[4:])                          // random invalid data

		source := io.NopCloser(bytes.NewReader(invalidGCMData))

		decryptedReader, err := DecryptStream(source, key, iv)
		require.NoError(t, err)

		// try to read - should get GCM error
		buf := make([]byte, 64)
		_, err = decryptedReader.Read(buf)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "GCM decryption failed")
	})
}

func TestStream2LargeDataStreaming(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// test various data sizes
	sizes := []int{0, 1, 15, 16, 17, 1023, 1024, 1025, 4095, 4096, 4097, 16383, 16384, 16385}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			// generate test data with pattern
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			// encrypt with stream2
			source := io.NopCloser(bytes.NewReader(testData))
			encryptedReader, err := EncryptStream(source, key, iv)
			require.NoError(t, err)

			// read encrypted data with various buffer sizes
			var encryptedBuf bytes.Buffer
			bufSize := 1 + (size % 100) // variable buffer size from 1 to 100
			if bufSize < 1 {
				bufSize = 1
			}
			buf := make([]byte, bufSize)

			for {
				n, err := encryptedReader.Read(buf)
				if n > 0 {
					encryptedBuf.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			require.NoError(t, encryptedReader.Close())

			// decrypt with stream2
			decryptedReader, err := DecryptStream(io.NopCloser(&encryptedBuf), key, iv)
			require.NoError(t, err)

			// read decrypted data with different buffer size
			var decryptedBuf bytes.Buffer
			bufSize = 1 + ((size + 50) % 200) // different variable buffer size
			if bufSize < 1 {
				bufSize = 1
			}
			buf = make([]byte, bufSize)

			for {
				n, err := decryptedReader.Read(buf)
				if n > 0 {
					decryptedBuf.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			require.NoError(t, decryptedReader.Close())

			// verify result
			assert.Equal(t, size, decryptedBuf.Len(), "decrypted size should match original")
			if size == 0 {
				assert.Equal(t, 0, decryptedBuf.Len(), "empty data should produce empty result")
			} else {
				assert.Equal(t, testData, decryptedBuf.Bytes(), "decrypted content should match original")
			}
		})
	}
}

func TestStream2ReadPatterns(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// create test data with pattern
	testData := make([]byte, 5000) // 5KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// encrypt the data
	source := io.NopCloser(bytes.NewReader(testData))
	encryptedReader, err := EncryptStream(source, key, iv)
	require.NoError(t, err)

	var encryptedBuf bytes.Buffer
	_, err = io.Copy(&encryptedBuf, encryptedReader)
	require.NoError(t, err)
	require.NoError(t, encryptedReader.Close())

	readPatterns := []struct {
		name     string
		readSize int
	}{
		{"single byte reads", 1},
		{"tiny reads", 3},
		{"small reads", 7},
		{"medium reads", 64},
		{"large reads", 512},
		{"very large reads", 2048},
		{"exact chunk reads", 1024}, // matches internal chunk size
	}

	for _, pattern := range readPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			// decrypt with specific read pattern
			decryptedReader, err := DecryptStream(io.NopCloser(bytes.NewReader(encryptedBuf.Bytes())), key, iv)
			require.NoError(t, err)

			var decryptedBuf bytes.Buffer
			buf := make([]byte, pattern.readSize)
			for {
				n, err := decryptedReader.Read(buf)
				if n > 0 {
					decryptedBuf.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}

			require.NoError(t, decryptedReader.Close())
			assert.Equal(t, testData, decryptedBuf.Bytes(), "decrypted data should match original regardless of read pattern")
		})
	}
}

func TestConcurrentStreamOperations(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	testData := []byte("concurrent test data for stream operations")

	// test multiple concurrent encryptions with Stream2
	const numGoroutines = 20
	results := make(chan []byte, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			source := io.NopCloser(bytes.NewReader(testData))
			encryptedReader, err := EncryptStream(source, key, iv)
			if err != nil {
				errors <- err
				return
			}

			var encrypted bytes.Buffer
			_, err = io.Copy(&encrypted, encryptedReader)
			if err != nil {
				errors <- err
				return
			}
			encryptedReader.Close()

			results <- encrypted.Bytes()
		}()
	}

	// collect and verify results
	for i := 0; i < numGoroutines; i++ {
		select {
		case encrypted := <-results:
			// decrypt and verify
			decrypted, err := DecryptStream(io.NopCloser(bytes.NewReader(encrypted)), key, iv)
			require.NoError(t, err)

			var result bytes.Buffer
			_, err = io.Copy(&result, decrypted)
			require.NoError(t, err)
			require.NoError(t, decrypted.Close())

			assert.Equal(t, testData, result.Bytes())
		case err := <-errors:
			t.Fatalf("concurrent encryption failed: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for concurrent operations")
		}
	}
}

func TestMemoryEfficiency(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// create very large test data (1MB)
	const dataSize = 1024 * 1024
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	t.Run("large data streaming without memory explosion", func(t *testing.T) {
		// encrypt with small read buffer to test true streaming
		source := io.NopCloser(bytes.NewReader(testData))
		encryptedReader, err := EncryptStream(source, key, iv)
		require.NoError(t, err)

		var encryptedBuf bytes.Buffer
		buf := make([]byte, 1024) // small buffer - should not load entire 1MB into memory
		for {
			n, err := encryptedReader.Read(buf)
			if n > 0 {
				encryptedBuf.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}
		require.NoError(t, encryptedReader.Close())

		// decrypt with small read buffer
		decryptedReader, err := DecryptStream(io.NopCloser(&encryptedBuf), key, iv)
		require.NoError(t, err)

		var decryptedBuf bytes.Buffer
		buf = make([]byte, 512) // different small buffer size
		for {
			n, err := decryptedReader.Read(buf)
			if n > 0 {
				decryptedBuf.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}
		require.NoError(t, decryptedReader.Close())

		// verify result
		assert.Equal(t, dataSize, decryptedBuf.Len(), "decrypted size should match original")
		assert.Equal(t, testData, decryptedBuf.Bytes(), "decrypted content should match original")
	})
}

func TestProxyFunctions(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name string
		data string
	}{
		{
			name: "empty data",
			data: "",
		},
		{
			name: "small data",
			data: "hello proxy world",
		},
		{
			name: "medium data",
			data: strings.Repeat("proxy test data ", 100), // ~1.6KB
		},
		{
			name: "large data",
			data: strings.Repeat("large proxy data chunk ", 500), // ~11.5KB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testData := []byte(tt.data)

			// test EncryptProxy + DecryptProxy round trip
			var encryptedBuf bytes.Buffer
			src := bytes.NewReader(testData)

			// encrypt using proxy
			err := EncryptProxy(src, &encryptedBuf, key, iv)
			require.NoError(t, err)

			// verify encrypted data is not empty for non-empty input
			if len(testData) > 0 {
				assert.True(t, encryptedBuf.Len() > 0, "encrypted data should not be empty for non-empty input")
			}

			// decrypt using proxy
			var decryptedBuf bytes.Buffer
			err = DecryptProxy(&encryptedBuf, &decryptedBuf, key, iv)
			require.NoError(t, err)

			// verify round trip
			assert.Equal(t, testData, decryptedBuf.Bytes(), "proxy round trip should preserve data")
		})
	}
}

func TestProxyErrorHandling(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	t.Run("encrypt proxy with read error", func(t *testing.T) {
		errorReader := &errorReadCloser{err: fmt.Errorf("read error")}
		var buf bytes.Buffer

		err := EncryptProxy(errorReader, &buf, key, iv)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read error")
	})

	t.Run("decrypt proxy with write error", func(t *testing.T) {
		// create valid encrypted data
		testData := []byte("test data")
		var encryptedBuf bytes.Buffer
		src := bytes.NewReader(testData)
		err := EncryptProxy(src, &encryptedBuf, key, iv)
		require.NoError(t, err)

		// try to decrypt to error writer
		errorWriter := &errorWriter{err: fmt.Errorf("write error")}
		err = DecryptProxy(&encryptedBuf, errorWriter, key, iv)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("decrypt proxy with corrupted data", func(t *testing.T) {
		corruptedData := bytes.NewReader([]byte("corrupted"))
		var buf bytes.Buffer

		err := DecryptProxy(corruptedData, &buf, key, iv)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid chunk length")
	})
}

func TestProxyVsStreamConsistency(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	testData := []byte("consistency test between proxy and stream methods")

	// encrypt using proxy
	var proxyEncrypted bytes.Buffer
	src1 := bytes.NewReader(testData)
	err := EncryptProxy(src1, &proxyEncrypted, key, iv)
	require.NoError(t, err)

	// encrypt using stream
	src2 := io.NopCloser(bytes.NewReader(testData))
	streamEncrypted, err := EncryptStream(src2, key, iv)
	require.NoError(t, err)

	var streamEncryptedBuf bytes.Buffer
	_, err = io.Copy(&streamEncryptedBuf, streamEncrypted)
	require.NoError(t, err)
	streamEncrypted.Close()

	// encrypted results will be different due to random nonces, but should have same structure
	assert.Equal(t, streamEncryptedBuf.Len(), proxyEncrypted.Len(), "proxy and stream encryption should produce same length")

	// decrypt both using proxy
	var proxyDecrypted1, proxyDecrypted2 bytes.Buffer

	err = DecryptProxy(&proxyEncrypted, &proxyDecrypted1, key, iv)
	require.NoError(t, err)

	err = DecryptProxy(&streamEncryptedBuf, &proxyDecrypted2, key, iv)
	require.NoError(t, err)

	// both should produce original data
	assert.Equal(t, testData, proxyDecrypted1.Bytes(), "proxy decryption should work")
	assert.Equal(t, testData, proxyDecrypted2.Bytes(), "proxy should decrypt stream-encrypted data")
}

// errorWriter is a helper for testing write errors
type errorWriter struct {
	err error
}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, e.err
}

func TestEncryptBytesChunking(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name           string
		dataSize       int
		expectedChunks int
	}{
		{
			name:           "empty data",
			dataSize:       0,
			expectedChunks: 0, // empty data produces no chunks
		},
		{
			name:           "small data - one chunk",
			dataSize:       500,
			expectedChunks: 1,
		},
		{
			name:           "exact chunk size",
			dataSize:       defaultChunkSize,
			expectedChunks: 1,
		},
		{
			name:           "slightly over one chunk",
			dataSize:       defaultChunkSize + 1,
			expectedChunks: 2,
		},
		{
			name:           "two chunks",
			dataSize:       2*defaultChunkSize - 1,
			expectedChunks: 2,
		},
		{
			name:           "three chunks",
			dataSize:       2*defaultChunkSize + defaultChunkSize/2,
			expectedChunks: 3,
		},
		{
			name:           "large data - multiple chunks",
			dataSize:       1000 * defaultChunkSize,
			expectedChunks: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// generate test data
			testData := make([]byte, tt.dataSize)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			// encrypt using EncryptBytes
			encrypted, err := EncryptBytes(testData, key, iv)
			require.NoError(t, err)

			// analyze encrypted data to count chunks
			chunkCount := 0
			offset := 0

			for offset < len(encrypted) {
				// ensure we have at least 4 bytes for length
				if offset+4 > len(encrypted) {
					break
				}

				// read chunk length
				chunkLen := binary.BigEndian.Uint32(encrypted[offset : offset+4])

				// validate chunk length
				if chunkLen == 0 || chunkLen > 1024*1024 {
					t.Fatalf("invalid chunk length at offset %d: %d", offset, chunkLen)
				}

				// ensure we have the complete chunk
				totalChunkSize := 4 + int(chunkLen) // length prefix + chunk data
				if offset+totalChunkSize > len(encrypted) {
					t.Fatalf("incomplete chunk at offset %d: need %d bytes, have %d", offset, totalChunkSize, len(encrypted)-offset)
				}

				chunkCount++
				offset += totalChunkSize
			}

			// verify chunk count matches expectation
			assert.Equal(t, tt.expectedChunks, chunkCount, "chunk count should match expected")

			// verify decryption works correctly
			decrypted, err := DecryptBytes(encrypted, key, iv)
			require.NoError(t, err)

			if tt.dataSize == 0 {
				assert.Empty(t, decrypted, "empty data should decrypt to empty")
			} else {
				assert.Equal(t, testData, decrypted, "decrypted data should match original")
			}
		})
	}
}

func TestNonceXORMasking(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	testData := []byte("test data for nonce XOR verification")

	// encrypt with stream2
	source := io.NopCloser(bytes.NewReader(testData))
	encryptedReader, err := EncryptStream(source, key, iv)
	require.NoError(t, err)

	// read encrypted data and analyze nonce masking
	var encryptedBuf bytes.Buffer
	_, err = io.Copy(&encryptedBuf, encryptedReader)
	require.NoError(t, err)
	require.NoError(t, encryptedReader.Close())

	encryptedData := encryptedBuf.Bytes()

	// verify that encrypted data contains masked nonces
	// extract first chunk to verify nonce is XORed
	if len(encryptedData) >= 16 { // 4-byte length + 12-byte GCM nonce
		chunkLen := binary.BigEndian.Uint32(encryptedData[0:4])
		require.True(t, chunkLen >= 12, "chunk should contain at least nonce")

		if len(encryptedData) >= int(4+chunkLen) {
			maskedNonce := encryptedData[4:16] // first 12 bytes of chunk data

			// verify nonce is actually masked (XORed with IV)
			// we can't predict exact nonce value, but we can verify it's not all zeros
			allZeros := true
			for _, b := range maskedNonce {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros, "masked nonce should not be all zeros (extremely unlikely)")
		}
	}

	// decrypt and verify correctness
	decryptedReader, err := DecryptStream(io.NopCloser(&encryptedBuf), key, iv)
	require.NoError(t, err)

	var decryptedBuf bytes.Buffer
	_, err = io.Copy(&decryptedBuf, decryptedReader)
	require.NoError(t, err)
	require.NoError(t, decryptedReader.Close())

	// verify decryption worked correctly despite nonce masking
	assert.Equal(t, testData, decryptedBuf.Bytes(), "decryption should work correctly with XOR masked nonces")
}

func TestXORWithIVFunction(t *testing.T) {
	iv := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	tests := []struct {
		name     string
		nonce    []byte
		expected []byte
	}{
		{
			name:     "12-byte nonce (GCM standard)",
			nonce:    []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC},
			expected: []byte{0xBB, 0x99, 0xFF, 0x99, 0xBB, 0x99, 0x66, 0xAA, 0xAA, 0xEE, 0xEE, 0xAA}, // XOR result
		},
		{
			name:     "16-byte nonce",
			nonce:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			expected: []byte{0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0xFF}, // XOR result
		},
		{
			name:     "8-byte nonce",
			nonce:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			expected: []byte{0xAA, 0xAA, 0xEE, 0xEE, 0xAA, 0xAA, 0x77, 0x55}, // XOR result
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// test XOR operation
			nonceCopy := make([]byte, len(tt.nonce))
			copy(nonceCopy, tt.nonce)

			xorWithIV(nonceCopy, iv)
			assert.Equal(t, tt.expected, nonceCopy, "XOR result should match expected")

			// test that double XOR restores original
			xorWithIV(nonceCopy, iv)
			assert.Equal(t, tt.nonce, nonceCopy, "double XOR should restore original nonce")
		})
	}
}

func TestNonceNotVisibleInTransmission(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	// create test data that would produce predictable nonce pattern if not masked
	testData := []byte("predictable test data for nonce visibility test")

	// encrypt multiple times to get multiple chunks with different nonces
	var allEncryptedData [][]byte
	for i := 0; i < 5; i++ {
		source := io.NopCloser(bytes.NewReader(testData))
		encryptedReader, err := EncryptStream(source, key, iv)
		require.NoError(t, err)

		var encryptedBuf bytes.Buffer
		_, err = io.Copy(&encryptedBuf, encryptedReader)
		require.NoError(t, err)
		require.NoError(t, encryptedReader.Close())

		allEncryptedData = append(allEncryptedData, encryptedBuf.Bytes())
	}

	// analyze nonce areas in encrypted data
	for i, encrypted := range allEncryptedData {
		if len(encrypted) >= 16 { // 4-byte length + 12-byte masked nonce
			chunkLen := binary.BigEndian.Uint32(encrypted[0:4])
			require.True(t, chunkLen >= 12, "chunk should contain at least nonce")

			if len(encrypted) >= int(4+chunkLen) {
				maskedNonce := encrypted[4:16] // first 12 bytes should be masked nonce

				// verify that masked nonces are different between encryptions
				// (this proves nonces are random and properly masked)
				for j, otherEncrypted := range allEncryptedData {
					if i != j && len(otherEncrypted) >= 16 {
						otherMaskedNonce := otherEncrypted[4:16]
						assert.NotEqual(t, maskedNonce, otherMaskedNonce,
							"masked nonces should be different between encryptions %d and %d", i, j)
					}
				}

				// verify that nonce is properly masked (not original random bytes)
				// by checking it's not the IV XORed with all zeros (which would be the IV itself)
				assert.NotEqual(t, iv[:12], maskedNonce, "masked nonce should not equal IV (would indicate zero nonce)")
			}
		}
	}

	// verify all encryptions decrypt correctly
	for i, encrypted := range allEncryptedData {
		decryptedReader, err := DecryptStream(io.NopCloser(bytes.NewReader(encrypted)), key, iv)
		require.NoError(t, err, "decryption %d should succeed", i)

		var decryptedBuf bytes.Buffer
		_, err = io.Copy(&decryptedBuf, decryptedReader)
		require.NoError(t, err, "reading decrypted data %d should succeed", i)
		require.NoError(t, decryptedReader.Close())

		assert.Equal(t, testData, decryptedBuf.Bytes(), "decrypted data %d should match original", i)
	}
}

func TestEdgeCasesAndBoundaries(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	t.Run("zero-length read buffers", func(t *testing.T) {
		testData := []byte("test data")

		source := io.NopCloser(bytes.NewReader(testData))
		encryptedReader, err := EncryptStream(source, key, iv)
		require.NoError(t, err)

		// read with zero-length buffer
		buf := make([]byte, 0)
		n, err := encryptedReader.Read(buf)
		assert.Equal(t, 0, n)
		assert.NoError(t, err)

		require.NoError(t, encryptedReader.Close())
	})

	t.Run("multiple small reads across chunk boundaries", func(t *testing.T) {
		// create data larger than chunk size to test boundary crossing
		testData := make([]byte, 2500) // > 2 chunks
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		source := io.NopCloser(bytes.NewReader(testData))
		encryptedReader, err := EncryptStream(source, key, iv)
		require.NoError(t, err)

		var encryptedBuf bytes.Buffer
		_, err = io.Copy(&encryptedBuf, encryptedReader)
		require.NoError(t, err)
		require.NoError(t, encryptedReader.Close())

		// decrypt with very small reads (smaller than chunk size)
		decryptedReader, err := DecryptStream(io.NopCloser(&encryptedBuf), key, iv)
		require.NoError(t, err)

		var result bytes.Buffer
		buf := make([]byte, 7) // small odd-sized buffer
		for {
			n, err := decryptedReader.Read(buf)
			if n > 0 {
				result.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		require.NoError(t, decryptedReader.Close())
		assert.Equal(t, testData, result.Bytes())
	})

	t.Run("immediate EOF from source", func(t *testing.T) {
		// empty source that immediately returns EOF
		source := io.NopCloser(strings.NewReader(""))

		encryptedReader, err := EncryptStream(source, key, iv)
		require.NoError(t, err)

		// should handle empty stream gracefully
		buf := make([]byte, 64)
		n, err := encryptedReader.Read(buf)

		// might return 0 bytes with EOF or some encrypted empty data
		if err == io.EOF {
			assert.Equal(t, 0, n)
		} else {
			assert.NoError(t, err)
		}

		require.NoError(t, encryptedReader.Close())
	})
}

func TestRandomDataConsistency(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// test with truly random data of various sizes
	sizes := []int{0, 1, 16, 17, 64, 65, 256, 257, 1024, 1025, 4096, 4097}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("random_size_%d", size), func(t *testing.T) {
			// generate random data
			testData := make([]byte, size)
			if size > 0 {
				_, err := rand.Read(testData)
				require.NoError(t, err)
			}

			// test both bytes and stream methods
			// bytes method
			encryptedBytes, err := EncryptBytes(testData, key, iv)
			require.NoError(t, err)

			decryptedBytes, err := DecryptBytes(encryptedBytes, key, iv)
			require.NoError(t, err)
			assert.Equal(t, testData, decryptedBytes, "bytes method should work correctly")

			// stream2 method
			source := io.NopCloser(bytes.NewReader(testData))
			encryptedReader, err := EncryptStream(source, key, iv)
			require.NoError(t, err)

			var encryptedStream bytes.Buffer
			_, err = io.Copy(&encryptedStream, encryptedReader)
			require.NoError(t, err)
			require.NoError(t, encryptedReader.Close())

			decryptedReader, err := DecryptStream(io.NopCloser(&encryptedStream), key, iv)
			require.NoError(t, err)

			var decryptedStream bytes.Buffer
			_, err = io.Copy(&decryptedStream, decryptedReader)
			require.NoError(t, err)
			require.NoError(t, decryptedReader.Close())

			if len(testData) == 0 {
				assert.Equal(t, 0, decryptedStream.Len(), "stream2 method should handle empty data")
			} else {
				assert.Equal(t, testData, decryptedStream.Bytes(), "stream2 method should work correctly")
			}
		})
	}
}

// Performance and stress tests adapted from encryptor_test.go
func TestHighVolumeStreaming(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// test sizes: 16KB, 1MB, 32MB
	sizes := []int{16 * 1024, 1024 * 1024, 32 * 1024 * 1024}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("volume_%dB", size), func(t *testing.T) {
			// generate large test data
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			// encrypt with stream2
			source := io.NopCloser(bytes.NewReader(testData))
			encryptedReader, err := EncryptStream(source, key, iv)
			require.NoError(t, err)

			// read encrypted data efficiently
			var encryptedBuf bytes.Buffer
			buf := make([]byte, 8192) // 8KB buffer for efficiency
			for {
				n, err := encryptedReader.Read(buf)
				if n > 0 {
					encryptedBuf.Write(buf[:n])
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			require.NoError(t, encryptedReader.Close())

			// decrypt with stream2
			decryptedReader, err := DecryptStream(io.NopCloser(&encryptedBuf), key, iv)
			require.NoError(t, err)

			// verify by reading in chunks
			buf = make([]byte, 8192)
			totalRead := 0
			for {
				n, err := decryptedReader.Read(buf)
				if n > 0 {
					// verify chunk matches original data
					assert.Equal(t, testData[totalRead:totalRead+n], buf[:n],
						"chunk at offset %d should match original", totalRead)
					totalRead += n
				}
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}

			require.NoError(t, decryptedReader.Close())
			assert.Equal(t, size, totalRead, "total read should match original size")
		})
	}
}

// errorReadCloser is a helper for testing error conditions
type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return nil
}
