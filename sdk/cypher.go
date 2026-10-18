package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// StreamDirection binds protected frames to a request or response.
// StreamLegacy selects the original framing and ignores requestID.
type StreamDirection byte

const (
	defaultChunkSize = 16 * 1024   // 16KB
	maxChunkSize     = 1024 * 1024 // 1MB
	finalFrameFlag   = uint32(1 << 31)

	StreamLegacy   StreamDirection = 0
	StreamRequest  StreamDirection = 1
	StreamResponse StreamDirection = 2
)

// EncryptBytes encrypts data using GCM streaming method
func EncryptBytes(data []byte, key, iv, requestID [16]byte, direction StreamDirection) ([]byte, error) {
	src := io.NopCloser(bytes.NewReader(data))

	// use streaming encryption
	encryptedReader, err := EncryptStream(src, key, iv, requestID, direction)
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted stream: %w", err)
	}

	// read all encrypted data
	var result bytes.Buffer
	_, err = io.Copy(&result, encryptedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	err = encryptedReader.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close encrypted stream: %w", err)
	}

	return result.Bytes(), nil
}

// DecryptBytes decrypts data using GCM streaming method
func DecryptBytes(encryptedData []byte, key, iv, requestID [16]byte, direction StreamDirection) ([]byte, error) {
	src := io.NopCloser(bytes.NewReader(encryptedData))

	// use streaming decryption
	decryptedReader, err := DecryptStream(src, key, iv, requestID, direction)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypted stream: %w", err)
	}

	// read all decrypted data
	var result bytes.Buffer
	_, err = io.Copy(&result, decryptedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	err = decryptedReader.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close decrypted stream: %w", err)
	}

	return result.Bytes(), nil
}

// EncryptProxy encrypts data from src and writes to dst in blocking manner
func EncryptProxy(src io.Reader, dst io.Writer, key, iv, requestID [16]byte, direction StreamDirection) error {
	encryptedReader, err := EncryptStream(src, key, iv, requestID, direction)
	if err != nil {
		return fmt.Errorf("failed to create encrypted stream: %w", err)
	}
	defer encryptedReader.Close()

	_, err = io.Copy(dst, encryptedReader)
	if err != nil {
		return fmt.Errorf("failed to copy encrypted data: %w", err)
	}

	return nil
}

// DecryptProxy decrypts data from src and writes to dst in blocking manner
func DecryptProxy(src io.Reader, dst io.Writer, key, iv, requestID [16]byte, direction StreamDirection) error {
	decryptedReader, err := DecryptStream(src, key, iv, requestID, direction)
	if err != nil {
		return fmt.Errorf("failed to create decrypted stream: %w", err)
	}
	defer decryptedReader.Close()

	_, err = io.Copy(dst, decryptedReader)
	if err != nil {
		return fmt.Errorf("failed to copy decrypted data: %w", err)
	}

	return nil
}

// streamEncryptor implements true streaming encryption using AES-GCM
type streamEncryptor struct {
	src        io.Reader
	gcm        cipher.AEAD
	iv         [16]byte
	requestID  [16]byte
	direction  StreamDirection
	buffer     []byte
	index      int
	finished   bool
	sourceErr  error
	frameIndex uint64
	total      uint64
	chunkSize  int
}

// EncryptStream creates a true streaming encryptor using AES-GCM.
// The decryptor must use the same requestID and direction; StreamLegacy ignores requestID.
func EncryptStream(src io.Reader, key, iv, requestID [16]byte, direction StreamDirection) (io.ReadCloser, error) {
	switch direction {
	case StreamLegacy, StreamRequest, StreamResponse:
	default:
		return nil, fmt.Errorf("invalid stream direction: %d", direction)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &streamEncryptor{
		src:       src,
		gcm:       gcm,
		iv:        iv,
		requestID: requestID,
		direction: direction,
		buffer:    make([]byte, 0),
		index:     0,
		finished:  false,
		chunkSize: defaultChunkSize,
	}, nil
}

func (se *streamEncryptor) Read(p []byte) (n int, err error) {
	if se.finished && se.index >= len(se.buffer) {
		return 0, io.EOF
	}

	// serve from buffer if available
	if se.index < len(se.buffer) {
		n = copy(p, se.buffer[se.index:])
		se.index += n
		return n, nil
	}

	// need more data - read and encrypt chunk
	if !se.finished {
		if err := se.encryptNextChunk(); err != nil {
			if err == io.EOF {
				se.finished = true
				// try to serve remaining data from buffer
				if se.index < len(se.buffer) {
					n = copy(p, se.buffer[se.index:])
					se.index += n
					if se.index >= len(se.buffer) {
						return n, io.EOF
					}
					return n, nil
				}
				return 0, io.EOF
			}
			return 0, err
		}

		// serve from newly filled buffer
		if se.index < len(se.buffer) {
			n = copy(p, se.buffer[se.index:])
			se.index += n
			return n, nil
		}
	}

	return 0, nil
}

func (se *streamEncryptor) encryptNextChunk() error {
	// read chunk from source
	var chunk []byte
	var srcN int
	srcErr := se.sourceErr
	if srcErr == nil {
		chunk = make([]byte, se.chunkSize)
		srcN, srcErr = se.src.Read(chunk)
		if se.direction != StreamLegacy {
			se.sourceErr = srcErr
		}
	}
	if srcErr != nil && srcErr != io.EOF {
		return fmt.Errorf("source read error: %w", srcErr)
	}
	if srcN == 0 && srcErr == nil {
		return nil
	}

	final := srcN == 0 && srcErr == io.EOF
	if final {
		if se.direction == StreamLegacy {
			return io.EOF
		}
		chunk = make([]byte, 16)
		binary.BigEndian.PutUint64(chunk[:8], se.frameIndex)
		binary.BigEndian.PutUint64(chunk[8:], se.total)
	} else if se.direction != StreamLegacy && (se.frameIndex == ^uint64(0) || se.total > ^uint64(0)-uint64(srcN)) {
		return fmt.Errorf("stream length overflow")
	} else {
		chunk = chunk[:srcN]
	}

	// encrypt the chunk with random nonce
	nonce := make([]byte, se.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// encrypt with GCM
	ciphertext := se.gcm.Seal(nil, nonce, chunk, streamAAD(se.requestID, se.direction, se.frameIndex, final))

	// XOR nonce with IV before transmission
	maskedNonce := make([]byte, len(nonce))
	copy(maskedNonce, nonce)
	xorWithIV(maskedNonce, se.iv)

	// create chunk: 4-byte length + masked_nonce + ciphertext
	chunkLen := uint32(len(maskedNonce) + len(ciphertext))
	chunkData := make([]byte, 4+len(maskedNonce)+len(ciphertext))
	if final {
		chunkLen |= finalFrameFlag
	}
	binary.BigEndian.PutUint32(chunkData[0:4], chunkLen)
	copy(chunkData[4:4+len(maskedNonce)], maskedNonce)
	copy(chunkData[4+len(maskedNonce):], ciphertext)

	se.buffer = chunkData
	se.index = 0
	if final {
		return io.EOF
	}
	if se.direction != StreamLegacy {
		se.frameIndex++
		se.total += uint64(srcN)
		return nil
	}

	return srcErr
}

func (se *streamEncryptor) Close() error {
	if closer, ok := any(se.src).(io.Closer); ok && closer != nil {
		return closer.Close()
	}
	return nil
}

// streamDecryptor implements true streaming decryption using AES-GCM
type streamDecryptor struct {
	src         io.Reader
	gcm         cipher.AEAD
	iv          [16]byte
	requestID   [16]byte
	direction   StreamDirection
	readBuffer  []byte // buffer for reading encrypted chunks
	plainBuffer []byte // buffer for decrypted data
	index       int
	finished    bool
	readErr     error
	frameIndex  uint64
	total       uint64
}

// DecryptStream creates a true streaming decryptor using AES-GCM.
// Protected streams must be read to EOF to verify the final frame; Close does not verify it.
// A read error is terminal for a protected stream.
func DecryptStream(src io.Reader, key, iv, requestID [16]byte, direction StreamDirection) (io.ReadCloser, error) {
	switch direction {
	case StreamLegacy, StreamRequest, StreamResponse:
	default:
		return nil, fmt.Errorf("invalid stream direction: %d", direction)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &streamDecryptor{
		src:         src,
		gcm:         gcm,
		iv:          iv,
		requestID:   requestID,
		direction:   direction,
		readBuffer:  make([]byte, 0),
		plainBuffer: make([]byte, 0),
		index:       0,
		finished:    false,
	}, nil
}

func (sd *streamDecryptor) Read(p []byte) (n int, err error) {
	if sd.readErr != nil {
		return 0, sd.readErr
	}

	if sd.finished && sd.index >= len(sd.plainBuffer) {
		return 0, io.EOF
	}

	// serve from plaintext buffer if available
	if sd.index < len(sd.plainBuffer) {
		n = copy(p, sd.plainBuffer[sd.index:])
		sd.index += n
		return n, nil
	}

	// need more data - read and decrypt next chunk
	if !sd.finished {
		if err := sd.decryptNextChunk(); err != nil {
			if err == io.EOF {
				sd.finished = true
				if sd.index < len(sd.plainBuffer) {
					n = copy(p, sd.plainBuffer[sd.index:])
					sd.index += n
					if sd.index >= len(sd.plainBuffer) {
						return n, io.EOF
					}
					return n, nil
				}
				return 0, io.EOF
			}
			if sd.direction != StreamLegacy {
				sd.readErr = err
			}
			return 0, err
		}

		// serve from newly decrypted buffer
		if sd.index < len(sd.plainBuffer) {
			n = copy(p, sd.plainBuffer[sd.index:])
			sd.index += n
			return n, nil
		}
	}

	return 0, nil
}

func (sd *streamDecryptor) decryptNextChunk() error {
	// read chunk length (4 bytes)
	lengthBuf := make([]byte, 4)
	_, err := io.ReadFull(sd.src, lengthBuf)
	if err == io.EOF {
		if sd.direction != StreamLegacy {
			return fmt.Errorf("missing final frame: %w", io.ErrUnexpectedEOF)
		}
		return io.EOF
	}
	if err != nil {
		return fmt.Errorf("failed to read chunk length: %w", err)
	}

	chunkLen := binary.BigEndian.Uint32(lengthBuf)
	final := chunkLen&finalFrameFlag != 0
	if final && sd.direction == StreamLegacy {
		return fmt.Errorf("invalid chunk length: %d", chunkLen)
	}
	chunkLen &^= finalFrameFlag
	if chunkLen < uint32(sd.gcm.NonceSize()+sd.gcm.Overhead()) || chunkLen > maxChunkSize {
		return fmt.Errorf("invalid chunk length: %d", chunkLen)
	}

	// read chunk data (nonce + ciphertext)
	chunkData := make([]byte, chunkLen)
	_, err = io.ReadFull(sd.src, chunkData)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return fmt.Errorf("failed to read chunk data: %w", err)
	}

	// extract masked nonce and ciphertext
	nonceSize := sd.gcm.NonceSize()
	if len(chunkData) < nonceSize {
		return fmt.Errorf("chunk too short for nonce")
	}

	maskedNonce := chunkData[:nonceSize]
	ciphertext := chunkData[nonceSize:]

	// restore original nonce by XOR with IV
	nonce := make([]byte, len(maskedNonce))
	copy(nonce, maskedNonce)
	xorWithIV(nonce, sd.iv)

	// decrypt with GCM using restored nonce
	plaintext, err := sd.gcm.Open(nil, nonce, ciphertext, streamAAD(sd.requestID, sd.direction, sd.frameIndex, final))
	if err != nil {
		return fmt.Errorf("GCM decryption failed: %w", err)
	}
	if final {
		if len(plaintext) != 16 || binary.BigEndian.Uint64(plaintext[:8]) != sd.frameIndex ||
			binary.BigEndian.Uint64(plaintext[8:]) != sd.total {
			return fmt.Errorf("invalid final frame")
		}
		var extra [1]byte
		if _, err := io.ReadFull(sd.src, extra[:]); err != io.EOF {
			if err == nil {
				return fmt.Errorf("extra data after final frame")
			}
			return fmt.Errorf("failed to read stream end: %w", err)
		}
		return io.EOF
	}
	if sd.direction != StreamLegacy {
		if len(plaintext) == 0 || sd.frameIndex == ^uint64(0) || sd.total > ^uint64(0)-uint64(len(plaintext)) {
			return fmt.Errorf("invalid data frame")
		}
		sd.frameIndex++
		sd.total += uint64(len(plaintext))
	}

	sd.plainBuffer = plaintext
	sd.index = 0

	return nil
}

func (sd *streamDecryptor) Close() error {
	if closer, ok := any(sd.src).(io.Closer); ok && closer != nil {
		return closer.Close()
	}
	return nil
}

func streamAAD(requestID [16]byte, direction StreamDirection, index uint64, final bool) []byte {
	if direction == StreamLegacy {
		return nil
	}
	var aad [27]byte
	aad[0] = sdkProtocolVersion
	aad[1] = byte(direction)
	copy(aad[2:18], requestID[:])
	binary.BigEndian.PutUint64(aad[18:26], index)
	if final {
		aad[26] = 1
	}
	return aad[:]
}

func xorWithIV(nonce []byte, iv [16]byte) {
	for i := 0; i < len(nonce) && i < 16; i++ {
		nonce[i] ^= iv[i]
	}
}
