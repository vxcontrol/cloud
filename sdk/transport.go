package sdk

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

const (
	defaultScheme      = "https"
	defaultTicketPath  = "/api/v1/ticket/"
	sdkProtocolVersion = 2
)

const (
	headerXInstallationID = "X-Installation-ID"
	headerXRequestID      = "X-Request-ID"
	headerXRequestKey     = "X-Request-Key"
	headerXRequestSign    = "X-Request-Sign"
	headerXLicenseKey     = "X-License-Key"
)

func DefaultTransport() *http.Transport {
	// create dialer with optimal settings
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,  // connection timeout
		KeepAlive: 30 * time.Second, // keep-alive probe interval
	}

	// create transport with production-optimized settings for 2-minute requests
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,

		// connection pooling settings
		MaxIdleConns:        50,               // total max idle connections across all hosts
		MaxIdleConnsPerHost: 10,               // max idle connections per host
		MaxConnsPerHost:     300,              // max active connections per host
		IdleConnTimeout:     90 * time.Second, // how long idle connections stay open

		// timeout settings for backend API processing
		TLSHandshakeTimeout:   10 * time.Second, // TLS handshake timeout
		ResponseHeaderTimeout: 3 * time.Minute,  // time to wait for response headers (backend processing)
		ExpectContinueTimeout: 0,                // disable expect continue timeout

		// HTTP/2 and performance settings
		ForceAttemptHTTP2:  true,  // enable HTTP/2
		DisableCompression: false, // keep compression enabled
		DisableKeepAlives:  false, // keep-alive is essential

		// a TLS config of the transport's own: callers set their roots and verification on
		// it, so it is never nil; its protocols are left to the standard library, which
		// offers h2 only when it speaks HTTP/2 (not under GODEBUG=http2client=0)
		TLSClientConfig: &tls.Config{},
	}

	// HTTP/1.1 and HTTP/2 over TLS, by the HTTP/2 of the standard library, which is
	// patched with the toolchain
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Protocols.SetHTTP2(true)

	return transport
}

// ticketData contains parsed ticket information and session keys
type ticketData struct {
	Key        [16]byte
	IV         [16]byte
	RequestID  uuid.UUID
	Nonce      [16]byte
	AllowedRPM uint16
	WaitDelay  uint16
}

func (c *callFunc) getTicket(cctx *callContext) (string, error) {
	requestID := uuid.New()

	sessionKey := [16]byte{}
	sessionIV := [16]byte{}
	_, err := rand.Read(sessionKey[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate session key: %w", err)
	}
	_, err = rand.Read(sessionIV[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate session IV: %w", err)
	}

	requestKeyHeader, err := c.createRequestKeyHeader(sessionKey, sessionIV, 0)
	if err != nil {
		return "", fmt.Errorf("failed to create request key header: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(cctx, "GET", cctx.reqTicketURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create ticket request: %w", err)
	}

	c.sdk.applyExtraHeaders(httpReq)
	// the body of an answer is ciphertext, which does not compress, and a streamed
	// answer must reach the caller frame by frame: ask every hop for the bytes as they are
	httpReq.Header.Set("Accept-Encoding", "identity")
	httpReq.Header.Set(headerXInstallationID, uuid.UUID(c.sdk.installationID).String())
	httpReq.Header.Set(headerXRequestID, requestID.String())
	httpReq.Header.Set(headerXRequestKey, requestKeyHeader)
	httpReq.Header.Set("User-Agent", c.createUserAgentHeader())
	if c.sdk.licenseKey != emptyLicenseKey && c.sdk.licenseFP != emptyLicenseFP {
		licenseKeyHeader, err := c.createLicenseKeyHeader(sessionKey, sessionIV)
		if err != nil {
			return "", fmt.Errorf("failed to create license key header: %w", err)
		}
		httpReq.Header.Set(headerXLicenseKey, licenseKeyHeader)
	}

	resp, err := c.sdk.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ticket request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read ticket response: %w", err)
	}

	if !isSuccessStatus(resp.StatusCode) {
		return "", parseServerError(resp.StatusCode, resp.Header, body)
	}

	decryptedBody, err := DecryptBytes(body, sessionKey, sessionIV, [16]byte{}, StreamLegacy)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ticket response: %w", err)
	}

	return string(decryptedBody), nil
}

func (c *callFunc) solvePoW(cctx *callContext, ticket string) (*ticketData, error) {
	ctx, cancel := context.WithTimeout(cctx, c.sdk.powTimeout)
	defer cancel()

	result, err := transmute(ctx, ticket, c.sdk.installationID[:])
	cctx.restWaitTime = time.Duration(result.Recipe.RestTime) * time.Second
	if err != nil {
		return nil, fmt.Errorf("PoW solving failed: %w", err)
	}

	xor(result.Catalyst[0:16], c.sdk.installationID[0:16])

	td := &ticketData{
		Key:        [16]byte(result.Key),
		IV:         generateIV(c.sdk.installationID),
		RequestID:  uuid.UUID(result.Catalyst),
		Nonce:      [16]byte(result.Signature),
		AllowedRPM: result.Recipe.Capacity,
		WaitDelay:  result.Recipe.RestTime,
	}

	return td, nil
}

func requestSignatureHash(randomPadding []byte, method, requestURI string, nonce, installationID [16]byte) [4]byte {
	data := make([]byte, 0, len(randomPadding)+len(method)+len(requestURI)+32)
	data = append(data, randomPadding...)
	data = append(data, method...)
	data = append(data, requestURI...)
	data = append(data, nonce[:]...)
	data = append(data, installationID[:]...)

	sum := sha256.Sum256(data)
	var hash [4]byte
	for i, b := range sum {
		hash[i%4] ^= b
	}
	return hash
}

func (c *callFunc) createSignature(td *ticketData, method, requestURI string, contentLength int64) (string, error) {
	// maskedNonce[16] + requestHash[4] + randPadding[7] + version[1] + timestamp[8] + contentLength[8] + crc32[4]
	signData := make([]byte, 48)
	copy(signData[0:16], td.Nonce[0:16])
	xor(signData[0:16], c.sdk.installationID[0:16])

	_, err := rand.Read(signData[20:27])
	if err != nil {
		return "", fmt.Errorf("failed to generate random padding: %w", err)
	}
	hash := requestSignatureHash(signData[20:27], method, requestURI, td.Nonce, c.sdk.installationID)
	copy(signData[16:20], hash[:])
	signData[27] = sdkProtocolVersion

	binary.BigEndian.PutUint64(signData[28:36], uint64(time.Now().UTC().UnixMicro()))
	binary.BigEndian.PutUint64(signData[36:44], uint64(contentLength))

	checksum := crc32.ChecksumIEEE(signData[16:44])
	binary.BigEndian.PutUint32(signData[44:48], checksum)

	sc, err := aes.NewCipher(td.Key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	scb := cipher.NewCBCEncrypter(sc, td.IV[:])
	scb.CryptBlocks(signData[16:48], signData[16:48])

	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(signData), nil
}

func (c *callFunc) createRequestKeyHeader(sessionKey, sessionIV [16]byte, contentLength int64) (string, error) {
	var clientPublicKey [32]byte
	copy(clientPublicKey[0:32], c.sdk.clientPublicKey[0:32])
	xor(clientPublicKey[0:16], c.sdk.installationID[0:16])
	xor(clientPublicKey[16:32], c.sdk.installationID[0:16])

	var sharedKey [32]byte
	box.Precompute(&sharedKey, c.sdk.serverPublicKey, c.sdk.clientPrivateKey)

	// key[16] + iv[16] + timestamp[8] + contentLength[8]
	payload := make([]byte, 48)
	copy(payload[0:16], sessionKey[:])
	copy(payload[16:32], sessionIV[:])
	binary.BigEndian.PutUint64(payload[32:40], uint64(time.Now().UTC().UnixMicro()))
	binary.BigEndian.PutUint64(payload[40:48], uint64(contentLength))

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedPayload := box.SealAfterPrecomputation(nil, payload, &nonce, &sharedKey)

	// clientPublicKey[32] + nonce[24] + encryptedPayload[64]
	headerData := make([]byte, 120)
	copy(headerData[0:32], clientPublicKey[:])
	copy(headerData[32:56], nonce[:])
	copy(headerData[56:120], encryptedPayload)

	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(headerData), nil
}

func (c *callFunc) createLicenseKeyHeader(sessionKey, sessionIV [16]byte) (string, error) {
	payload := make([]byte, 32)
	copy(payload[6:16], c.sdk.licenseKey[0:10])
	copy(payload[16:32], c.sdk.licenseFP[0:16])

	if _, err := rand.Read(payload[0:6]); err != nil {
		return "", fmt.Errorf("failed to generate random padding: %w", err)
	}

	sc, err := aes.NewCipher(sessionKey[:])
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	scb := cipher.NewCBCEncrypter(sc, sessionIV[:])
	scb.CryptBlocks(payload[0:16], payload[0:16])
	xor(payload[16:32], payload[0:16])

	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(payload), nil
}

func (c *callFunc) createUserAgentHeader() string {
	userAgent := DefaultClientName + "/" + DefaultClientVersion
	if c.sdk.clientName != DefaultClientName || c.sdk.clientVersion != DefaultClientVersion {
		userAgent = c.sdk.clientName + "/" + c.sdk.clientVersion + " " + userAgent
	}

	return userAgent
}

// fetchTicketData acquires and solves a PoW ticket; shared by invokeRequest and Check.
func (c *callFunc) fetchTicketData(cctx *callContext) (*ticketData, error) {
	ticket, err := c.getTicket(cctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ticket: %w", err)
	}

	td, err := c.solvePoW(cctx, ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to solve PoW: %w", err)
	}

	return td, nil
}

// newProbeContext builds a callContext with only the ticket URL set (used by Check).
func (c *callFunc) newProbeContext(ctx context.Context) *callContext {
	return &callContext{
		Context: ctx,
		reqTicketURL: url.URL{
			Scheme: defaultScheme,
			Host:   c.cfg.Host,
			Path:   defaultTicketPath + c.cfg.Name,
		},
	}
}

// invokeRequest performs a complete PoW-protected request
func (c *callFunc) invokeRequest(cctx *callContext) error {
	// step 1: get ticket and solve PoW challenge
	td, err := c.fetchTicketData(cctx)
	if err != nil {
		return err
	}

	// step 2: prepare encrypted request
	var reqBody io.ReadCloser
	if cctx.reqBody != nil && cctx.reqBodyLength > 0 {
		plaintext, bodyErr := cctx.reqBody()
		if bodyErr != nil {
			return fmt.Errorf("failed to obtain request body: %w", bodyErr)
		}

		reqBody, err = EncryptStream(plaintext, td.Key, td.IV, [16]byte(td.RequestID), StreamRequest)
		if err != nil {
			return fmt.Errorf("failed to encrypt request body: %w", err)
		}
	}

	// step 3: create signature
	signature, err := c.createSignature(td, cctx.reqMethod, cctx.reqCallURL.String(), cctx.reqBodyLength)
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	// step 4: make HTTP target request
	httpReq, err := http.NewRequestWithContext(cctx, cctx.reqMethod, cctx.reqCallURL.String(), reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.sdk.applyExtraHeaders(httpReq)
	// the body of an answer is ciphertext, which does not compress, and a streamed
	// answer must reach the caller frame by frame: ask every hop for the bytes as they are
	httpReq.Header.Set("Accept-Encoding", "identity")
	httpReq.Header.Set(headerXInstallationID, uuid.UUID(c.sdk.installationID).String())
	httpReq.Header.Set(headerXRequestID, td.RequestID.String())
	httpReq.Header.Set(headerXRequestSign, signature)
	httpReq.Header.Set("User-Agent", c.createUserAgentHeader())
	if cctx.reqBody != nil && cctx.reqBodyLength > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if c.sdk.licenseKey != emptyLicenseKey && c.sdk.licenseFP != emptyLicenseFP {
		licenseKeyHeader, err := c.createLicenseKeyHeader(td.Key, td.IV)
		if err != nil {
			return fmt.Errorf("failed to create license key header: %w", err)
		}
		httpReq.Header.Set(headerXLicenseKey, licenseKeyHeader)
	}

	resp, err := c.sdk.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w: %w", ErrClientInternal, err)
	}
	if resp == nil {
		return fmt.Errorf("%w: unexpected response value", ErrClientInternal)
	}

	cctx.respStatusCode = resp.StatusCode
	if isSuccessStatus(cctx.respStatusCode) {
		// response body should be closed after decryption
		if cctx.respBodyWriter != nil {
			err = DecryptProxy(resp.Body, cctx.respBodyWriter, td.Key, td.IV, [16]byte(td.RequestID), StreamResponse)
		} else {
			cctx.respBodyReader, err = DecryptStream(resp.Body, td.Key, td.IV, [16]byte(td.RequestID), StreamResponse)
		}
		if err != nil {
			return fmt.Errorf("failed to decrypt response body: %w", err)
		}

		return nil
	}

	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	return parseServerError(cctx.respStatusCode, resp.Header, responseBody)
}

func getServerPublicKey() *[32]byte {
	rawPublic := [40]byte{
		0x8C, 0x00, 0x4F, 0xE0, 0xA4, 0xA5, 0x2C, 0x02,
		0xAD, 0xDC, 0x66, 0x4C, 0x52, 0x51, 0xA2, 0xC1,
		0x98, 0x7C, 0xF3, 0x7F, 0x7C, 0x04, 0x60, 0x44,
		0x73, 0x02, 0x2F, 0x89, 0x45, 0x2F, 0xCA, 0x06,
		0xEA, 0x9A, 0xFF, 0x68, 0x03, 0x40, 0x6B, 0x60,
	}

	result := [40]byte{rawPublic[0]>>4 | rawPublic[0]<<4}
	for i := 1; i < 40; i++ {
		result[i] = result[i-1] ^ rawPublic[i-1] ^ rawPublic[i]
	}

	key := [32]byte(result[result[37]:result[39]])
	return &key
}

func generateIV(init [16]byte) [16]byte {
	messSha256 := func(data [32]byte) [32]byte {
		result := data
		for range 7 {
			result = sha256.Sum256(result[:])
		}
		return result
	}

	doubled := [32]byte{}
	copy(doubled[0:16], init[:])
	copy(doubled[16:32], init[:])
	hash := messSha256(doubled)
	xor(hash[0:16], hash[16:32])

	return [16]byte(hash[0:16])
}

func xor(dst []byte, op []byte) {
	for i := range min(len(dst), len(op)) {
		dst[i] ^= op[i]
	}
}
