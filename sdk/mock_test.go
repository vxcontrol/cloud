package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

const testResponseData = `{"status":"success","message":"test completed"}`

type testData struct {
	Tickets      []testTicket   `json:"tickets"`
	Licenses     []testLicense  `json:"licenses"`
	ResponseData []testResponse `json:"response_data"`
}

type testTicket struct {
	Name           string   `json:"name"`
	Ticket         string   `json:"ticket"`
	RequestID      string   `json:"request_id"`
	SignatureNonce string   `json:"signature_nonce"`
	ServerKey      string   `json:"server_key"`
	InstallationID string   `json:"installation_id"`
	Valid          bool     `json:"valid"`
	id             [16]byte `json:"-"`
	key            [16]byte `json:"-"`
	nonce          [16]byte `json:"-"`
}

type testLicense struct {
	Name      string    `json:"name"`
	FP        string    `json:"fp"`
	Key       string    `json:"key"`
	Flags     [7]bool   `json:"flags"`
	ExpiredAt time.Time `json:"expired_at"`
	CreatedAt time.Time `json:"created_at"`
	Valid     bool      `json:"valid"`
}

type testResponse struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

func loadTestData() *testData {
	dataPath := filepath.Join("testdata", "data.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load test data: %v", err))
	}

	var td testData
	if err := json.Unmarshal(data, &td); err != nil {
		panic(fmt.Sprintf("failed to parse test data: %v", err))
	}

	for idx := range td.Tickets {
		ticket := td.Tickets[idx]

		idData, err := uuid.Parse(ticket.InstallationID)
		if err != nil {
			panic(fmt.Sprintf("failed to parse installation ID: %v", err))
		}
		td.Tickets[idx].id = [16]byte(idData)

		keyData, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(ticket.ServerKey)
		if err != nil {
			panic(fmt.Sprintf("failed to decode server key: %v", err))
		}
		if len(keyData) == 16 {
			td.Tickets[idx].key = [16]byte(keyData)
		}

		nonceData, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(ticket.SignatureNonce)
		if err != nil {
			panic(fmt.Sprintf("failed to decode signature nonce: %v", err))
		}
		if len(nonceData) == 16 {
			td.Tickets[idx].nonce = [16]byte(nonceData)
		}
	}

	return &td
}

func newTestSDK() sdk {
	var err error
	s := defaultSDK()

	s.clientPublicKey, s.clientPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate client keys: %v", err))
	}

	s.transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	s.client = &http.Client{
		Transport: s.transport,
	}

	return *s
}

// mockServer simulates real server middleware chain behavior
type mockServer struct {
	keys          *mockServerKeys
	testData      *testData
	ticketsByID   map[string]testTicket // RequestID -> ticket data
	ticketsByName map[string]testTicket // name -> ticket data for /api/v1/ticket/{name}
	licenses      map[[32]byte]bool
}

type mockServerKeys struct {
	public  *[32]byte
	private *[32]byte
}

func generateMockKeys() *mockServerKeys {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate server keys: %v", err))
	}

	return &mockServerKeys{
		public:  pub,
		private: priv,
	}
}

func newMockServer() *mockServer {
	testData := loadTestData()
	tickets := make(map[string]testTicket)
	ticketsByName := make(map[string]testTicket)

	for _, ticket := range testData.Tickets {
		if ticket.Valid && ticket.RequestID != "" {
			tickets[ticket.RequestID] = ticket
		}
		if ticket.Name != "" {
			ticketsByName[ticket.Name] = ticket
		}
	}

	return &mockServer{
		keys:          generateMockKeys(),
		testData:      testData,
		ticketsByID:   tickets,
		ticketsByName: ticketsByName,
		licenses:      make(map[[32]byte]bool),
	}
}

func (ms *mockServer) getPublicKey() *[32]byte {
	return ms.keys.public
}

func (ms *mockServer) getPrivateKey() *[32]byte {
	return ms.keys.private
}

func (ms *mockServer) createServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(ms.handler))
}

func (ms *mockServer) createTLSServer() *httptest.Server {
	server := httptest.NewTLSServer(http.HandlerFunc(ms.handler))
	// disable certificate verification for testing
	server.Client().Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return server
}

func (ms *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	if !ms.validateBasicHeaders(w, r) {
		return
	}

	if strings.HasPrefix(r.URL.Path, defaultTicketPath) {
		ms.handleTicketEndpoint(w, r)
		return
	}

	if !ms.validatePoWSignature(w, r) {
		return
	}

	ms.sendResponse(w, r)
}

func (ms *mockServer) validateBasicHeaders(w http.ResponseWriter, r *http.Request) bool {
	licenseKeyHeader := r.Header.Get(headerXLicenseKey)
	installationID := r.Header.Get(headerXInstallationID)
	requestID := r.Header.Get(headerXRequestID)

	if installationID == "" || requestID == "" {
		ms.sendError(w, ErrBadRequest)
		return false
	}

	if _, err := uuid.Parse(installationID); err != nil {
		ms.sendError(w, ErrBadRequest)
		return false
	}

	if _, err := uuid.Parse(requestID); err != nil {
		ms.sendError(w, ErrBadRequest)
		return false
	}

	if licenseKeyHeader == "" {
		return true
	}

	if !ms.validateLicenseKey(licenseKeyHeader) {
		ms.sendError(w, ErrBadRequest)
		return false
	}

	return true
}

func (ms *mockServer) validateLicenseKey(licenseKeyHeader string) bool {
	licenseKey, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(licenseKeyHeader)
	if err != nil {
		return false
	}

	if len(licenseKey) != 32 {
		return false
	}

	if _, exists := ms.licenses[[32]byte(licenseKey)]; exists {
		return false
	} else {
		ms.licenses[[32]byte(licenseKey)] = true
	}

	xor(licenseKey[16:32], licenseKey[0:16])

	return computeLicenseKeyFP(testLicenseKey) == [16]byte(licenseKey[16:32])
}

func (ms *mockServer) handleTicketEndpoint(w http.ResponseWriter, r *http.Request) {
	sessionKey, sessionIV, err := ms.validateRequestKey(r)
	if err != nil {
		ms.sendError(w, ErrBadRequest)
		return
	}

	ticket, exists := ms.ticketsByName[strings.TrimPrefix(r.URL.Path, defaultTicketPath)]
	if !exists {
		ms.sendError(w, ErrNotFound)
		return
	}

	ms.sendSuccess(w, []byte(ticket.Ticket), sessionKey, sessionIV)
}

func (ms *mockServer) validateRequestKey(r *http.Request) ([16]byte, [16]byte, error) {
	requestKeyHeader := r.Header.Get(headerXRequestKey)
	if requestKeyHeader == "" {
		return [16]byte{}, [16]byte{}, fmt.Errorf("missing X-Request-Key header")
	}

	decodedKeyHeader, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(requestKeyHeader)
	if err != nil || len(decodedKeyHeader) != 120 {
		return [16]byte{}, [16]byte{}, fmt.Errorf("invalid X-Request-Key header")
	}

	clientPublicKey := [32]byte(decodedKeyHeader[0:32])

	// restore original client public key
	installationID := r.Header.Get(headerXInstallationID)
	instID, _ := uuid.Parse(installationID)
	instIDBytes := [16]byte(instID)
	xor(clientPublicKey[0:16], instIDBytes[0:16])
	xor(clientPublicKey[16:32], instIDBytes[0:16])

	nonce := [24]byte(decodedKeyHeader[32:56])
	encryptedPayload := decodedKeyHeader[56:120]

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &clientPublicKey, ms.getPrivateKey())

	sessionData, ok := box.OpenAfterPrecomputation(nil, encryptedPayload, &nonce, &sharedKey)
	if !ok || len(sessionData) != 48 {
		return [16]byte{}, [16]byte{}, fmt.Errorf("failed to decrypt session data")
	}

	return [16]byte(sessionData[0:16]), [16]byte(sessionData[16:32]), nil
}

func (ms *mockServer) validatePoWSignature(w http.ResponseWriter, r *http.Request) bool {
	signHeader := r.Header.Get(headerXRequestSign)
	if signHeader == "" {
		ms.sendError(w, ErrForbidden)
		return false
	}

	requestID := r.Header.Get(headerXRequestID)
	if requestID == "" {
		ms.sendError(w, ErrForbidden)
		return false
	}

	signData, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(signHeader)
	if err != nil || len(signData) < 48 {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}

	ticket, exists := ms.ticketsByID[requestID]
	if !exists {
		ms.sendError(w, ErrForbidden)
		return false
	}

	xor(signData[0:16], ticket.id[0:16])
	if [16]byte(signData[0:16]) != ticket.nonce {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}

	sc, err := aes.NewCipher(ticket.key[0:16])
	if err != nil {
		ms.sendError(w, ErrServerInternal)
		return false
	}

	iv := generateIV(ticket.id)
	scb := cipher.NewCBCDecrypter(sc, iv[0:16])
	scb.CryptBlocks(signData[16:48], signData[16:48])

	version := signData[27]
	if version != sdkProtocolVersion {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}

	hash := binary.BigEndian.Uint32(signData[44:48])
	if hash != crc32.ChecksumIEEE(signData[16:44]) {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}

	timestamp := time.UnixMicro(int64(binary.BigEndian.Uint64(signData[28:36])))
	if timestamp.After(time.Now().UTC().Add(3 * time.Second)) {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}
	if timestamp.Before(time.Now().UTC().Add(-3 * time.Second)) {
		ms.sendError(w, ErrInvalidSignature)
		return false
	}

	return true
}

func (ms *mockServer) sendResponse(w http.ResponseWriter, r *http.Request) {
	ticket, exists := ms.ticketsByID[r.Header.Get(headerXRequestID)]
	if !exists {
		ms.sendError(w, ErrForbidden)
		return
	}

	// extract name after /api/v1/call/ and handle different endpoint patterns
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/call/")

	// handle different endpoint patterns for comprehensive testing
	var responseData string
	switch {
	case name == "test_json" || name == "echo" || strings.HasPrefix(name, "basic") ||
		strings.HasPrefix(name, "query") || strings.HasPrefix(name, "args") ||
		strings.HasPrefix(name, "body") || strings.HasPrefix(name, "reader"):
		// return standard test response for all test endpoints
		responseData = testResponseData
	default:
		// check if it matches any configured response data
		for _, response := range ms.testData.ResponseData {
			if response.Name == name {
				responseData = response.Data
				break
			}
		}
		if responseData == "" {
			ms.sendError(w, ErrNotFound)
			return
		}
	}

	// read request body if present (for body validation testing)
	if r.Body != nil {
		// we don't need to validate the body content, just consume it
		// to simulate server behavior except echo endpoint
		if name != "echo" {
			defer r.Body.Close()
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				ms.sendError(w, ErrServerInternal)
				return
			}
		} else {
			bodyReader, err := DecryptStream(r.Body, ticket.key, generateIV(ticket.id))
			if err != nil {
				ms.sendError(w, ErrServerInternal)
				return
			}
			defer bodyReader.Close()

			body, err := io.ReadAll(bodyReader)
			if err != nil {
				ms.sendError(w, ErrServerInternal)
				return
			}
			responseData = string(body)
		}
	}

	ms.sendSuccess(w, []byte(responseData), ticket.key, generateIV(ticket.id))
}

func (ms *mockServer) sendError(w http.ResponseWriter, err error) {
	var statusCode int
	var errorCode string

	switch err {
	case ErrBadRequest:
		statusCode = http.StatusBadRequest
		errorCode = "BadRequest"
	case ErrForbidden:
		statusCode = http.StatusForbidden
		errorCode = "Forbidden"
	case ErrTooManyRequestsRPM:
		statusCode = http.StatusTooManyRequests
		errorCode = "TooManyRequestsRPM"
	case ErrInvalidSignature:
		statusCode = http.StatusForbidden
		errorCode = "Forbidden"
	case ErrNotFound:
		statusCode = http.StatusNotFound
		errorCode = "NotFound"
	default:
		statusCode = http.StatusInternalServerError
		errorCode = "Internal"
	}

	response := map[string]string{
		"status": "error",
		"code":   errorCode,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		ms.sendError(w, ErrServerInternal)
		return
	}
}

func (ms *mockServer) sendSuccess(w http.ResponseWriter, data []byte, key, iv [16]byte) {
	encryptedData, err := EncryptBytes(data, key, iv)
	if err != nil {
		ms.sendError(w, ErrServerInternal)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(encryptedData)
}
