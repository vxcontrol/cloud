package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMockServerBasic(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createServer()
	defer server.Close()

	// test basic header validation
	req, _ := http.NewRequest("GET", server.URL+defaultTicketPath+"test", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing headers, got %d", resp.StatusCode)
	}

	// test with proper basic headers
	req.Header.Set(headerXInstallationID, uuid.New().String())
	req.Header.Set(headerXRequestID, uuid.New().String())

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request with headers failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing X-Request-Key, got %d", resp.StatusCode)
	}
}

func TestGetTicketOnly(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createServer()
	defer server.Close()

	serverPublicKey := mockSrv.getPublicKey()

	err := Build([]CallConfig{}, withServerPublicKey(serverPublicKey))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	s := newTestSDK()
	s.serverPublicKey = serverPublicKey

	cfn := &callFunc{sdk: s}

	ctx := context.Background()
	cctx := &callContext{Context: ctx}
	cctx.reqTicketURL.Scheme = "http"
	cctx.reqTicketURL.Host = strings.TrimPrefix(server.URL, "http://")
	cctx.reqTicketURL.Path = defaultTicketPath + "valid_success"

	ticket, err := cfn.getTicket(cctx)
	if err != nil {
		t.Errorf("getTicket failed: %v", err)
		return
	}

	if ticket == "" {
		t.Error("getTicket returned empty ticket")
		return
	}

	testTicket, found := mockSrv.ticketsByName["valid_success"]
	if !found || testTicket.Ticket != ticket {
		t.Error("returned ticket does not match test data")
	}
}

func TestTicketSuccessScenario(t *testing.T) {
	mockSrv := newMockServer()

	successTicket, exists := mockSrv.ticketsByName["valid_success"]
	if !exists {
		t.Fatal("valid_success ticket not found in test data")
	}

	installationID, err := uuid.Parse(successTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	// test PoW solving directly without full protocol encryption complexity
	s := newTestSDK()
	s.installationID = [16]byte(installationID)
	s.powTimeout = 1 * time.Second

	cfn := &callFunc{sdk: s}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cctx := &callContext{Context: ctx}

	// test PoW solving (should complete quickly)
	ticketData, err := cfn.solvePoW(cctx, successTicket.Ticket)
	if err != nil {
		t.Errorf("Fast PoW solving failed: %v", err)
		return
	}

	// validate ticket data
	if ticketData.Key != successTicket.key {
		t.Error("Fast PoW solving returned invalid key")
		return
	}
	if ticketData.RequestID.String() != successTicket.RequestID {
		t.Error("Fast PoW solving returned invalid RequestID")
		return
	}
	if ticketData.Nonce != successTicket.nonce {
		t.Error("Fast PoW solving returned invalid Nonce")
		return
	}

	t.Log("Success scenario: Fast PoW solved successfully within 1s timeout")
}

func TestTicketTimeoutScenario(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	timeoutTicket, exists := mockSrv.ticketsByName["valid_timeout"]
	if !exists {
		t.Fatal("valid_timeout ticket not found in test data")
	}

	installationID, err := uuid.Parse(timeoutTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	var testCall CallReqRespBytes
	configs := []CallConfig{{
		Calls:  []any{&testCall},
		Host:   strings.TrimPrefix(server.URL, "https://"),
		Name:   "valid_timeout",
		Path:   "/api/v1/test",
		Method: CallMethodGET,
	}}

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(1*time.Second),
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err = testCall(ctx); err == nil {
		t.Error("timeout scenario should have failed")
		return
	}

	if !errors.Is(err, ErrExperimentTimeout) {
		t.Errorf("expected ErrExperimentTimeout, got: %v", err)
		return
	}

	t.Log("Timeout scenario completed as expected")
}

func TestSimpleResponseData(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	testTicket, exists := mockSrv.ticketsByName["valid_success"]
	if !exists {
		t.Fatal("valid_success ticket not found in test data")
	}

	installationID, err := uuid.Parse(testTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	if len(mockSrv.testData.ResponseData) == 0 {
		t.Skip("no response data found in test data")
	}

	responseData := mockSrv.testData.ResponseData[0]

	var testCall CallReqRespBytes
	configs := []CallConfig{{
		Calls:  []any{&testCall},
		Host:   strings.TrimPrefix(server.URL, "https://"),
		Name:   "valid_success",
		Path:   "/api/v1/call/" + responseData.Name,
		Method: CallMethodGET,
	}}

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(1*time.Second),
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	data, err := testCall(ctx)
	if err != nil {
		t.Error("response data scenario should have succeeded")
		return
	}

	if string(data) != responseData.Data {
		t.Errorf("response data mismatch: got %s, want %s", string(data), responseData.Data)
		return
	}

	t.Log("Response data scenario completed as expected")
}

func TestProtocolSecurity(t *testing.T) {
	t.Run("https_enforcement", func(t *testing.T) {
		mockSrv := newMockServer()
		server := mockSrv.createServer()
		defer server.Close()

		var testCall CallReqRespBytes
		configs := []CallConfig{{
			Calls:  []any{&testCall},
			Host:   strings.TrimPrefix(server.URL, "http://"),
			Name:   "valid_success",
			Path:   "/api/v1/test",
			Method: CallMethodGET,
		}}

		err := Build(configs, withServerPublicKey(mockSrv.getPublicKey()))
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		_, err = testCall(context.Background())
		if err == nil || !strings.Contains(err.Error(), "HTTP response to HTTPS client") {
			t.Error("protocol should enforce HTTPS")
		}
	})

	t.Run("error_parsing", func(t *testing.T) {
		tests := []struct {
			errorJSON string
			wantError error
		}{
			{`{"code":"TooManyRequestsRPM"}`, ErrTooManyRequestsRPM},
			{`{"code":"BadGateway"}`, ErrBadGateway},
			{`{"code":"Forbidden"}`, ErrForbidden},
		}

		for _, tt := range tests {
			err := parseServerError(429, []byte(tt.errorJSON))
			if err != tt.wantError {
				t.Errorf("parseServerError() = %v, want %v", err, tt.wantError)
			}
		}
	})
}

func TestProtocolUtilities(t *testing.T) {
	t.Run("server_public_key", func(t *testing.T) {
		key := getServerPublicKey()
		if key == nil || *key == [32]byte{} {
			t.Error("server public key invalid")
		}
	})

	t.Run("generate_iv", func(t *testing.T) {
		input := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		iv1 := generateIV(input)
		iv2 := generateIV(input)

		if iv1 != iv2 {
			t.Error("generateIV should be deterministic")
		}
	})

	t.Run("xor", func(t *testing.T) {
		dst := []byte{0xFF, 0x00, 0xFF, 0x00}
		op := []byte{0x0F, 0xF0, 0x0F, 0xF0}
		expected := []byte{0xF0, 0xF0, 0xF0, 0xF0}

		xor(dst, op)

		for i, b := range dst {
			if b != expected[i] {
				t.Errorf("xor result[%d] = %02x, want %02x", i, b, expected[i])
			}
		}
	})
}

// testCallSuite provides comprehensive testing for all call function types
type testCallSuite struct {
	// Basic patterns
	CallBytes  CallReqRespBytes
	CallReader CallReqRespReader
	CallWriter CallReqRespWriter

	// Query patterns
	CallQueryBytes  CallReqQueryRespBytes
	CallQueryReader CallReqQueryRespReader
	CallQueryWriter CallReqQueryRespWriter

	// Args patterns
	CallArgsBytes  CallReqWithArgsRespBytes
	CallArgsReader CallReqWithArgsRespReader
	CallArgsWriter CallReqWithArgsRespWriter

	// Query + Args patterns
	CallQueryArgsBytes  CallReqQueryWithArgsRespBytes
	CallQueryArgsReader CallReqQueryWithArgsRespReader
	CallQueryArgsWriter CallReqQueryWithArgsRespWriter

	// Body patterns
	CallBodyBytes  CallReqBytesRespBytes
	CallBodyReader CallReqBytesRespReader
	CallBodyWriter CallReqBytesRespWriter

	// Reader body patterns
	CallReaderBytes  CallReqReaderRespBytes
	CallReaderReader CallReqReaderRespReader
	CallReaderWriter CallReqReaderRespWriter

	// Body + Args patterns
	CallBodyArgsBytes  CallReqBytesWithArgsRespBytes
	CallBodyArgsReader CallReqBytesWithArgsRespReader
	CallBodyArgsWriter CallReqBytesWithArgsRespWriter

	// Reader + Args patterns
	CallReaderArgsBytes  CallReqReaderWithArgsRespBytes
	CallReaderArgsReader CallReqReaderWithArgsRespReader
	CallReaderArgsWriter CallReqReaderWithArgsRespWriter
}

func (s *testCallSuite) getCallConfigs(host, basePath string) []CallConfig {
	// All endpoints use the same valid ticket name to ensure they can get tickets
	ticketName := "valid_success"
	configs := []CallConfig{
		// Basic patterns
		{Calls: []any{&s.CallBytes}, Host: host, Name: ticketName, Path: basePath + "/basic", Method: CallMethodGET},
		{Calls: []any{&s.CallReader}, Host: host, Name: ticketName, Path: basePath + "/basic", Method: CallMethodGET},
		{Calls: []any{&s.CallWriter}, Host: host, Name: ticketName, Path: basePath + "/basic", Method: CallMethodGET},

		// Query patterns
		{Calls: []any{&s.CallQueryBytes}, Host: host, Name: ticketName, Path: basePath + "/query", Method: CallMethodGET},
		{Calls: []any{&s.CallQueryReader}, Host: host, Name: ticketName, Path: basePath + "/query", Method: CallMethodGET},
		{Calls: []any{&s.CallQueryWriter}, Host: host, Name: ticketName, Path: basePath + "/query", Method: CallMethodGET},

		// Args patterns
		{Calls: []any{&s.CallArgsBytes}, Host: host, Name: ticketName, Path: basePath + "/args/:id", Method: CallMethodGET},
		{Calls: []any{&s.CallArgsReader}, Host: host, Name: ticketName, Path: basePath + "/args/:id", Method: CallMethodGET},
		{Calls: []any{&s.CallArgsWriter}, Host: host, Name: ticketName, Path: basePath + "/args/:id", Method: CallMethodGET},

		// Query + Args patterns
		{Calls: []any{&s.CallQueryArgsBytes}, Host: host, Name: ticketName, Path: basePath + "/query/:id", Method: CallMethodGET},
		{Calls: []any{&s.CallQueryArgsReader}, Host: host, Name: ticketName, Path: basePath + "/query/:id", Method: CallMethodGET},
		{Calls: []any{&s.CallQueryArgsWriter}, Host: host, Name: ticketName, Path: basePath + "/query/:id", Method: CallMethodGET},

		// Body patterns
		{Calls: []any{&s.CallBodyBytes}, Host: host, Name: ticketName, Path: basePath + "/body", Method: CallMethodPOST},
		{Calls: []any{&s.CallBodyReader}, Host: host, Name: ticketName, Path: basePath + "/body", Method: CallMethodPOST},
		{Calls: []any{&s.CallBodyWriter}, Host: host, Name: ticketName, Path: basePath + "/body", Method: CallMethodPOST},

		// Reader body patterns
		{Calls: []any{&s.CallReaderBytes}, Host: host, Name: ticketName, Path: basePath + "/reader", Method: CallMethodPOST},
		{Calls: []any{&s.CallReaderReader}, Host: host, Name: ticketName, Path: basePath + "/reader", Method: CallMethodPOST},
		{Calls: []any{&s.CallReaderWriter}, Host: host, Name: ticketName, Path: basePath + "/reader", Method: CallMethodPOST},

		// Body + Args patterns
		{Calls: []any{&s.CallBodyArgsBytes}, Host: host, Name: ticketName, Path: basePath + "/body/:id", Method: CallMethodPOST},
		{Calls: []any{&s.CallBodyArgsReader}, Host: host, Name: ticketName, Path: basePath + "/body/:id", Method: CallMethodPOST},
		{Calls: []any{&s.CallBodyArgsWriter}, Host: host, Name: ticketName, Path: basePath + "/body/:id", Method: CallMethodPOST},

		// Reader + Args patterns
		{Calls: []any{&s.CallReaderArgsBytes}, Host: host, Name: ticketName, Path: basePath + "/reader/:id", Method: CallMethodPOST},
		{Calls: []any{&s.CallReaderArgsReader}, Host: host, Name: ticketName, Path: basePath + "/reader/:id", Method: CallMethodPOST},
		{Calls: []any{&s.CallReaderArgsWriter}, Host: host, Name: ticketName, Path: basePath + "/reader/:id", Method: CallMethodPOST},
	}

	return configs
}

func (s *testCallSuite) testCalls(ctx context.Context, expectedData string) error {
	testData := []byte("test request body")

	// Test basic patterns
	if data, err := s.CallBytes(ctx); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallBytes: unexpected response")
	}

	if reader, err := s.CallReader(ctx); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallReader: unexpected response")
		}
	}

	var buf bytes.Buffer
	if err := s.CallWriter(ctx, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallWriter: unexpected response")
	}

	// Test query patterns
	query := map[string]string{"limit": "10"}
	if data, err := s.CallQueryBytes(ctx, query); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallQueryBytes: unexpected response")
	}

	if reader, err := s.CallQueryReader(ctx, query); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallQueryReader: unexpected response")
		}
	}

	buf.Reset()
	if err := s.CallQueryWriter(ctx, query, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallQueryWriter: unexpected response")
	}

	// Test args patterns
	args := []string{"123"}
	if data, err := s.CallArgsBytes(ctx, args); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallArgsBytes: unexpected response")
	}

	if reader, err := s.CallArgsReader(ctx, args); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallArgsReader: unexpected response")
		}
	}

	buf.Reset()
	if err := s.CallArgsWriter(ctx, args, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallArgsWriter: unexpected response")
	}

	// Test query + args patterns
	if data, err := s.CallQueryArgsBytes(ctx, args, query); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallQueryArgsBytes: unexpected response")
	}

	if reader, err := s.CallQueryArgsReader(ctx, args, query); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallQueryArgsReader: unexpected response")
		}
	}

	buf.Reset()
	if err := s.CallQueryArgsWriter(ctx, args, query, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallQueryArgsWriter: unexpected response")
	}

	// Test body patterns
	if data, err := s.CallBodyBytes(ctx, testData); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallBodyBytes: unexpected response")
	}

	if reader, err := s.CallBodyReader(ctx, testData); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallBodyReader: unexpected response")
		}
	}

	buf.Reset()
	if err := s.CallBodyWriter(ctx, testData, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallBodyWriter: unexpected response")
	}

	// Test reader body patterns
	bodyReader := bytes.NewReader(testData)
	if data, err := s.CallReaderBytes(ctx, bodyReader, int64(len(testData))); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallReaderBytes: unexpected response")
	}

	bodyReader = bytes.NewReader(testData)
	if reader, err := s.CallReaderReader(ctx, bodyReader, int64(len(testData))); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallReaderReader: unexpected response")
		}
	}

	bodyReader = bytes.NewReader(testData)
	buf.Reset()
	if err := s.CallReaderWriter(ctx, bodyReader, int64(len(testData)), &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallReaderWriter: unexpected response")
	}

	// Test body + args patterns
	if data, err := s.CallBodyArgsBytes(ctx, args, testData); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallBodyArgsBytes: unexpected response")
	}

	if reader, err := s.CallBodyArgsReader(ctx, args, testData); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallBodyArgsReader: unexpected response")
		}
	}

	buf.Reset()
	if err := s.CallBodyArgsWriter(ctx, args, testData, &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallBodyArgsWriter: unexpected response")
	}

	// Test reader + args patterns
	bodyReader = bytes.NewReader(testData)
	if data, err := s.CallReaderArgsBytes(ctx, args, bodyReader, int64(len(testData))); err != nil {
		return err
	} else if string(data) != expectedData {
		return errors.New("CallReaderArgsBytes: unexpected response")
	}

	bodyReader = bytes.NewReader(testData)
	if reader, err := s.CallReaderArgsReader(ctx, args, bodyReader, int64(len(testData))); err != nil {
		return err
	} else {
		defer reader.Close()
		if data, err := io.ReadAll(reader); err != nil {
			return err
		} else if string(data) != expectedData {
			return errors.New("CallReaderArgsReader: unexpected response")
		}
	}

	bodyReader = bytes.NewReader(testData)
	buf.Reset()
	if err := s.CallReaderArgsWriter(ctx, args, bodyReader, int64(len(testData)), &buf); err != nil {
		return err
	} else if buf.String() != expectedData {
		return errors.New("CallReaderArgsWriter: unexpected response")
	}

	return nil
}

func TestAllCallTypes(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	testTicket, exists := mockSrv.ticketsByName["valid_success"]
	if !exists {
		t.Fatal("valid_success ticket not found in test data")
	}

	installationID, err := uuid.Parse(testTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	var callSuite testCallSuite
	configs := callSuite.getCallConfigs(
		strings.TrimPrefix(server.URL, "https://"),
		"/api/v1/call",
	)

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(1*time.Second),
		WithLicenseKey(encodeLicenseKey(testLicenseKey)),
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := callSuite.testCalls(ctx, testResponseData); err != nil {
		t.Errorf("testCalls failed: %v", err)
	}
}

func TestStreamingOperations(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	testTicket, exists := mockSrv.ticketsByName["valid_success"]
	if !exists {
		t.Fatal("valid_success ticket not found in test data")
	}

	installationID, err := uuid.Parse(testTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	var streamCall CallReqReaderRespReader
	configs := []CallConfig{{
		Calls:  []any{&streamCall},
		Host:   strings.TrimPrefix(server.URL, "https://"),
		Name:   "valid_success",
		Path:   "/api/v1/call/echo",
		Method: CallMethodPOST,
	}}

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(1*time.Second),
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// test streaming with large data
	largeData := make([]byte, 10*1024) // 10KB
	for i := range largeData {
		largeData[i] = byte('a' + (i % 26))
	}

	reader, err := streamCall(ctx, bytes.NewReader(largeData), int64(len(largeData)))
	if err != nil {
		t.Errorf("streaming call failed: %v", err)
		return
	}
	defer reader.Close()

	response, err := io.ReadAll(reader)
	if err != nil {
		t.Errorf("failed to read streaming response: %v", err)
		return
	}

	if string(response) != string(largeData) {
		t.Errorf("unexpected streaming response: got %d bytes, want %d bytes", len(response), len(largeData))
	}
}

func TestRetryLogic(t *testing.T) {
	tests := []struct {
		name          string
		errorType     error
		expectedRetry bool
		expectedDelay time.Duration
	}{
		{"bad_gateway", ErrBadGateway, true, 3 * time.Second},
		{"server_internal", ErrServerInternal, true, 3 * time.Second},
		{"too_many_requests", ErrTooManyRequests, true, 5 * time.Second},
		{"rpm_limit", ErrTooManyRequestsRPM, true, DefaultWaitTime},
		{"experiment_timeout", ErrExperimentTimeout, true, DefaultWaitTime},
		{"bad_request", ErrBadRequest, false, 0},
		{"forbidden", ErrForbidden, false, 0},
		{"not_found", ErrNotFound, false, 0},
	}

	cfn := &callFunc{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retry := isTemporaryError(tt.errorType)
			if retry != tt.expectedRetry {
				t.Errorf("isTemporaryError() = %v, want %v", retry, tt.expectedRetry)
			}

			if tt.expectedRetry {
				delay := cfn.calculateWaitTime(tt.errorType, nil)
				if tt.errorType == ErrTooManyRequestsRPM || tt.errorType == ErrExperimentTimeout {
					// these can vary based on context, just check it's reasonable
					if delay <= 0 || delay > DefaultWaitTime {
						t.Errorf("calculateWaitTime() = %v, expected <= %v", delay, DefaultWaitTime)
					}
				} else if delay != tt.expectedDelay {
					t.Errorf("calculateWaitTime() = %v, want %v", delay, tt.expectedDelay)
				}
			}
		})
	}
}

func TestErrorScenarios(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	testTicket, exists := mockSrv.ticketsByName["invalid_corrupted"]
	if !exists {
		t.Fatal("invalid_corrupted ticket not found in test data")
	}

	installationID, err := uuid.Parse(testTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	var testCall CallReqRespBytes
	configs := []CallConfig{{
		Calls:  []any{&testCall},
		Host:   strings.TrimPrefix(server.URL, "https://"),
		Name:   "invalid_corrupted",
		Path:   "/api/v1/call/test_json",
		Method: CallMethodGET,
	}}

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(100*time.Millisecond), // short timeout to force error
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = testCall(ctx)
	if err == nil {
		t.Error("expected error for corrupted ticket scenario")
		return
	}

	// should get PoW timeout or invalid format error
	if !errors.Is(err, ErrExperimentTimeout) && !strings.Contains(err.Error(), "PoW solving failed") {
		t.Errorf("unexpected error type: %v", err)
	}
}

func TestConcurrentCalls(t *testing.T) {
	mockSrv := newMockServer()
	server := mockSrv.createTLSServer()
	defer server.Close()

	testTicket, exists := mockSrv.ticketsByName["valid_success"]
	if !exists {
		t.Fatal("valid_success ticket not found in test data")
	}

	installationID, err := uuid.Parse(testTicket.InstallationID)
	if err != nil {
		t.Fatalf("invalid InstallationID: %v", err)
	}

	var testCall CallReqRespBytes
	configs := []CallConfig{{
		Calls:  []any{&testCall},
		Host:   strings.TrimPrefix(server.URL, "https://"),
		Name:   "valid_success",
		Path:   "/api/v1/call/test_json",
		Method: CallMethodGET,
	}}

	transport := DefaultTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	err = Build(configs,
		withServerPublicKey(mockSrv.getPublicKey()),
		WithInstallationID([16]byte(installationID)),
		WithPowTimeout(5*time.Second),
		WithTransport(transport))
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// test concurrent calls
	var wg sync.WaitGroup
	const numCalls = 20
	results := make(chan error, numCalls*10)

	for range numCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_, err := testCall(ctx)
				results <- err
			}
		}()
	}

	// wait for all calls to complete
	wg.Wait()

	// collect results
	for i := range numCalls {
		if err := <-results; err != nil {
			t.Errorf("concurrent call %d failed: %v", i, err)
		}
	}
}
