package sdk

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

var testLicenseKey = [10]byte{5, 214, 101, 133, 220, 47, 241, 139, 53, 124}

func ExampleBuild() {
	var calls struct {
		DownloadInstaller CallReqRespWriter
		SendError         CallReqBytesRespBytes
	}
	callsConfig := []CallConfig{
		{
			Calls:  []any{&calls.DownloadInstaller},
			Host:   "localhost",
			Name:   "download-installer",
			Path:   "/api/v1/downloads/installer",
			Method: CallMethodGET,
		},
		{
			Calls:  []any{&calls.SendError},
			Host:   "localhost",
			Name:   "send-error",
			Path:   "/api/v1/support/errors",
			Method: CallMethodPOST,
		},
	}
	if err := Build(callsConfig); err != nil {
		panic(fmt.Sprintf("failed to build SDK: %v", err))
	}

	fmt.Println(calls.DownloadInstaller != nil)
	fmt.Println(calls.SendError != nil)
	// Output:
	// true
	// true
}

func TestBuildValidation(t *testing.T) {
	tests := []struct {
		config  []CallConfig
		wantErr bool
	}{
		{
			config: []CallConfig{{
				Calls:  []any{new(CallReqRespBytes)},
				Host:   "api.example.com",
				Name:   "test",
				Path:   "/api/v1/test",
				Method: CallMethodGET,
			}},
			wantErr: false,
		},
		{
			config: []CallConfig{{
				Calls:  []any{new(CallReqRespBytes)},
				Name:   "test",
				Path:   "/api/v1/test",
				Method: CallMethodGET,
			}},
			wantErr: true, // missing host
		},
		{
			config: []CallConfig{{
				Calls:  []any{new(CallReqBytesRespBytes)},
				Host:   "api.example.com",
				Name:   "test",
				Path:   "/api/v1/test",
				Method: CallMethodGET,
			}},
			wantErr: true, // body with GET
		},
	}

	for _, tt := range tests {
		err := Build(tt.config)
		if (err != nil) != tt.wantErr {
			t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
		}
	}
}

func TestServerErrorParsing(t *testing.T) {
	tests := []struct {
		statusCode int
		body       []byte
		wantErr    error
	}{
		{200, []byte("success"), nil},
		{502, []byte(`{"code":"BadGateway"}`), ErrBadGateway},
		{429, []byte(`{"code":"TooManyRequestsRPM"}`), ErrTooManyRequestsRPM},
		{500, []byte("invalid json"), ErrRequestFailed},
	}

	for _, tt := range tests {
		err := parseServerError(tt.statusCode, tt.body)
		if tt.wantErr == nil {
			if err != nil {
				t.Errorf("parseServerError(%d) error = %v, wantErr nil", tt.statusCode, err)
			}
		} else {
			if err == nil {
				t.Errorf("parseServerError(%d) error = nil, wantErr %v", tt.statusCode, tt.wantErr)
			}
		}
	}
}

func TestBuildCallValidation(t *testing.T) {
	s := defaultSDK()

	t.Run("method_body_compatibility", func(t *testing.T) {
		// GET/DELETE should not have body calls
		err := s.buildCall(CallConfig{
			Host:   "api.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodGET,
			Calls:  []any{new(CallReqBytesRespBytes)},
		})
		if err == nil {
			t.Error("expected error for GET with body")
		}

		// POST/PUT/PATCH should not have query calls
		err = s.buildCall(CallConfig{
			Host:   "api.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodPOST,
			Calls:  []any{new(CallReqQueryRespBytes)},
		})
		if err == nil {
			t.Error("expected error for POST with query")
		}
	})

	t.Run("path_args_validation", func(t *testing.T) {
		// Path with args should use WithArgs call types
		err := s.buildCall(CallConfig{
			Host:   "api.com",
			Name:   "test",
			Path:   "/users/:id",
			Method: CallMethodGET,
			Calls:  []any{new(CallReqRespBytes)},
		})
		if err == nil {
			t.Error("expected error for path args without WithArgs call type")
		}

		// Valid args configuration
		err = s.buildCall(CallConfig{
			Host:   "api.com",
			Name:   "test",
			Path:   "/users/:id",
			Method: CallMethodGET,
			Calls:  []any{new(CallReqWithArgsRespBytes)},
		})
		if err != nil {
			t.Errorf("valid args config failed: %v", err)
		}
	})
}

func TestSDKInitialization(t *testing.T) {
	sdk := defaultSDK()

	if sdk.clientName != DefaultClientName || sdk.clientVersion != DefaultClientVersion {
		t.Error("default client info incorrect")
	}

	if sdk.installationID == [16]byte{} {
		t.Error("installation ID not generated")
	}

	if sdk.clientPublicKey != nil || sdk.clientPrivateKey != nil {
		t.Error("NaCL keys should be nil before Build()")
	}

	// test options
	WithClient("test", "2.0")(sdk)
	if sdk.clientName != "test" {
		t.Errorf("WithClient failed: got %s", sdk.clientName)
	}

	WithMaxRetries(3)(sdk)
	if sdk.maxRetries != 3 {
		t.Errorf("WithMaxRetries failed: got %d", sdk.maxRetries)
	}
}

func TestPathTemplates(t *testing.T) {
	sdk := defaultSDK()

	t.Run("simple_path", func(t *testing.T) {
		generator, argsCount, err := sdk.parsePath("/api/v1/test")
		if err != nil {
			t.Fatalf("parsePath error: %v", err)
		}
		if argsCount != 0 {
			t.Errorf("expected 0 args, got %d", argsCount)
		}

		result, err := generator(nil)
		if err != nil {
			t.Errorf("generator error: %v", err)
		}
		if result != "/api/v1/test" {
			t.Errorf("expected /api/v1/test, got %s", result)
		}
	})

	t.Run("single_arg_path", func(t *testing.T) {
		generator, argsCount, err := sdk.parsePath("/api/v1/users/:id")
		if err != nil {
			t.Fatalf("parsePath error: %v", err)
		}
		if argsCount != 1 {
			t.Errorf("expected 1 arg, got %d", argsCount)
		}

		result, err := generator([]string{"123"})
		if err != nil {
			t.Errorf("generator error: %v", err)
		}
		if result != "/api/v1/users/123" {
			t.Errorf("expected /api/v1/users/123, got %s", result)
		}

		// Test error cases
		_, err = generator([]string{})
		if err == nil {
			t.Error("expected error for missing args")
		}

		_, err = generator([]string{"123", "456"})
		if err == nil {
			t.Error("expected error for too many args")
		}
	})

	t.Run("multiple_args_path", func(t *testing.T) {
		generator, argsCount, err := sdk.parsePath("/api/v1/users/:userId/posts/:postId")
		if err != nil {
			t.Fatalf("parsePath error: %v", err)
		}
		if argsCount != 2 {
			t.Errorf("expected 2 args, got %d", argsCount)
		}

		result, err := generator([]string{"user123", "post456"})
		if err != nil {
			t.Errorf("generator error: %v", err)
		}
		if result != "/api/v1/users/user123/posts/post456" {
			t.Errorf("expected /api/v1/users/user123/posts/post456, got %s", result)
		}
	})

	t.Run("complex_path", func(t *testing.T) {
		generator, argsCount, err := sdk.parsePath("/api/:version/users/:id/settings/:key")
		if err != nil {
			t.Fatalf("parsePath error: %v", err)
		}
		if argsCount != 3 {
			t.Errorf("expected 3 args, got %d", argsCount)
		}

		result, err := generator([]string{"v2", "user123", "theme"})
		if err != nil {
			t.Errorf("generator error: %v", err)
		}
		expected := "/api/v2/users/user123/settings/theme"
		if result != expected {
			t.Errorf("expected %s, got %s", expected, result)
		}
	})
}

func TestSDKOptions(t *testing.T) {
	t.Run("all_options", func(t *testing.T) {
		sdk := defaultSDK()

		// Test all option functions
		WithClient("TestApp", "1.2.3")(sdk)
		if sdk.clientName != "TestApp" || sdk.clientVersion != "1.2.3" {
			t.Error("WithClient option failed")
		}

		WithPowTimeout(45 * time.Second)(sdk)
		if sdk.powTimeout != 45*time.Second {
			t.Error("WithPowTimeout option failed")
		}

		WithMaxRetries(5)(sdk)
		if sdk.maxRetries != 5 {
			t.Error("WithMaxRetries option failed")
		}

		WithLicenseKey(encodeLicenseKey(testLicenseKey))(sdk)
		if sdk.licenseKey != testLicenseKey || sdk.licenseFP != computeLicenseKeyFP(testLicenseKey) {
			t.Error("WithLicenseKey option failed")
		}

		testID := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
		WithInstallationID(testID)(sdk)
		if sdk.installationID != testID {
			t.Error("WithInstallationID option failed")
		}

		transport := DefaultTransport()
		WithTransport(transport)(sdk)
		if sdk.transport != transport {
			t.Error("WithTransport option failed")
		}

		logger := DefaultLogger()
		WithLogger(logger)(sdk)
		if sdk.logger != logger {
			t.Error("WithLogger option failed")
		}
	})
}

func encodeLicenseKey(key [10]byte) string {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234679"
	expand := func(bkey [5]byte) [8]byte {
		result := [8]byte{}
		for idx := 4; idx >= 0; idx-- {
			result[4-idx+3] = bkey[idx]
		}
		pkey := binary.BigEndian.Uint64(result[:])
		for idx := range 8 {
			result[idx] = byte((pkey >> (5 * idx)) & 0x1F)
		}
		return result
	}

	result := [19]byte{}
	for idx, b := range expand([5]byte(key[0:5])) {
		result[idx+idx/4] = alphabet[b]
	}
	for idx, b := range expand([5]byte(key[5:10])) {
		result[idx+8+idx/4+2] = alphabet[b]
	}

	result[4] = '-'
	result[9] = '-'
	result[14] = '-'

	return string(result[:])
}
