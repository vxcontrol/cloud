package sdk

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
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
		err := parseServerError(tt.statusCode, nil, tt.body)
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

func TestParseServerError_Blocked(t *testing.T) {
	err := parseServerError(http.StatusForbidden, http.Header{}, []byte(`{"status":"error","code":"Blocked"}`))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("errors.Is(ErrBlocked) failed for %v", err)
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatal("firewall block must be distinct from a tier/auth Forbidden")
	}
}

func TestErrBlocked_IsFatal(t *testing.T) {
	if isTemporaryError(ErrBlocked) {
		t.Fatal("a firewall block must never be auto-retried")
	}
}

func TestParseServerError_BlockedDistinctFromQuotaBlocked(t *testing.T) {
	blocked := parseServerError(http.StatusForbidden, http.Header{}, []byte(`{"code":"Blocked"}`))
	quota := parseServerError(http.StatusForbidden, http.Header{}, []byte(`{"code":"QuotaBlocked"}`))
	if !errors.Is(blocked, ErrBlocked) {
		t.Fatalf("errors.Is(ErrBlocked) failed for %v", blocked)
	}
	if !errors.Is(quota, ErrQuotaBlocked) {
		t.Fatalf("errors.Is(ErrQuotaBlocked) failed for %v", quota)
	}
	if errors.Is(blocked, ErrQuotaBlocked) {
		t.Fatal("ErrBlocked must not satisfy ErrQuotaBlocked")
	}
}

func TestParseServerError_QuotaExceededDailyWithRetryAfter(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Retry-After", "3600")
	body := []byte(`{"status":"error","code":"QuotaExceededDaily"}`)

	err := parseServerError(http.StatusTooManyRequests, hdr, body)

	if !errors.Is(err, ErrQuotaExceededDaily) {
		t.Fatalf("errors.Is(ErrQuotaExceededDaily) failed for %v", err)
	}
	var qe *QuotaError
	if !errors.As(err, &qe) {
		t.Fatalf("errors.As(*QuotaError) failed for %v", err)
	}
	if qe.Scope != QuotaScopeDaily {
		t.Fatalf("scope = %q, want %q", qe.Scope, QuotaScopeDaily)
	}
	if qe.RetryAfter != time.Hour {
		t.Fatalf("retry-after = %s, want 1h", qe.RetryAfter)
	}
}

func TestParseServerError_QuotaBlockedNoRetry(t *testing.T) {
	body := []byte(`{"status":"error","code":"QuotaBlocked"}`)
	err := parseServerError(http.StatusForbidden, nil, body)

	if !errors.Is(err, ErrQuotaBlocked) {
		t.Fatalf("errors.Is(ErrQuotaBlocked) failed for %v", err)
	}
	var qe *QuotaError
	if !errors.As(err, &qe) {
		t.Fatalf("errors.As(*QuotaError) failed for %v", err)
	}
	if qe.RetryAfter != 0 {
		t.Fatalf("blocked retry-after = %s, want 0", qe.RetryAfter)
	}
	// blocked is fatal and never auto-retried
	if isTemporaryError(err) {
		t.Fatalf("QuotaBlocked must not be temporary")
	}
}

func TestParseServerError_QuotaMonthlyIsFatal(t *testing.T) {
	body := []byte(`{"status":"error","code":"QuotaExceededMonthly"}`)
	err := parseServerError(http.StatusTooManyRequests, nil, body)
	if !errors.Is(err, ErrQuotaExceededMonthly) {
		t.Fatalf("errors.Is(ErrQuotaExceededMonthly) failed for %v", err)
	}
	if isTemporaryError(err) {
		t.Fatalf("QuotaExceededMonthly must not be temporary (fatal, surfaced with cooldown)")
	}
}

func TestParseServerError_RateLimitWithRetryAfter(t *testing.T) {
	cases := []struct {
		code      string
		sentinel  error
		scope     RateLimitScope
		temporary bool
	}{
		{"TooManyRequests", ErrTooManyRequests, RateLimitScopeGeneral, true},
		{"TooManyRequestsRPM", ErrTooManyRequestsRPM, RateLimitScopeRPM, true},
		{"TooManyRequestsRPH", ErrTooManyRequestsRPH, RateLimitScopeRPH, false},
		{"TooManyRequestsRPD", ErrTooManyRequestsRPD, RateLimitScopeRPD, false},
	}
	for _, c := range cases {
		hdr := http.Header{}
		hdr.Set("Retry-After", "42")
		body := []byte(`{"status":"error","code":"` + c.code + `"}`)

		err := parseServerError(http.StatusTooManyRequests, hdr, body)

		if !errors.Is(err, c.sentinel) {
			t.Fatalf("%s: errors.Is(sentinel) failed for %v", c.code, err)
		}
		var rle *RateLimitError
		if !errors.As(err, &rle) {
			t.Fatalf("%s: errors.As(*RateLimitError) failed for %v", c.code, err)
		}
		if rle.Scope != c.scope {
			t.Fatalf("%s: scope = %q, want %q", c.code, rle.Scope, c.scope)
		}
		if rle.RetryAfter != 42*time.Second {
			t.Fatalf("%s: retry-after = %s, want 42s", c.code, rle.RetryAfter)
		}
		if isTemporaryError(err) != c.temporary {
			t.Fatalf("%s: isTemporaryError = %v, want %v", c.code, isTemporaryError(err), c.temporary)
		}
	}
}

func TestRateLimitError_NoHeader(t *testing.T) {
	// Without a Retry-After header the wrapper still classifies correctly.
	err := parseServerError(http.StatusTooManyRequests, nil, []byte(`{"code":"TooManyRequestsRPM"}`))
	var rle *RateLimitError
	if !errors.As(err, &rle) || rle.RetryAfter != 0 {
		t.Fatalf("expected *RateLimitError with zero RetryAfter, got %v", err)
	}
	if !isTemporaryError(err) {
		t.Fatalf("RPM should be temporary")
	}
}

func TestCheck_EmptyConfigs(t *testing.T) {
	results, err := Check(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected no top-level error for empty configs, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d entries", len(results))
	}
}

func TestCheck_InvalidConfigs(t *testing.T) {
	cases := []struct {
		name   string
		cfg    CallConfig
		wantIs error
	}{
		{
			name:   "missing host",
			cfg:    CallConfig{Name: "test-endpoint"},
			wantIs: ErrInvalidConfiguration,
		},
		{
			name:   "missing name",
			cfg:    CallConfig{Host: "api.example.com"},
			wantIs: ErrInvalidConfiguration,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// key in results is always cfg.Name (may be "")
			key := c.cfg.Name

			results, err := Check(context.Background(), []CallConfig{c.cfg})
			if err != nil {
				t.Fatalf("unexpected top-level error: %v", err)
			}

			status, ok := results[key]
			if !ok {
				t.Fatalf("no result for key %q (results: %v)", key, results)
			}
			if status.LastError() == nil {
				t.Error("expected per-endpoint error, got nil")
			}
			if !errors.Is(status.LastError(), c.wantIs) {
				t.Errorf("errors.Is(%v) failed; got: %v", c.wantIs, status.LastError())
			}
			// IsReachable works via pointer receiver
			if status.IsReachable() {
				t.Error("expected IsReachable=false for an invalid config")
			}
		})
	}
}

func TestRetryAfterOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want time.Duration
	}{
		// no hint: returns 0
		{"nil", nil, 0},
		{"plain ErrForbidden", ErrForbidden, 0},
		{"plain ErrBadRequest", ErrBadRequest, 0},
		{"plain ErrTooManyRequestsRPM bare sentinel", ErrTooManyRequestsRPM, 0},
		{"QuotaBlocked — never retry", &QuotaError{
			Err: ErrQuotaBlocked, Scope: QuotaScopeBlocked}, 0,
		},
		{"RateLimitError with zero RetryAfter", &RateLimitError{
			Err: ErrTooManyRequestsRPM, Scope: RateLimitScopeRPM, RetryAfter: 0}, 0,
		},

		// server hint carried in *RateLimitError
		{"RPM with RetryAfter", &RateLimitError{
			Err: ErrTooManyRequestsRPM, Scope: RateLimitScopeRPM, RetryAfter: 42 * time.Second}, 42 * time.Second,
		},
		{"RPH with RetryAfter", &RateLimitError{
			Err: ErrTooManyRequestsRPH, Scope: RateLimitScopeRPH, RetryAfter: 3300 * time.Second}, 3300 * time.Second,
		},
		{"RPD with RetryAfter", &RateLimitError{
			Err: ErrTooManyRequestsRPD, Scope: RateLimitScopeRPD, RetryAfter: 79200 * time.Second}, 79200 * time.Second,
		},
		{"general with RetryAfter", &RateLimitError{
			Err: ErrTooManyRequests, Scope: RateLimitScopeGeneral, RetryAfter: 5 * time.Second}, 5 * time.Second,
		},

		// server hint carried in *QuotaError
		{"QuotaExceededDaily with RetryAfter", &QuotaError{
			Err: ErrQuotaExceededDaily, Scope: QuotaScopeDaily, RetryAfter: time.Hour}, time.Hour,
		},
		{"QuotaExceededMonthly with RetryAfter", &QuotaError{
			Err: ErrQuotaExceededMonthly, Scope: QuotaScopeMonthly, RetryAfter: 720 * time.Hour}, 720 * time.Hour,
		},

		// wrapped via %w — errors.As still finds the inner type
		{"wrapped RateLimitError", fmt.Errorf("request failed: %w", &RateLimitError{
			Err: ErrTooManyRequestsRPM, Scope: RateLimitScopeRPM, RetryAfter: 7 * time.Second}), 7 * time.Second,
		},

		// context deadline joined with rate-limit error (our fix in calls.go)
		{"context deadline + RateLimitError", fmt.Errorf("%w: %w", context.DeadlineExceeded, &RateLimitError{
			Err: ErrTooManyRequestsRPM, Scope: RateLimitScopeRPM, RetryAfter: 55 * time.Second}), 55 * time.Second,
		},
		{"context deadline alone", fmt.Errorf("%w", context.DeadlineExceeded), 0},

		// parseServerError produces these via http.Header with Retry-After
		{"parseServerError RPM", parseServerError(429, func() http.Header {
			h := http.Header{}
			h.Set("Retry-After", "30")
			return h
		}(), []byte(`{"code":"TooManyRequestsRPM"}`)), 30 * time.Second},
		{"parseServerError QuotaDaily", parseServerError(429, func() http.Header {
			h := http.Header{}
			h.Set("Retry-After", "3600")
			return h
		}(), []byte(`{"code":"QuotaExceededDaily"}`)), time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RetryAfterOf(tt.err)
			if got != tt.want {
				t.Errorf("RetryAfterOf() = %v, want %v (err = %v)", got, tt.want, tt.err)
			}
		})
	}
}

func TestRetryAfterOf_UsagePattern(t *testing.T) {
	// Simulate what parseServerError returns for a real 429 response
	h := http.Header{}
	h.Set("Retry-After", "42")
	err := parseServerError(429, h, []byte(`{"code":"TooManyRequestsRPM"}`))

	// Caller does NOT need to know about *RateLimitError:
	wait := RetryAfterOf(err)
	if wait != 42*time.Second {
		t.Fatalf("expected 42s, got %v", wait)
	}

	// errors.Is classification still works normally
	if !errors.Is(err, ErrTooManyRequestsRPM) {
		t.Fatal("errors.Is check failed")
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
