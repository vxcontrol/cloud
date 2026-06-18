package sdk

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

var (
	ErrInvalidRequest       = errors.New("invalid request")
	ErrInvalidConfiguration = errors.New("invalid configuration")
	ErrClientInternal       = errors.New("internal client error")

	// server errors - needs exact match with server response.code
	ErrBadGateway         = errors.New("bad gateway")                // temporary - can retry
	ErrServerInternal     = errors.New("internal server error")      // temporary - can retry
	ErrBadRequest         = errors.New("bad request")                // fatal - don't retry
	ErrForbidden          = errors.New("forbidden")                  // fatal - don't retry
	ErrBlocked            = errors.New("client temporarily blocked") // fatal - never retry
	ErrNotFound           = errors.New("not found")                  // fatal - don't retry
	ErrTooManyRequests    = errors.New("rate limit exceeded")        // temporary - can retry with default delay
	ErrTooManyRequestsRPM = errors.New("RPM limit exceeded")         // temporary - can retry with RestTime
	ErrTooManyRequestsRPH = errors.New("RPH limit exceeded")         // fatal - too long wait
	ErrTooManyRequestsRPD = errors.New("RPD limit exceeded")         // fatal - too long wait
	ErrInvalidSignature   = errors.New("invalid signature")          // fatal - crypto issue
	ErrReplayAttack       = errors.New("replay attack")              // fatal - security issue

	// daily/monthly quota errors - all fatal (no auto-retry).
	// QuotaExceeded* carry a Retry-After cooldown via *QuotaError (use errors.As).
	ErrQuotaBlocked         = errors.New("endpoint not available for this license tier") // fatal - never retry
	ErrQuotaExceededDaily   = errors.New("daily quota exceeded")                         // fatal - retry after reset
	ErrQuotaExceededMonthly = errors.New("monthly quota exceeded")                       // fatal - retry after reset

	// client errors
	ErrTicketFailed       = errors.New("failed to get ticket")
	ErrPoWFailed          = errors.New("proof of work failed")
	ErrCryptoFailed       = errors.New("cryptographic operation failed")
	ErrRequestFailed      = errors.New("request execution failed")
	ErrMaxRetriesExceeded = errors.New("maximum retry attempts exceeded")
)

// ServerErrorResponse represents server error response format
type ServerErrorResponse struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

// RateLimitScope identifies which rolling-window rate limit the proxy rejected.
type RateLimitScope string

const (
	RateLimitScopeGeneral RateLimitScope = "general" // no specific window
	RateLimitScopeRPM     RateLimitScope = "rpm"     // requests-per-minute
	RateLimitScopeRPH     RateLimitScope = "rph"     // requests-per-hour
	RateLimitScopeRPD     RateLimitScope = "rpd"     // requests-per-day
)

// QuotaScope identifies which server's quota was exhausted.
type QuotaScope string

const (
	QuotaScopeBlocked QuotaScope = "blocked" // tier has no access (never retry)
	QuotaScopeDaily   QuotaScope = "daily"   // daily quota exhausted
	QuotaScopeMonthly QuotaScope = "monthly" // monthly quota exhausted
)

// QuotaError wraps a quota sentinel with the server-advertised Retry-After cooldown.
// Use errors.Is for classification; errors.As to read Scope and RetryAfter.
type QuotaError struct {
	Err        error         // ErrQuotaBlocked | ErrQuotaExceededDaily | ErrQuotaExceededMonthly
	Scope      QuotaScope    // QuotaScopeBlocked | QuotaScopeDaily | QuotaScopeMonthly
	RetryAfter time.Duration // 0 for QuotaScopeBlocked (never retry)
}

func (e *QuotaError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s (retry after %s)", e.Err, e.RetryAfter)
	}
	return e.Err.Error()
}

func (e *QuotaError) Unwrap() error { return e.Err }

// RateLimitError wraps a rate-limit sentinel with the server-advertised Retry-After cooldown
// (seconds to the next rolling-window boundary).
// Use errors.Is for classification; errors.As to read Scope and RetryAfter.
type RateLimitError struct {
	Err        error          // ErrTooManyRequests | ErrTooManyRequestsRPM | RPH | RPD
	Scope      RateLimitScope // RateLimitScopeGeneral | RateLimitScopeRPM | RPH | RPD
	RetryAfter time.Duration  // 0 if server sent no Retry-After header
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s (retry after %s)", e.Err, e.RetryAfter)
	}
	return e.Err.Error()
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// RetryAfterOf extracts the server-suggested wait duration from err, or returns 0.
// Works through any error wrapping chain, including the context+rate-limit join.
func RetryAfterOf(err error) time.Duration {
	if err == nil {
		return 0
	}
	var rle *RateLimitError
	if errors.As(err, &rle) && rle.RetryAfter > 0 {
		return rle.RetryAfter
	}
	var qe *QuotaError
	if errors.As(err, &qe) && qe.RetryAfter > 0 {
		return qe.RetryAfter
	}
	return 0
}

// parseRetryAfter reads the Retry-After header (delay in seconds) as a duration.
func parseRetryAfter(header http.Header) time.Duration {
	if header == nil {
		return 0
	}
	v := strings.TrimSpace(header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// isTemporaryError reports whether err should be retried.
// Only general/RPM rate limits retry (RPH/RPD waits are too long).
// Bare ErrExperimentTimeout is temporary; wrapped form from solvePoW is fatal.
func isTemporaryError(err error) bool {
	var rle *RateLimitError
	if errors.As(err, &rle) {
		return errors.Is(rle.Err, ErrTooManyRequests) || errors.Is(rle.Err, ErrTooManyRequestsRPM)
	}

	switch err {
	case ErrBadGateway, ErrServerInternal, ErrTooManyRequests, ErrTooManyRequestsRPM, ErrExperimentTimeout:
		return true
	default:
		return false
	}
}

// isSuccessStatus reports whether code is a 2xx success. The proxy encrypts the body of
// every 2xx backend response, so the SDK decrypts and accepts all of them.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// parseServerError parses a server error response and returns the appropriate
// error. The response header is inspected for the Retry-After cooldown carried by
// quota-exceeded responses.
func parseServerError(statusCode int, header http.Header, body []byte) error {
	if isSuccessStatus(statusCode) {
		return nil
	}

	var serverErr ServerErrorResponse
	if err := json.Unmarshal(body, &serverErr); err != nil {
		return fmt.Errorf("HTTP %d: %w", statusCode, ErrRequestFailed)
	}

	switch serverErr.Code {
	case "BadGateway":
		return ErrBadGateway
	case "Internal":
		return ErrServerInternal
	case "BadRequest":
		return ErrBadRequest
	case "Forbidden":
		return ErrForbidden
	case "Blocked":
		return ErrBlocked
	case "NotFound":
		return ErrNotFound
	case "TooManyRequests":
		return &RateLimitError{Err: ErrTooManyRequests, Scope: RateLimitScopeGeneral, RetryAfter: parseRetryAfter(header)}
	case "TooManyRequestsRPM":
		return &RateLimitError{Err: ErrTooManyRequestsRPM, Scope: RateLimitScopeRPM, RetryAfter: parseRetryAfter(header)}
	case "TooManyRequestsRPH":
		return &RateLimitError{Err: ErrTooManyRequestsRPH, Scope: RateLimitScopeRPH, RetryAfter: parseRetryAfter(header)}
	case "TooManyRequestsRPD":
		return &RateLimitError{Err: ErrTooManyRequestsRPD, Scope: RateLimitScopeRPD, RetryAfter: parseRetryAfter(header)}
	case "QuotaBlocked":
		return &QuotaError{Err: ErrQuotaBlocked, Scope: QuotaScopeBlocked}
	case "QuotaExceededDaily":
		return &QuotaError{Err: ErrQuotaExceededDaily, Scope: QuotaScopeDaily, RetryAfter: parseRetryAfter(header)}
	case "QuotaExceededMonthly":
		return &QuotaError{Err: ErrQuotaExceededMonthly, Scope: QuotaScopeMonthly, RetryAfter: parseRetryAfter(header)}
	default:
		return fmt.Errorf("%s: %w", serverErr.Code, ErrRequestFailed)
	}
}

type Option func(*sdk)

func WithTransport(transport *http.Transport) Option {
	return func(s *sdk) {
		if transport != nil {
			s.transport = transport
		}
	}
}

func WithLogger(logger Logger) Option {
	return func(s *sdk) {
		if logger != nil {
			s.logger = logger
		}
	}
}

func WithClient(name string, version string) Option {
	return func(s *sdk) {
		s.clientName = name
		s.clientVersion = version
	}
}

func WithPowTimeout(timeout time.Duration) Option {
	return func(s *sdk) {
		s.powTimeout = timeout
	}
}

func WithMaxRetries(maxRetries int) Option {
	return func(s *sdk) {
		s.maxRetries = maxRetries
	}
}

func WithLicenseKey(key string) Option {
	return func(s *sdk) {
		info, err := IntrospectLicenseKey(key)
		if err == nil && info != nil && info.IsValid() {
			s.licenseKey = decodeLicenseKey(key)
			s.licenseFP = computeLicenseKeyFP(s.licenseKey)
		}
	}
}

func WithInstallationID(installationID [16]byte) Option {
	return func(s *sdk) {
		s.installationID = installationID
	}
}

func WithHeaders(headers map[string]string) Option {
	return func(s *sdk) {
		if s.extraHeaders == nil {
			s.extraHeaders = make(map[string]string, len(headers))
		}
		maps.Copy(s.extraHeaders, headers)
	}
}

func withServerPublicKey(serverPublicKey *[32]byte) Option {
	return func(s *sdk) {
		s.serverPublicKey = serverPublicKey
	}
}

func (s *sdk) applyExtraHeaders(req *http.Request) {
	for k, v := range s.extraHeaders {
		req.Header.Set(k, v)
	}
}

type sdk struct {
	clientName     string
	clientVersion  string
	client         *http.Client
	transport      *http.Transport
	logger         Logger
	powTimeout     time.Duration
	maxRetries     int
	licenseKey     [10]byte
	licenseFP      [16]byte
	installationID [16]byte
	extraHeaders   map[string]string

	// NaCL keypair for session key encryption
	clientPublicKey  *[32]byte
	clientPrivateKey *[32]byte
	serverPublicKey  *[32]byte
}

func defaultSDK() *sdk {
	installationID := [16]byte(uuid.New())

	return &sdk{
		clientName:      DefaultClientName,
		clientVersion:   DefaultClientVersion,
		transport:       DefaultTransport(),
		logger:          DefaultLogger(),
		powTimeout:      DefaultPowTimeout,
		maxRetries:      DefaultMaxRetries,
		installationID:  installationID,
		serverPublicKey: getServerPublicKey(),
	}
}

// Build initialises the SDK and generates typed call functions for each config entry.
// Must be called once before using any of the generated call functions.
func Build(configs []CallConfig, options ...Option) error {
	sdk := defaultSDK()
	for _, option := range options {
		option(sdk)
	}

	sdk.client = &http.Client{
		Transport: sdk.transport,
	}

	var err error
	if sdk.clientPublicKey, sdk.clientPrivateKey, err = box.GenerateKey(rand.Reader); err != nil {
		return fmt.Errorf("%w: failed to generate client NaCL keypair: %w", ErrClientInternal, err)
	}
	if sdk.clientPublicKey == nil || sdk.clientPrivateKey == nil {
		return fmt.Errorf("%w: failed to generate client NaCL keypair", ErrClientInternal)
	}

	for idx, cfg := range configs {
		if err := sdk.buildCall(cfg); err != nil {
			format := "failed to build call[%d] '%s': %w: %w"
			return fmt.Errorf(format, idx, cfg.Name, ErrInvalidConfiguration, err)
		}
	}

	return nil
}

// EndpointStatus is the read/re-probe interface returned by Check.
type EndpointStatus interface {
	LastError() error
	AllowedRPM() int
	IsReachable() bool
	Recheck(ctx context.Context) error
}

// endpointStatus implements EndpointStatus.
type endpointStatus struct {
	mu         sync.Mutex
	cfn        *callFunc // nil when config was invalid at Check time
	err        error
	allowedRPM int
}

func (es *endpointStatus) LastError() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.err
}

func (es *endpointStatus) AllowedRPM() int {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.allowedRPM
}

func (es *endpointStatus) IsReachable() bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.err == nil && es.allowedRPM > 0
}

// Recheck re-probes the endpoint and updates err and allowedRPM in place.
func (es *endpointStatus) Recheck(ctx context.Context) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if es.cfn == nil {
		return es.err
	}

	td, err := es.cfn.fetchTicketData(es.cfn.newProbeContext(ctx))
	es.allowedRPM = 0
	es.err = err
	if err == nil {
		es.allowedRPM = int(td.AllowedRPM)
	}

	return err
}

// EndpointStatuses maps endpoint Name → its probed status.
type EndpointStatuses map[string]EndpointStatus

// Check probes each endpoint by acquiring and solving a PoW ticket (no actual API call).
// Top-level error = SDK setup failure; per-endpoint failures are in EndpointStatus.LastError().
func Check(ctx context.Context, configs []CallConfig, options ...Option) (EndpointStatuses, error) {
	s := defaultSDK()
	for _, option := range options {
		option(s)
	}

	s.client = &http.Client{Transport: s.transport}

	var err error
	if s.clientPublicKey, s.clientPrivateKey, err = box.GenerateKey(rand.Reader); err != nil {
		return nil, fmt.Errorf("%w: failed to generate client NaCL keypair: %w", ErrClientInternal, err)
	}
	if s.clientPublicKey == nil || s.clientPrivateKey == nil {
		return nil, fmt.Errorf("%w: failed to generate client NaCL keypair", ErrClientInternal)
	}

	results := make(EndpointStatuses, len(configs))

	for _, cfg := range configs {
		cfn, buildErr := s.buildCheckCall(cfg)
		if buildErr != nil {
			results[cfg.Name] = &endpointStatus{err: fmt.Errorf("%w: %w", ErrInvalidConfiguration, buildErr)}
			continue
		}

		es := &endpointStatus{cfn: cfn}
		_ = es.Recheck(ctx)
		results[cfg.Name] = es
	}

	return results, nil
}

// buildCheckCall is a lightweight variant of buildCall: only host and name are validated.
func (s sdk) buildCheckCall(cfg CallConfig) (*callFunc, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	return &callFunc{sdk: s, cfg: cfg}, nil
}

func (s sdk) buildCall(cfg CallConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("host is required")
	}

	if cfg.Name == "" {
		return fmt.Errorf("name is required")
	}

	for _, call := range cfg.Calls {
		if err := checkCallType(call); err != nil {
			return err
		}
	}

	switch cfg.Method {
	case CallMethodGET, CallMethodDELETE:
		if slices.ContainsFunc(cfg.Calls, isCallWithBody) {
			return fmt.Errorf("call with body is not supported for GET and DELETE methods")
		}
	case CallMethodPUT, CallMethodPATCH:
		if !slices.ContainsFunc(cfg.Calls, isCallWithBody) {
			return fmt.Errorf("call with body is required for POST, PUT and PATCH methods")
		}
		fallthrough
	case CallMethodPOST:
		if slices.ContainsFunc(cfg.Calls, isCallWithQuery) {
			return fmt.Errorf("call with query is not supported for POST, PUT and PATCH methods")
		}
	default:
		return fmt.Errorf("invalid call method: '%s'", cfg.Method)
	}

	pathGenerator, argsNumber, err := s.parsePath(cfg.Path)
	if err != nil {
		return fmt.Errorf("invalid path: '%s': %w", cfg.Path, err)
	}

	for _, call := range cfg.Calls {
		if argsNumber > 0 && !isCallWithArgs(call) {
			return fmt.Errorf("call with position arguments must use variant call type with args")
		}
	}

	if err := fillCallFunc(cfg, s, pathGenerator); err != nil {
		return fmt.Errorf("failed to fill call func: %w", err)
	}

	return nil
}

// parsePath parses the path and returns the path template and position arguments number
func (s sdk) parsePath(p string) (pathGenerator, int, error) {
	parts := make([]string, 0)
	names := make([]string, 0)
	indices := make([]int, 0)
	for idx, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ":") {
			indices = append(indices, idx)
			names = append(names, strings.TrimPrefix(part, ":"))
		}
		parts = append(parts, part)
	}

	return func(args []string) (string, error) {
		if len(indices) == 0 {
			return p, nil
		}

		if len(args) == 0 {
			return "", fmt.Errorf("no arguments provided: must be %d: %v", len(indices), names)
		}
		if len(args) != len(indices) {
			return "", fmt.Errorf("invalid number of arguments: must be %d: %v", len(indices), names)
		}

		parts = slices.Clone(parts)
		for idx, arg := range args {
			parts[indices[idx]] = arg
		}

		return strings.Join(parts, "/"), nil
	}, len(indices), nil
}
