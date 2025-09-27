package sdk

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

var (
	ErrInvalidRequest       = errors.New("invalid request")
	ErrInvalidConfiguration = errors.New("invalid configuration")
	ErrClientInternal       = errors.New("internal client error")

	// server errors - needs exact match with server response.code
	ErrBadGateway         = errors.New("bad gateway")           // temporary - can retry
	ErrServerInternal     = errors.New("internal server error") // temporary - can retry
	ErrBadRequest         = errors.New("bad request")           // fatal - don't retry
	ErrForbidden          = errors.New("forbidden")             // fatal - don't retry
	ErrNotFound           = errors.New("not found")             // fatal - don't retry
	ErrTooManyRequests    = errors.New("rate limit exceeded")   // temporary - can retry with default delay
	ErrTooManyRequestsRPM = errors.New("RPM limit exceeded")    // temporary - can retry with RestTime
	ErrTooManyRequestsRPH = errors.New("RPH limit exceeded")    // fatal - too long wait
	ErrTooManyRequestsRPD = errors.New("RPD limit exceeded")    // fatal - too long wait
	ErrInvalidSignature   = errors.New("invalid signature")     // fatal - crypto issue
	ErrReplayAttack       = errors.New("replay attack")         // fatal - security issue

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

// isTemporaryError determines if error is temporary and can be retried
func isTemporaryError(err error) bool {
	switch err {
	case ErrBadGateway, ErrServerInternal, ErrTooManyRequests, ErrTooManyRequestsRPM, ErrExperimentTimeout:
		return true
	default:
		return false
	}
}

// parseServerError parses server error response and returns appropriate error
func parseServerError(statusCode int, body []byte) error {
	if statusCode == 200 {
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
	case "NotFound":
		return ErrNotFound
	case "TooManyRequests":
		return ErrTooManyRequests
	case "TooManyRequestsRPM":
		return ErrTooManyRequestsRPM
	case "TooManyRequestsRPH":
		return ErrTooManyRequestsRPH
	case "TooManyRequestsRPD":
		return ErrTooManyRequestsRPD
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

func withServerPublicKey(serverPublicKey *[32]byte) Option {
	return func(s *sdk) {
		s.serverPublicKey = serverPublicKey
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
