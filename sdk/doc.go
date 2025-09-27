// Package sdk provides enterprise-grade Go SDK for secure integration with VXControl Cloud Platform APIs.
//
// The SDK implements a comprehensive security framework featuring memory-hard proof-of-work
// protection, end-to-end AES-GCM encryption, Ed25519 signatures, and automatic retry logic.
// It offers 24 strongly-typed function patterns covering all request/response scenarios
// with built-in connection pooling, HTTP/2 support, and streaming architecture for
// high-performance integration with cloud services.
//
// # Architecture Overview
//
// The SDK consists of several core components working together:
//
//   - Call Generation: 24 strongly-typed function patterns for all API scenarios
//   - Transport Layer: HTTP/2 optimized transport with connection pooling
//   - Security Engine: PoW challenges, AES-GCM encryption, Ed25519 signatures
//   - License System: Cryptographic license validation with tier enforcement
//   - Logging Framework: Structured logging with configurable levels and formats
//
// # Quick Start
//
// Basic SDK usage involves defining client structure, configuring endpoints, and building:
//
//	import "github.com/vxcontrol/cloud/sdk"
//
//	// Define client with typed API functions
//	type Client struct {
//	    CheckUpdates  sdk.CallReqBytesRespBytes    // JSON request/response
//	    DownloadFile  sdk.CallReqQueryRespWriter   // Query params, stream response
//	    UploadData    sdk.CallReqReaderRespBytes   // Stream request, JSON response
//	}
//
//	// Configure endpoints
//	configs := []sdk.CallConfig{
//	    {
//	        Calls:  []any{&client.CheckUpdates},
//	        Host:   "api.example.com",
//	        Name:   "check_updates",
//	        Path:   "/api/v1/updates/check",
//	        Method: sdk.CallMethodPOST,
//	    },
//	    {
//	        Calls:  []any{&client.DownloadFile},
//	        Host:   "files.example.com",
//	        Name:   "download_file",
//	        Path:   "/files/:id",
//	        Method: sdk.CallMethodGET,
//	    },
//	}
//
//	// Initialize SDK with options
//	err := sdk.Build(configs,
//	    sdk.WithClient("MyApp", "1.0.0"),
//	    sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),
//	    sdk.WithPowTimeout(30*time.Second),
//	    sdk.WithMaxRetries(3),
//	)
//	if err != nil {
//	    return err
//	}
//
//	// Use generated functions
//	updateData := []byte(`{"version": "1.0.0"}`)
//	response, err := client.CheckUpdates(context.Background(), updateData)
//
// # Call Function Types
//
// The SDK provides 24 strongly-typed function patterns covering all request/response scenarios:
//
// ## Basic Patterns (No Parameters)
//   - CallReqRespBytes: Simple GET endpoints returning JSON/binary data
//   - CallReqRespReader: File downloads or large data streams
//   - CallReqRespWriter: Direct output streaming to custom writers
//
// ## Query Parameter Patterns
//   - CallReqQueryRespBytes: Filtered queries (?limit=10&offset=20)
//   - CallReqQueryRespReader: Query-based file downloads
//   - CallReqQueryRespWriter: Query-based streaming responses
//
// ## Path Argument Patterns
//   - CallReqWithArgsRespBytes: RESTful resource access (/users/:id)
//   - CallReqWithArgsRespReader: Resource-specific file downloads
//   - CallReqWithArgsRespWriter: Resource-specific streaming
//
// ## Combined Patterns
//   - CallReqQueryWithArgsRespBytes: Path args + query params
//   - CallReqQueryWithArgsRespReader: Complex resource queries with streaming
//   - CallReqQueryWithArgsRespWriter: Advanced query scenarios
//
// ## Request Body Patterns
//   - CallReqBytesRespBytes: JSON API calls (POST/PUT with JSON payload)
//   - CallReqBytesRespReader: JSON request with streaming response
//   - CallReqBytesRespWriter: JSON request with writer output
//   - CallReqReaderRespBytes: File uploads with JSON response
//   - CallReqReaderRespReader: Stream-to-stream processing
//   - CallReqReaderRespWriter: Upload streaming with output streaming
//
// ## Advanced Combined Patterns
//   - CallReqBytesWithArgsRespBytes: RESTful updates with JSON payloads
//   - CallReqBytesWithArgsRespReader: Resource updates with streaming responses
//   - CallReqBytesWithArgsRespWriter: Resource updates with output streaming
//   - CallReqReaderWithArgsRespBytes: File uploads to specific resources
//   - CallReqReaderWithArgsRespReader: Stream processing with resource targeting
//   - CallReqReaderWithArgsRespWriter: Complex stream processing scenarios
//
// Example usage patterns:
//
//	// Simple JSON API
//	type API struct {
//	    GetUser    sdk.CallReqWithArgsRespBytes      // GET /users/:id
//	    UpdateUser sdk.CallReqBytesWithArgsRespBytes // PUT /users/:id + JSON body
//	    ListUsers  sdk.CallReqQueryRespBytes         // GET /users?limit=10
//	    UploadFile sdk.CallReqReaderRespBytes        // POST /upload + file stream
//	}
//
// # Security Framework
//
// ## Proof-of-Work Protection
//
// All API calls require solving memory-hard proof-of-work challenges:
//
//	// Automatic PoW solving process:
//	// 1. Request challenge ticket from server
//	// 2. Solve memory-hard puzzle (12-1024KB, variable AES iterations)
//	// 3. Include PoW signature with every API request
//	// 4. Server validates signature before processing
//
// PoW Algorithm Features:
//   - Memory-hard algorithm designed for GPU and FPGA resistance
//   - Dynamic difficulty scaling based on server load and license tier
//   - Variable parameters prevent hardware optimization (millions of combinations)
//   - Configurable timeout support for different hardware capabilities
//
// ## Cryptographic Protection
//
// Multi-layer encryption and signature system:
//
//	// Session Key Generation
//	sessionKey := [16]byte{} // AES-128 for request/response encryption
//	sessionIV := [16]byte{}  // Unique IV per request
//
//	// NaCL Key Exchange
//	clientPublic, clientPrivate := box.GenerateKey(rand.Reader)
//	sharedKey := box.Precompute(serverPublic, clientPrivate)
//
//	// Request Encryption
//	encryptedBody := EncryptStream(requestBody, sessionKey, sessionIV)
//
//	// Response Decryption
//	decryptedResponse := DecryptStream(responseBody, sessionKey, sessionIV)
//
// Cryptographic Features:
//   - AES-GCM streaming encryption with 1KB configurable chunks
//   - NaCL (Curve25519) key exchange for session key protection
//   - Ed25519 signatures for data integrity verification
//   - Forward secrecy through daily server key rotation
//
// ## License System
//
// Enterprise license validation with cryptographic verification:
//
//	// License introspection
//	info, err := sdk.IntrospectLicenseKey("XXXX-XXXX-XXXX-XXXX")
//	if err != nil {
//	    return err
//	}
//
//	// License properties
//	switch info.Type {
//	case sdk.LicenseExpireable:
//	    fmt.Printf("License expires: %v", info.ExpiredAt)
//	case sdk.LicensePerpetual:
//	    fmt.Println("Perpetual license")
//	}
//
//	// Feature flags
//	for i, flag := range info.Flags {
//	    fmt.Printf("Feature %d: %v", i, flag)
//	}
//
// License Features:
//   - Base32 encoding with validation checksums
//   - Cryptographic verification prevents tampering
//   - Expiration time validation with day-aligned precision
//   - Feature flags for tier-based access control
//   - PBKDF2-based fingerprinting for license correlation
//
// # Streaming Architecture
//
// ## Encryption Streaming
//
// Memory-efficient encryption for large data transfers:
//
//	// Encrypt large files without memory accumulation
//	file, err := os.Open("large-file.dat")
//	if err != nil {
//	    return err
//	}
//	defer file.Close()
//
//	// Create streaming encryptor
//	encryptedStream, err := sdk.EncryptStream(file, sessionKey, sessionIV)
//	if err != nil {
//	    return err
//	}
//	defer encryptedStream.Close()
//
//	// Stream encrypted data to destination
//	_, err = io.Copy(destination, encryptedStream)
//
// ## Decryption Streaming
//
// Streaming decryption with authentication validation:
//
//	// Decrypt response stream directly to file
//	outputFile, err := os.Create("decrypted-output.dat")
//	if err != nil {
//	    return err
//	}
//	defer outputFile.Close()
//
//	// Use DecryptProxy for direct streaming
//	err = sdk.DecryptProxy(encryptedResponse, outputFile, sessionKey, sessionIV)
//	if err != nil {
//	    return fmt.Errorf("decryption failed: %w", err)
//	}
//
// Streaming Features:
//   - Configurable chunk sizes (default 16KB, max 1MB)
//   - Per-chunk authentication prevents tampering
//   - Random nonces ensure GCM security properties
//   - No memory accumulation regardless of data size
//
// # Transport Layer
//
// ## HTTP/2 Optimization
//
// Production-optimized transport configuration:
//
//	transport := sdk.DefaultTransport()
//
//	// Customize for specific requirements
//	transport.MaxConnsPerHost = 500
//	transport.ResponseHeaderTimeout = 5 * time.Minute
//
//	err := sdk.Build(configs, sdk.WithTransport(transport))
//
// Transport Features:
//   - HTTP/2 with automatic protocol negotiation
//   - Connection pooling with configurable limits
//   - TLS 1.2+ with certificate validation
//   - Proxy support with environment variable detection
//
// ## Request Processing
//
// Complete request lifecycle with automatic security:
//
//	// SDK automatically handles:
//	// 1. PoW ticket acquisition
//	// 2. Challenge solving with configurable timeout
//	// 3. Request encryption and signing
//	// 4. Response decryption and validation
//	// 5. Error handling and retry logic
//
// Processing Features:
//   - Automatic retry logic for temporary errors
//   - Exponential backoff with server-provided timing
//   - Context cancellation support throughout
//   - Comprehensive error classification and handling
//
// # Error Handling
//
// ## Error Classification
//
// Structured error handling with automatic retry logic:
//
//	data, err := api.SomeCall(ctx, requestData)
//	if err != nil {
//	    switch {
//	    case errors.Is(err, sdk.ErrTooManyRequestsRPM):
//	        // Temporary: Will be retried automatically with server timing
//	        log.Info("Rate limited, retrying with backoff")
//
//	    case errors.Is(err, sdk.ErrForbidden):
//	        // Fatal: Check license validity or authentication
//	        log.Error("Access denied - verify license key")
//
//	    case errors.Is(err, sdk.ErrExperimentTimeout):
//	        // Temporary: Increase PoW timeout for slower systems
//	        log.Warn("PoW timeout - consider increasing timeout")
//
//	    default:
//	        log.Error("Unexpected error:", err)
//	    }
//	}
//
// ## Error Types
//
// Temporary Errors (automatically retried):
//   - ErrBadGateway: Server maintenance or overload
//   - ErrServerInternal: Temporary server issues
//   - ErrTooManyRequests: Standard rate limiting
//   - ErrTooManyRequestsRPM: Rate limiting with server-provided backoff
//   - ErrExperimentTimeout: PoW solving timeout (increase timeout or retry)
//
// Fatal Errors (no retry):
//   - ErrBadRequest: Invalid request format or parameters
//   - ErrForbidden: Invalid license or insufficient permissions
//   - ErrNotFound: Unknown endpoint or resource
//   - ErrTooManyRequestsRPH/RPD: Long-term rate limits exceeded
//   - ErrInvalidSignature: Cryptographic validation failure
//   - ErrReplayAttack: Security violation detected
//
// # Logging Integration
//
// ## Structured Logging
//
// Built-in logging framework with multiple adapters:
//
//	import "github.com/sirupsen/logrus"
//
//	// Use default logger
//	logger := sdk.DefaultLogger()
//	logger.SetLevel(sdk.LevelDebug)
//
//	// Or wrap existing logrus instance
//	logrusLogger := logrus.New()
//	logrusLogger.SetLevel(logrus.InfoLevel)
//	wrappedLogger := sdk.WrapLogrus(logrusLogger)
//
//	// Configure SDK with logger
//	err := sdk.Build(configs, sdk.WithLogger(wrappedLogger))
//
// ## Custom Logger Integration
//
// Implement Logger interface for custom logging backends:
//
//	type CustomLogger struct {
//	    // Your logging implementation
//	}
//
//	func (l *CustomLogger) SetLevel(level sdk.Level) { /* ... */ }
//	func (l *CustomLogger) GetLevel() sdk.Level { /* ... */ }
//	func (l *CustomLogger) WithError(err error) sdk.Entry { /* ... */ }
//	func (l *CustomLogger) WithField(key string, value any) sdk.Entry { /* ... */ }
//	// ... implement all Logger interface methods
//
// Logging Features:
//   - Contextual logging with fields and errors
//   - Configurable log levels (Trace, Debug, Info, Warn, Error, Fatal, Panic)
//   - Request tracing with timing and retry information
//   - Cryptographic operation logging for security auditing
//
// # Advanced Configuration
//
// ## Option Pattern
//
// Flexible SDK configuration using functional options:
//
//	err := sdk.Build(configs,
//	    // Required: Client identification
//	    sdk.WithClient("MySecurityTool", "2.1.0"),
//
//	    // Optional: License for premium features
//	    sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),
//
//	    // Optional: Performance tuning
//	    sdk.WithPowTimeout(60*time.Second),    // For slower systems
//	    sdk.WithMaxRetries(5),                 // For unreliable networks
//
//	    // Optional: Custom transport
//	    sdk.WithTransport(customTransport),
//
//	    // Optional: Structured logging
//	    sdk.WithLogger(customLogger),
//
//	    // Optional: Installation tracking
//	    sdk.WithInstallationID(installationUUID),
//	)
//
// ## Transport Customization
//
// Advanced HTTP transport configuration:
//
//	transport := sdk.DefaultTransport()
//
//	// Corporate proxy configuration
//	proxyURL, _ := url.Parse("http://proxy.company.com:8080")
//	transport.Proxy = http.ProxyURL(proxyURL)
//
//	// Custom TLS configuration
//	transport.TLSClientConfig = &tls.Config{
//	    MinVersion: tls.VersionTLS12,
//	    // Add custom certificate validation
//	}
//
//	// Performance tuning
//	transport.MaxConnsPerHost = 500
//	transport.ResponseHeaderTimeout = 5 * time.Minute
//
//	err := sdk.Build(configs, sdk.WithTransport(transport))
//
// # Path Templates
//
// ## RESTful Resource Patterns
//
// Automatic path argument substitution for RESTful APIs:
//
//	// Configure endpoint with path arguments
//	{
//	    Calls:  []any{&client.GetUserPosts},
//	    Path:   "/users/:userId/posts/:postId",  // Path template
//	    Method: sdk.CallMethodGET,
//	}
//
//	// Generated function signature includes args parameter
//	posts, err := client.GetUserPosts(ctx, []string{"123", "456"})
//	// Generates: GET /users/123/posts/456
//
// ## Query Parameter Generation
//
// Automatic query string generation from Go models:
//
//	type QueryParams struct {
//	    Limit  int    `url:"limit"`
//	    Offset int    `url:"offset"`
//	    Filter string `url:"filter"`
//	}
//
//	params := QueryParams{Limit: 10, Offset: 20, Filter: "active"}
//
//	// Convert to query map for SDK
//	queryMap := map[string]string{
//	    "limit":  "10",
//	    "offset": "20",
//	    "filter": "active",
//	}
//
//	results, err := client.SearchItems(ctx, queryMap)
//	// Generates: GET /search?limit=10&offset=20&filter=active
//
// # Performance Optimization
//
// ## Connection Management
//
// Optimized connection pooling and reuse:
//
//	// Default settings optimized for production
//	transport := sdk.DefaultTransport()
//	// MaxIdleConns: 50 (total idle connections)
//	// MaxIdleConnsPerHost: 10 (per-host idle connections)
//	// MaxConnsPerHost: 300 (max active connections per host)
//	// IdleConnTimeout: 90s (idle connection lifetime)
//
// ## Streaming Performance
//
// Memory-efficient processing for large data:
//
//	// Upload large file without loading into memory
//	file, err := os.Open("large-dataset.json")
//	if err != nil {
//	    return err
//	}
//	defer file.Close()
//
//	stat, _ := file.Stat()
//	response, err := client.ProcessLargeData(ctx, file, stat.Size())
//
//	// Download large response directly to file
//	outputFile, err := os.Create("processed-result.json")
//	if err != nil {
//	    return err
//	}
//	defer outputFile.Close()
//
//	err = client.GetLargeResult(ctx, queryParams, outputFile)
//
// # License Management
//
// ## License Validation
//
// Comprehensive license verification and introspection:
//
//	// Validate license before SDK initialization
//	licenseInfo, err := sdk.IntrospectLicenseKey("XXXX-XXXX-XXXX-XXXX")
//	if err != nil {
//	    return fmt.Errorf("invalid license: %w", err)
//	}
//
//	if !licenseInfo.IsValid() {
//	    return fmt.Errorf("license is invalid or expired")
//	}
//
//	// Check license type and permissions
//	switch licenseInfo.Type {
//	case sdk.LicenseExpireable:
//	    if licenseInfo.IsExpired() {
//	        return fmt.Errorf("license expired on %v", licenseInfo.ExpiredAt)
//	    }
//	    fmt.Printf("License valid until %v", licenseInfo.ExpiredAt)
//
//	case sdk.LicensePerpetual:
//	    fmt.Println("Perpetual license - no expiration")
//	}
//
//	// Feature flag checking
//	if licenseInfo.Flags[0] {
//	    fmt.Println("Premium feature enabled")
//	}
//
// ## License Encoding
//
// Base32 encoding with multiple validation layers:
//
//	// License key format: XXXX-XXXX-XXXX-XXXX
//
// # Production Deployment
//
// ## Configuration Best Practices
//
// Recommended production configuration:
//
//	// Production-ready SDK setup
//	configs := []sdk.CallConfig{
//	    // ... your API endpoints
//	}
//
//	err := sdk.Build(configs,
//	    // Required: Application identification
//	    sdk.WithClient("YourApp", appVersion),
//
//	    // Recommended: License for premium features
//	    sdk.WithLicenseKey(os.Getenv("VXCONTROL_LICENSE")),
//
//	    // Performance: Adjust for your hardware
//	    sdk.WithPowTimeout(45*time.Second),
//	    sdk.WithMaxRetries(5),
//
//	    // Monitoring: Production logging
//	    sdk.WithLogger(productionLogger),
//
//	    // Identity: Stable installation tracking
//	    sdk.WithInstallationID(persistentInstallationID),
//	)
//
// ## Monitoring Integration
//
// SDK provides comprehensive metrics for monitoring:
//
//	// Logger captures:
//	// - Request timing and retry information
//	// - PoW solving performance and difficulty
//	// - Cryptographic operation success/failure
//	// - Network errors and recovery attempts
//	// - License validation and tier information
//
// ## Error Recovery
//
// Robust error handling for production environments:
//
//	// Automatic recovery scenarios:
//	// - Network timeouts: Automatic retry with exponential backoff
//	// - Rate limiting: Server-provided backoff timing respected
//	// - PoW timeouts: Configurable timeout with retry support
//	// - Server overload: Automatic retry with jittered delays
//	// - License issues: Clear error messages for resolution
//
// # Thread Safety
//
// All SDK operations are thread-safe and optimized for concurrent usage:
//
//	// Single SDK instance can handle concurrent requests
//	var client Client
//	sdk.Build(configs, options...)
//
//	// Safe concurrent API calls
//	go func() {
//	    client.CheckUpdates(ctx1, data1)
//	}()
//	go func() {
//	    client.ReportError(ctx2, data2)
//	}()
//
// Concurrency Features:
//   - Thread-safe connection pooling
//   - Concurrent PoW solving (one per request)
//   - Shared session key generation
//   - Atomic retry counters and statistics
//
// Thread Safety Implementation:
//   - Immutable configuration after Build()
//   - Per-request context isolation
//   - Lock-free hot paths for performance
//   - Safe concurrent access to shared resources
package sdk
