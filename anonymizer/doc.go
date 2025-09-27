// Package anonymizer provides comprehensive PII and secrets masking for secure data transmission.
//
// The anonymizer package implements a high-performance data anonymization engine designed
// for protecting sensitive information before transmission to AI services or external systems.
// It features 300+ built-in patterns for automatic recognition and masking of credentials,
// personal information, network data, and cloud secrets while preserving data structure
// and analytical value.
//
// # Core Interface
//
// The main Anonymizer interface provides multiple ways to anonymize data:
//
//	type Anonymizer interface {
//	    Anonymize(any) error              // Deep anonymization of Go structures
//	    ReplaceString(string) string      // String-based pattern replacement
//	    ReplaceBytes([]byte) []byte       // Binary data anonymization
//	    WrapReader(io.Reader) io.Reader   // Streaming anonymization
//	}
//
// # Quick Start
//
// Basic usage involves creating an anonymizer and processing sensitive data:
//
//	import "github.com/vxcontrol/cloud/anonymizer"
//
//	// Create anonymizer with all built-in patterns
//	anon, err := anonymizer.NewAnonymizer(nil)
//	if err != nil {
//	    return err
//	}
//
//	// Anonymize complex data structures
//	sensitiveData := map[string]any{
//	    "user_email": "admin@company.com",
//	    "api_key": "sk-1234567890abcdef",
//	    "database_url": "postgres://user:password123@db.internal:5432/app",
//	    "server_ip": "192.168.1.100",
//	}
//
//	if err := anon.Anonymize(&sensitiveData); err != nil {
//	    return err
//	}
//	// Result: all sensitive patterns automatically masked
//
// # Pattern Recognition
//
// The anonymizer uses three comprehensive pattern databases:
//
// General Patterns (patterns/db/general.yml):
//   - Network data: IP addresses, domains, URLs, ports
//   - System data: File paths, configuration values, environment variables
//   - Application data: Session tokens, request IDs, temporary files
//
// PII Patterns (patterns/db/pii.yml):
//   - Contact information: Email addresses, phone numbers, postal addresses
//   - Identity data: Social Security Numbers, credit card numbers, personal IDs
//   - Biometric data: Fingerprints, facial recognition patterns
//
// Secrets Patterns (patterns/db/secrets.yml):
//   - API credentials: Keys, tokens, authentication headers
//   - Database credentials: Connection strings, passwords, certificates
//   - Cloud provider secrets: AWS/Azure/GCP access keys and service tokens
//
// Custom patterns can be added during initialization:
//
//	customPatterns := []patterns.Pattern{
//	    {
//	        Name:  "internal_token",
//	        Regex: `internal_[a-zA-Z0-9]{16}`,
//	    },
//	}
//	anon, err := anonymizer.NewAnonymizer(customPatterns)
//
// # Anonymization Methods
//
// ## Structural Anonymization
//
// Deep anonymization of Go structures using reflection:
//
//	type ErrorReport struct {
//	    Message    string            `json:"message"`
//	    Context    map[string]any    `json:"context"`
//	    UserEmail  string            `json:"user_email"`
//	    ConfigPath string            `json:"config_path" anonymizer:"skip"`
//	}
//
//	report := ErrorReport{
//	    Message: "Failed to connect to admin@company.com",
//	    Context: map[string]any{
//	        "api_key": "sk-abcd1234efgh5678",
//	        "server": "192.168.1.50",
//	    },
//	    UserEmail: "john.doe@company.com",
//	    ConfigPath: "/etc/app/config.yml", // Will be preserved due to "skip" tag
//	}
//
//	if err := anon.Anonymize(&report); err != nil {
//	    return err
//	}
//	// Result: emails and API keys masked, config path preserved
//
// ## String Anonymization
//
// Direct string processing for simple use cases:
//
//	original := "Connect to user admin@company.com with key sk-1234567890"
//	anonymized := anon.ReplaceString(original)
//	// Result: "Connect to user §**SSH Connection**§ with key §*****api_key*****§"
//
// ## Streaming Anonymization
//
// Memory-efficient processing for large data streams:
//
//	file, err := os.Open("large-log-file.txt")
//	if err != nil {
//	    return err
//	}
//	defer file.Close()
//
//	// Create anonymizing reader wrapper
//	anonymizedReader := anon.WrapReader(file)
//
//	// Process anonymized data without loading entire file into memory
//	scanner := bufio.NewScanner(anonymizedReader)
//	for scanner.Scan() {
//	    line := scanner.Text()
//	    // Each line has been anonymized during reading
//	    processAnonymizedLine(line)
//	}
//
// Streaming Features:
//   - Fixed memory footprint regardless of input size
//   - 8KB processing chunks with 1KB overlap for pattern boundaries
//   - High-performance throughput optimized for production workloads
//   - No temporary file creation or memory accumulation
//
// # Performance Characteristics
//
// Benchmark Results:
//   - String Processing: High-throughput pattern matching and replacement
//   - Structural Processing: Efficient reflection-based deep anonymization
//   - Streaming Processing: Memory-efficient large file handling
//   - Pattern Recognition: Optimized regex engine with experimental.Set
//
// Memory Usage:
//   - Fixed memory footprint for streaming operations
//   - Minimal overhead for structural anonymization
//   - Pattern cache optimization for repeated operations
//   - No memory leaks in long-running applications
//
// # Advanced Features
//
// ## Tag-Based Control
//
// Use struct tags to control anonymization behavior:
//
//	type Config struct {
//	    DatabaseURL string `json:"database_url"`                    // Will be anonymized
//	    SystemID    string `json:"system_id" anonymizer:"skip"`     // Will be preserved
//	    SecretKey   string `json:"secret_key"`                      // Will be anonymized
//	}
//
// ## Pattern Customization
//
// Extend built-in patterns with custom recognition rules:
//
//	customPatterns := []patterns.Pattern{
//	    {
//	        Name:  "custom_api_key",
//	        Regex: `cak_[a-zA-Z0-9]{32}`,
//	    },
//	    {
//	        Name:  "internal_user_id",
//	        Regex: `user_[0-9]{8}`,
//	    },
//	}
//
//	anon, err := anonymizer.NewAnonymizer(customPatterns)
//
// ## Cycle Detection
//
// Automatic handling of circular references in complex data structures:
//
//	type Node struct {
//	    Value string
//	    Next  *Node    // Circular references handled automatically
//	}
//
//	// Safe anonymization even with cycles
//	if err := anon.Anonymize(&node); err != nil {
//	    return err
//	}
//
// # Integration Examples
//
// ## Support Service Integration
//
//	// Anonymize error reports before AI analysis
//	errorDetails := map[string]any{
//	    "error_message": "Database connection failed for user admin@prod.com",
//	    "connection_string": "postgres://admin:secret@prod-db:5432/app",
//	    "client_ip": "10.0.1.50",
//	}
//
//	if err := anon.Anonymize(&errorDetails); err != nil {
//	    return fmt.Errorf("anonymization failed: %w", err)
//	}
//
//	// Safe to transmit to AI troubleshooting service
//	response, err := supportAPI.AnalyzeError(ctx, errorDetails)
//
// ## Log Processing Integration
//
//	// Anonymize log streams before storage or analysis
//	logFile, err := os.Open("/var/log/application.log")
//	if err != nil {
//	    return err
//	}
//	defer logFile.Close()
//
//	anonymizedLogs := anon.WrapReader(logFile)
//
//	// Write anonymized logs to secure storage
//	if _, err := io.Copy(secureStorage, anonymizedLogs); err != nil {
//	    return err
//	}
//
// # Security Considerations
//
// Data Protection:
//   - Irreversible anonymization process (original data cannot be recovered)
//   - Structure-preserving masking maintains data utility for analysis
//   - Comprehensive coverage prevents data leakage through overlooked patterns
//   - Tag-based control allows preservation of non-sensitive identifiers
//
// Performance Security:
//   - Memory-hard streaming prevents memory-based side-channel attacks
//   - Pattern compilation optimization prevents timing-based inference
//   - Cycle detection prevents infinite recursion-based DoS attacks
//   - Fixed memory footprint prevents memory exhaustion attacks
//
// # Thread Safety
//
// All anonymizer operations are thread-safe and can be used concurrently:
//
//	// Single anonymizer instance can be shared across goroutines
//	var anon anonymizer.Anonymizer
//
//	// Safe concurrent usage
//	go func() {
//	    anon.Anonymize(&data1)
//	}()
//	go func() {
//	    anon.ReplaceString(text2)
//	}()
//
// The underlying regex engine and pattern matching are optimized for concurrent access
// with minimal contention and high throughput.
package anonymizer
