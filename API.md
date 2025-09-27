# VXControl Cloud Platform API Reference

## Overview

The VXControl Cloud Platform provides a comprehensive suite of cybersecurity services accessible through secure, PoW-protected APIs. The platform serves as the backbone for advanced security operations, threat intelligence, vulnerability management, and AI-powered security analysis.

## API Request Flow

```mermaid
sequenceDiagram
    participant App as Security Application
    participant SDK as VXControl SDK
    participant Anon as Data Anonymizer
    participant API as Cloud API
    participant PoW as PoW Service

    App->>SDK: Configure endpoints & Build()
    App->>SDK: Support API call request

    alt Support/AI Services
        SDK->>Anon: Anonymize sensitive data
        Anon-->>SDK: PII/secrets masked
        Note over Anon: Mandatory for AI requests<br/>300+ pattern recognition
    end

    SDK->>PoW: Request challenge ticket
    PoW-->>SDK: Challenge (nonce, difficulty)
    SDK->>SDK: Solve PoW puzzle (12-1024KB)

    SDK->>API: HTTP request with PoW signature
    Note over SDK,API: AES-GCM encrypted<br/>Ed25519 signed<br/>Anonymized data

    API->>API: Validate PoW & license
    API->>API: Process request
    API-->>SDK: Encrypted response

    SDK->>SDK: Decrypt & validate
    SDK-->>App: Typed response model

    Note over App,API: All data validated<br/>with Go models
```

### Technical Components

- **PoW System**: Memory-hard challenges (12-1024KB, 800-4000 AES iterations) with dynamic parameters for FPGA resistance
- **Data Anonymization**: Comprehensive PII/secrets masking before AI troubleshooting transmission
- **Cryptographic Validation**: Ed25519 signatures with SHA-512 hashing ensure data integrity
- **Type Safety**: 24 strongly-typed call patterns with built-in Go model validation
- **Streaming Architecture**: Memory-efficient processing with AES-GCM chunk encryption

## Authentication & Security

All API endpoints require:
- **PoW Challenge**: Memory-hard proof-of-work with more than 206M parameter combinations
- **License Validation**: Cryptographic license verification with tier-based access control
- **End-to-End Encryption**: AES-GCM streaming encryption with 1KB chunks
- **Forward Secrecy**: Daily server key rotation with deterministic derivation
- **Data Anonymization**: Mandatory PII/secrets masking for all AI troubleshooting requests

## API Services

| Service | Host | Endpoint | Method | Models | Status | Description |
|---------|------|----------|--------|--------|--------|-------------|
| **Update Service** | `update.pentagi.com` | `/api/v1/updates/check` | POST | [CheckUpdatesRequest](models/update.go) → [CheckUpdatesResponse](models/update.go) | ✓ Production | Check for component updates with changelogs |
| **Package Service** | `update.pentagi.com` | `/api/v1/packages/info` | GET | [PackageInfoRequest](models/package.go) → [PackageInfoResponse](models/package.go) | ✓ Production | Get package metadata and signatures |
| **Package Service** | `update.pentagi.com` | `/api/v1/packages/download` | GET | [DownloadPackageRequest](models/package.go) → Binary stream | ✓ Production | Download signed packages with validation |
| **Support Service** | `support.pentagi.com` | `/api/v1/errors/report` | POST | [SupportErrorRequest](models/support.go) → [SupportErrorResponse](models/support.go) | ✓ Production | Automated error reporting with data anonymization |
| **Support Service** | `support.pentagi.com` | `/api/v1/issues/create` | POST | [SupportIssueRequest](models/support.go) → [SupportIssueResponse](models/support.go) | ✓ Production | Create support issues with AI assistance and PII protection |
| **AI Investigation** | `support.pentagi.com` | `/api/v1/issues/investigate` | POST | [SupportInvestigationRequest](models/support.go) → [SupportInvestigationResponse](models/support.go) | ✓ Production | AI-powered troubleshooting with secure data handling |
| **Threat Intelligence** | `ti.vxcontrol.com` | `/api/v1/threats/query` | POST | ThreatQueryRequest → ThreatIntelResponse | 🚧 Development | Access real-time threat intelligence and IOC databases |
| **Vulnerability Assessment** | `ti.vxcontrol.com` | `/api/v1/vulns/scan` | POST | VulnScanRequest → VulnScanResponse | 🚧 Development | Vulnerability assessment and exploit database queries |
| **Knowledge Base** | `kb.vxcontrol.com` | `/api/v1/knowledge/search` | GET | Query params → KnowledgeResponse | 🚧 Development | Search cybersecurity knowledge base (MITRE ATT&CK, IOCs, vulnerabilities) |
| **Computational Resources** | `compute.pentagi.com` | `/api/v1/compute/submit` | POST | ComputeTaskRequest → ComputeTaskResponse | 🚧 Development | Submit intensive computational tasks (password cracking, analysis) |
| **Computational Resources** | `compute.pentagi.com` | `/api/v1/compute/results/:taskId` | GET | Path args → ComputeResultResponse | 🚧 Development | Retrieve computational task results |

## SDK Architecture

### Request Lifecycle

1. **SDK Configuration**: Define endpoints with `CallConfig` structs
2. **Function Generation**: SDK creates typed functions for each endpoint
3. **Data Anonymization**: Mandatory PII/secrets masking for support services
4. **PoW Challenge**: Automatic challenge solving before each request
5. **Request Signing**: Ed25519 signature generation with installation ID
6. **Encryption**: AES-GCM encryption of request/response bodies
7. **Type Validation**: Go models ensure data integrity throughout

### Core Components

- **Call Patterns**: 24 function types handle different request/response scenarios
- **Data Anonymizer**: Mandatory PII/secrets masking engine with 300+ pattern recognition
- **Transport Layer**: HTTP/2 with connection pooling and custom TLS configuration
- **Cryptographic Engine**: Ed25519 + AES-GCM for signatures and encryption
- **PoW Solver**: Memory-hard algorithm implementation with configurable timeout
- **License Manager**: Cryptographic license validation and tier enforcement

## Data Models

All API requests and responses use strongly-typed Go models with built-in validation.

### Available Models

- **Component Management**: [models/types.go](models/types.go) - Component types, statuses, OS/architecture enums
- **Update Service**: [models/update.go](models/update.go) - Update checking and component information
- **Package Service**: [models/package.go](models/package.go) - Package metadata, downloads, signatures
- **Support Service**: [models/support.go](models/support.go) - Error reporting, AI-powered issue creation and investigation
- **Signature Validation**: [models/signature.go](models/signature.go) - Ed25519 cryptographic signature validation
- **Data Anonymization**: [anonymizer/](anonymizer/) - PII/secrets masking with pattern recognition
- **System Utilities**: [system/](system/) - Cross-platform installation ID generation and machine identification

### Model Features

- **IValid Interface**: All models implement validation with comprehensive rules
- **IQuery Interface**: GET endpoints support automatic query parameter generation
- **Database Integration**: SQL driver support with Scan() and Value() methods
- **Type Safety**: Enum validation prevents invalid API calls

## SDK Call Patterns

The SDK provides 24 strongly-typed function patterns covering all request/response scenarios:

### Request Types
- **None**: Simple requests without parameters
- **Query**: URL query parameters (`?limit=10&offset=20`)
- **Args**: Path arguments (`/users/:id/posts/:postId`)
- **QueryWithArgs**: Combined path arguments and query parameters

### Request Body Types
- **None**: GET requests without body
- **Bytes**: `[]byte` request body for JSON/binary data
- **Reader**: `io.Reader` for streaming large uploads

### Response Types
- **Bytes**: `[]byte` response for JSON/binary data
- **Reader**: `io.Reader` for streaming large downloads
- **Writer**: `io.Writer` for direct output streaming

### Complete Pattern Matrix

| Request | Body | Response | Function Type | Use Case |
|---------|------|----------|---------------|----------|
| None | None | Bytes | `CallReqRespBytes` | Simple data retrieval |
| None | None | Reader | `CallReqRespReader` | Large file downloads |
| None | None | Writer | `CallReqRespWriter` | Direct output streaming |
| Query | None | Bytes | `CallReqQueryRespBytes` | Filtered data queries |
| Args | None | Bytes | `CallReqWithArgsRespBytes` | Resource-specific requests |
| None | Bytes | Bytes | `CallReqBytesRespBytes` | JSON API calls |
| None | Reader | Bytes | `CallReqReaderRespBytes` | Large file uploads |
| Args | Bytes | Bytes | `CallReqBytesWithArgsRespBytes` | Resource updates |

## Data Anonymization

### Mandatory PII Protection

All support and AI troubleshooting requests require data anonymization before transmission. The process is automatic and comprehensive:

**Protected Data Categories**:
- **Credentials**: API keys, tokens, passwords, database connections
- **PII**: Email addresses, phone numbers, SSNs, credit cards, personal identifiers
- **Network Data**: IP addresses, domains, URLs, network configurations
- **Cloud Secrets**: AWS/Azure/GCP credentials, service tokens, certificates
- **System Data**: File paths, configuration values, session tokens

**Anonymization Process**:
```go
// Before transmission to AI services
if err := anonymizer.Anonymize(&errorDetails); err != nil {
    return fmt.Errorf("failed to anonymize data: %w", err)
}
if err := anonymizer.Anonymize(&logs); err != nil {
    return fmt.Errorf("failed to anonymize logs: %w", err)
}
```

**Technical Features**:
- **Structure Preservation**: `admin@company.com` → `§**SSH Connection**§` (maintains analytical value)
- **Comprehensive Coverage**: Multiple pattern databases (General, PII, Secrets) with extensive pattern recognition
- **Reflection-Based**: Deep anonymization of complex Go structures and nested data
- **Performance Optimized**: High throughput for production workloads
- **Memory Efficient**: Fixed memory footprint with chunk-based streaming

## Rate Limiting & PoW Protection

The platform uses a sophisticated memory-hard proof-of-work system designed for GPU and FPGA resistance:

### PoW Algorithm Specifications

- **Memory Requirement**: Dynamic allocation with step variation (prevents FPGA optimization)
- **Sequential Operations**: Variable AES iterations with configurable key rotation intervals
- **Memory Access**: Cryptographically derived offsets with uniform distribution
- **Parameter Combinations**: Millions of configurations prevent hardware specialization
- **Performance**: Exponential difficulty scaling based on server load and threat level

### Dynamic Anti-FPGA Protection

```go
type TicketSettings struct {
    MemorySize        uint16  // Dynamic memory allocation
    AESIterations     uint16  // Variable iteration count
    KeyUpdateInterval uint8   // Configurable rotation frequency
    MemoryReads       uint16  // Memory access operations
    ChunkSize         uint8   // Variable chunk sizes
    RetryDelaySeconds uint16  // Client backoff time
    AllowedRPM        uint16  // Rate limit threshold
}
```

### Security Properties

- **Multi-Threading Resistance**: High difficulty levels provide significant delays even with multi-core attacks
- **GPU Resistance**: Memory-hard properties substantially reduce GPU optimization advantages
- **Daily Key Isolation**: Regular key rotation prevents long-term cryptanalysis attacks
- **Deterministic Synchronization**: All servers use identical daily keys through cryptographic derivation

## Error Handling

All endpoints return structured error responses:

```json
{
  "status": "error",
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Request rate limit exceeded",
  "details": {
    "current_usage": "exceeded",
    "limit": "tier_based",
    "reset_time": "2025-09-17T15:30:00Z"
  }
}
```

Common error codes:
- `INVALID_LICENSE`: License validation failed
- `POW_REQUIRED`: Proof-of-work challenge not solved
- `RATE_LIMIT_EXCEEDED`: Request rate limit exceeded
- `INSUFFICIENT_TIER`: Feature requires higher access tier
- `INVALID_REQUEST`: Malformed request data

## SDK Integration

Use the VXControl Cloud SDK for seamless integration with the platform:

```go
import (
    "github.com/vxcontrol/cloud/sdk"
    "github.com/vxcontrol/cloud/system"
)

// Configure endpoints for multiple services
configs := []sdk.CallConfig{
    {
        Calls:  []any{&checkUpdates},
        Host:   "update.pentagi.com",
        Name:   "check-updates",
        Path:   "/api/v1/updates/check",
        Method: sdk.CallMethodPOST,
    },
    {
        Calls:  []any{&reportError},
        Host:   "support.pentagi.com",
        Name:   "report-error",
        Path:   "/api/v1/errors/report",
        Method: sdk.CallMethodPOST,
    },
    {
        Calls:  []any{&queryThreats},
        Host:   "ti.vxcontrol.com",
        Name:   "threat-intelligence",
        Path:   "/api/v1/threats/query",
        Method: sdk.CallMethodPOST,
    },
}

// Build SDK with stable installation ID
err := sdk.Build(configs,
    sdk.WithClient("MySecTool", "1.0.0"),
    sdk.WithInstallationID(system.GetInstallationID()),
    sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),
)
```

### Working Examples

Production-ready examples are available in the [examples/](examples/) directory:

- **[examples/check-update/](examples/check-update/)** - Update service integration with component management
- **[examples/download-installer/](examples/download-installer/)** - Package downloads with streaming signature validation
- **[examples/report-errors/](examples/report-errors/)** - Support workflow with automated data anonymization

### Integration Example

```go
// Complete multi-service integration
type Client struct {
    UpdatesCheck     sdk.CallReqBytesRespBytes
    PackageDownload  sdk.CallReqQueryRespWriter
    ErrorReport      sdk.CallReqBytesRespBytes
    IssueInvestigate sdk.CallReqBytesRespReader  // Steam response support
}

configs := []sdk.CallConfig{
    {
        Calls:  []any{&client.UpdatesCheck},
        Host:   "update.pentagi.com",
        Name:   "updates_check",
        Path:   "/api/v1/updates/check",
        Method: sdk.CallMethodPOST,
    },
    {
        Calls:  []any{&client.ErrorReport},
        Host:   "support.pentagi.com",
        Name:   "error_report",
        Path:   "/api/v1/errors/report",
        Method: sdk.CallMethodPOST,
    },
}

// SDK automatically handles:
// - PoW ticket generation and solving
// - AES-GCM streaming encryption
// - Retry logic with exponential backoff

// Client must initialize anonymizer for support services:
// - Mandatory PII/secrets masking before AI transmission
// - Comprehensive pattern recognition (credentials, emails, IPs, etc.)
// - Structure-preserving anonymization maintains analytical value
anonymizer, _ := anonymizer.NewAnonymizer(nil)

err := sdk.Build(configs, options...)
```

## Performance Characteristics

### Architecture Benefits

**Server Performance**:
- **High-Throughput**: Optimized ticket generation with microsecond latency
- **Efficient Validation**: Millions of PoW validations per second
- **Scalable Proxy**: Throughput scales based on security validation requirements

**Client Performance**:
- **Dynamic Scaling**: PoW solving scales exponentially with difficulty for effective rate limiting
- **Optimized Processing**: High-performance path templates and function generation
- **Efficient Cryptography**: Sub-millisecond license and signature validation
- **Streaming Architecture**: Memory-efficient processing for large data transfers

**Memory Efficiency**:
- **Minimal Footprint**: Optimized memory usage per request and SDK instance
- **Dynamic Allocation**: PoW memory reused across multiple attempts
- **Streaming Processing**: Fixed memory usage regardless of data size
- **Connection Pooling**: Efficient transport layer resource management

## Production Deployment

### Security Requirements
- **TLS 1.2+**: All API communications encrypted
- **Certificate validation**: Verify server certificates in production
- **License management**: Secure storage of license keys
- **Signature verification**: Validate all downloaded packages

### Performance Tuning
- **PoW timeout**: Adjust based on hardware capabilities and security requirements
- **Connection pooling**: Optimized connection limits per host and total idle connections
- **HTTP/2 optimization**: Automatic protocol negotiation with multiplexing
- **Transport layer**: Configurable response timeouts for backend processing

### Monitoring Integration
- **Endpoint Statistics**: Per-endpoint request/error/timing metrics with atomic counters
- **PoW Performance**: Solve time distribution and retry rate monitoring
- **Cryptographic Operations**: Signature validation and encryption performance tracking
- **Backend Health**: Response time and error rate tracking for proxy services

## Proxy Architecture

The platform uses a dynamic reverse proxy for unified API management:

### Components
- **Protocol Proxy**: Acts as API gateway with integrated PoW validation
- **Dynamic Routing**: Configuration-driven endpoint generation
- **Middleware Chain**: Unified security validation across all backends
- **Statistics Collection**: Real-time performance and error metrics

### Benefits
- **Backend Isolation**: Services receive only validated, decrypted requests
- **Unified Security**: Single point for PoW validation and rate limiting
- **Transparent Encryption**: No security complexity for backend services
- **Health Monitoring**: Built-in `/api/health` endpoint for load balancers

## Technical Details

### Request Headers

All API requests include these headers:
```
X-Client-Name: YourApp/1.0.0
X-Installation-ID: stable-machine-uuid (from system.GetInstallationID())
X-Request-ID: challenge-request-id
X-Request-Sign: base64-encoded-pow-signature
X-License-Key: encrypted-license-key (optional)
Content-Type: application/json
```

### Installation ID Generation

The SDK uses cross-platform machine identification for stable installation tracking:

**Implementation**:
```go
// Automatic stable ID generation
installationID := system.GetInstallationID()
// Returns same UUID for same machine across application restarts
```

**Platform Support**:
- **Linux**: `/var/lib/dbus/machine-id` + SMBIOS data (when available)
- **macOS**: IOPlatformUUID from hardware registry
- **Windows**: Registry MachineGuid + system product information

**Features**:
- **Deterministic**: Same machine always generates same UUID
- **Cross-Platform**: Works on Linux, macOS, Windows
- **Fallback Logic**: Uses hostname when machine ID unavailable
- **UUID Format**: RFC4122 compliant UUID v3 (MD5-based)

### Response Format

Successful responses return JSON data:
```json
{
  "status": "success",
  "data": { /* model-specific response */ }
}
```

Error responses include structured details:
```json
{
  "status": "error",
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Request rate limit exceeded",
  "details": {
    "retry_after": "server_defined",
    "quota_reset": "2025-09-26T15:30:00Z"
  }
}
```

### Streaming Encryption

Request and response bodies use AES-GCM chunk encryption:

```
┌─────────────────┬───────┬─────────────────┐
│ Length (4 bytes)│ Nonce │ GCM Ciphertext  │
│ (Big Endian)    │       │ (Data + Auth)   │
└─────────────────┴───────┴─────────────────┘
```

**Features**:
- **Configurable Chunks**: Optimized chunk size for different workloads
- **Authenticated Encryption**: Tampering detection per chunk
- **Streaming Processing**: No memory accumulation for large files
- **Random Nonces**: Unique nonce per chunk for GCM security

### PoW Signature Format

**Validation Process**:
1. **Nonce Verification**: XOR unmask with installation ID
2. **Timestamp Check**: Configurable time window validation
3. **Content Length**: Match actual request body size
4. **Integrity Check**: CRC32 validation of signature payload
5. **AES Decryption**: CBC decrypt with PoW-derived key

### Client-Side Anonymization

All support and AI investigation requests undergo mandatory data anonymization before transmission:

**Implementation**:
```go
type Client struct {
    errorReport  sdk.CallReqBytesRespBytes
    issueCreate  sdk.CallReqBytesRespBytes
    anonymizer   anonymizer.Anonymizer  // required for support services
}

// Mandatory anonymization - requests fail if anonymization fails
func (c *Client) ReportError(ctx context.Context,
    component models.ComponentType, errorDetails map[string]any) error {

    if err := c.anonymizer.Anonymize(&errorDetails); err != nil {
        return fmt.Errorf("failed to anonymize error details: %w", err)
    }
    // ... proceed with anonymized data
}
```

**Pattern Recognition**:
- **Regex Engine**: go-re2 with experimental.Set for efficient multi-pattern matching
- **Pattern Database**: 3 categories (General, PII, Secrets) with comprehensive coverage
- **Structural Processing**: Reflection-based deep anonymization of complex Go structures
- **Tag-Based Control**: `anonymizer:"skip"` struct tags preserve critical system identifiers

**Anonymization Examples**:
```go
// before anonymization:
"message": "Failed to connect ssh://admin@company.com with API key sk-1234567890abcdef"
"database_url": "postgres://user:password123@db.internal:5432/app"
"target_host": "192.168.1.100"

// after anonymization:
"message": "Failed to connect §*SSH Connection*§ with API key §*****api_key*****§"
"database_url": "§*****Database Connection Generic*****§"
"target_host": "§***ipv4****§"
```

For complete implementation examples, see the [examples/](examples/) directory.
