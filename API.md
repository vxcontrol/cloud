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
    Note over SDK,API: AES-GCM encrypted<br/>AES-CBC signed<br/>Anonymized data

    API->>API: Validate PoW & license
    API->>API: Process request
    API-->>SDK: Encrypted response

    SDK->>SDK: Decrypt & validate
    SDK-->>App: Response body (bytes/reader/writer)
    App->>App: models.ParseEnvelope[T] unwraps {status,data}

    Note over App,API: All data validated<br/>with Go models
```

### Technical Components

- **PoW System**: Memory-hard challenges (12-1024KB, 800-4000 AES iterations) with dynamic parameters for FPGA resistance
- **Data Anonymization**: Comprehensive PII/secrets masking before AI troubleshooting transmission
- **Cryptographic Validation**: Ed25519 + SHA-512 signatures validate **package downloads**; AES-GCM authentication tags protect every request/response chunk
- **Type Safety**: 24 strongly-typed call patterns with built-in Go model validation
- **Streaming Architecture**: Memory-efficient processing with AES-GCM chunk encryption (16KB default)

## Authentication & Security

All API endpoints require:
- **PoW Challenge**: Memory-hard proof-of-work with more than 206M parameter combinations
- **License Validation**: Cryptographic license verification with tier-based access control
- **End-to-End Encryption**: AES-128-GCM streaming encryption with 16KB chunks
- **Forward Secrecy**: Daily server key rotation with deterministic derivation
- **Data Anonymization**: Mandatory PII/secrets masking for all AI troubleshooting requests

## Terms of Service Compliance

⚠️ **Important Legal Notice:** Access to VXControl Cloud Platform services requires compliance with [Terms of Service](TERMS_OF_SERVICE.md).

The platform provides access to sensitive cybersecurity capabilities including:
- **Threat Intelligence**: IOC/IOA databases and real-time threat analysis
- **Vulnerability Data**: CVE databases, exploit information, and security assessments  
- **AI-Powered Support**: Automated troubleshooting with access to system logs and configurations
- **Computational Resources**: Cloud-based security analysis and processing

**These services may ONLY be used for authorized, ethical, and legal cybersecurity purposes.**

Before using any API endpoints, ensure you understand and comply with all applicable terms and restrictions outlined in the [Terms of Service](TERMS_OF_SERVICE.md).

## API Services

| Service | Host | Endpoint | Method | Models | Status | Description |
|---------|------|----------|--------|--------|--------|-------------|
| **Update Service** | `update.pentagi.com` | `/api/v1/proxy/updates/check` | POST | [CheckUpdatesRequest](models/update.go) → [CheckUpdatesResponse](models/update.go) | ✓ Production | Check for component updates with changelogs |
| **Package Service** | `update.pentagi.com` | `/api/v1/proxy/packages/info` | GET | [PackageInfoRequest](models/package.go) → [PackageInfoResponse](models/package.go) | ✓ Production | Get package metadata and signatures |
| **Package Service** | `update.pentagi.com` | `/api/v1/proxy/packages/download` | GET | [DownloadPackageRequest](models/package.go) → Binary stream | ✓ Production | Download signed packages with validation |
| **Support Service** | `support.pentagi.com` | `/api/v1/proxy/errors/report` | POST | [SupportErrorRequest](models/support.go) → [SupportErrorResponse](models/support.go) | ✓ Production | Automated error reporting with data anonymization |
| **Support Service** | `support.pentagi.com` | `/api/v1/proxy/support/issues` | POST | [SupportIssueRequest](models/support.go) → [SupportIssueResponse](models/support.go) | ✓ Production | Create support issues with AI assistance and PII protection; `error_details` is read as a [SupportIssueDetails](#support-issue-format) document, and the request has [limits](#support-issue-format); endpoint code `support_issues` |
| **Support Service** | `support.pentagi.com` | `/api/v1/proxy/support/issues/:issueID/status` | GET | Path args → [SupportIssueStatusResponse](models/support.go) | ✓ Production | What runs on an issue — `processing`, `processed` or `answering` — and when its conversation last changed (see [Support Issue Status Format](#support-issue-status-format)); endpoint code `support_issue_status` |
| **Support Service** | `support.pentagi.com` | `/api/v1/proxy/support/issues/:issueID/messages` | GET | Path args → [SupportIssueMessagesResponse](models/support.go) | ✓ Production | The conversation of an issue as the server keeps it: the questions, the steps of the assistant and its answers, `[]` before the first question; endpoint code `support_issue_messages` |
| **AI Investigation** | `support.pentagi.com` | `/api/v1/proxy/support/investigate` | POST | [SupportInvestigationRequest](models/support.go) → [SupportInvestigationResponse](models/support.go) | ✓ Production | AI-powered troubleshooting with secure data handling: one question of the conversation of an issue, taken only while the issue is `processed`; endpoint code `support_investigate` |
| **Language Models** | `features.pentagi.com` | `/api/v1/proxy/llm/chat/completions` | POST | chat completion request of the OpenAI API → event stream (`chunk` or `result`) | ✓ Production | Chat completions of the agents of a licence with Cloud LLM; `model` names an agent |
| **Language Models** | `features.pentagi.com` | `/api/v1/proxy/llm/embeddings` | POST | embeddings request of the OpenAI API, `input` a string or an array of strings (token ids are refused) → event stream (`result`) | ✓ Production | Embeddings of the agents of a licence with Cloud LLM |
| **Language Models** | `features.pentagi.com` | `/api/v1/proxy/llm/models` | GET | → [LLMModelsResponse](models/llm.go) | ✓ Production | The agents a licence may name in `model`, with what each takes: the list object of the OpenAI API (`{"object":"list","data":[…]}`) in the envelope of every JSON answer, each agent a model object whose `id` is its name |
| **Licence Status** | `update.pentagi.com` | `/api/v1/proxy/license/status` | GET | → [LicenseStatusResponse](models/license.go) | ✓ Production | The tier of a licence, the features it enables and the share of each of its quotas of the support assistant and of Cloud LLM used today and this month, in whole percent (`-1` for no ceiling); endpoint code `license_status` |
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
5. **Request Signing**: AES-CBC signature (nonce + timestamp + content length + CRC32) with installation ID XOR-masking
6. **Key Exchange**: NaCL box (Curve25519) encrypts the ephemeral session key to the server
7. **Encryption**: AES-128-GCM streaming encryption of request/response bodies (16KB chunks)
8. **Type Validation**: Go models ensure data integrity throughout

### Core Components

- **Call Patterns**: 24 function types handle different request/response scenarios
- **Data Anonymizer**: Mandatory PII/secrets masking engine with 300+ pattern recognition
- **Transport Layer**: HTTP/2 with connection pooling and custom TLS configuration
- **Cryptographic Engine**: NaCL box (Curve25519) for session-key exchange + AES-128-GCM for body encryption + AES-128-CBC for PoW request signatures; Ed25519 + SHA-512 used only for package-integrity validation (`models/signature.go`)
- **PoW Solver**: Memory-hard algorithm implementation with configurable timeout
- **License Manager**: Cryptographic license validation and tier enforcement

## Data Models

All API requests and responses use strongly-typed Go models with built-in validation.

### Available Models

- **Component Management**: [models/types.go](models/types.go) - Component types, statuses, OS/architecture enums, and their mapping to product stacks
- **Artefact Delivery & Update Vocabulary**: [models/artefacts.go](models/artefacts.go), [models/answer.go](models/answer.go) - Whether a component is a pulled image or a downloaded file, and the shared vocabulary for update answers (`ComponentAction`, `ComponentReason`, `StackResolution`, `StackStatus`)
- **Update Service**: [models/update.go](models/update.go) - Update checking split by images/files, with a per-component action and the curated releases crossed on the way
- **Package Service**: [models/package.go](models/package.go) - Package metadata, downloads, signatures
- **Support Service**: [models/support.go](models/support.go) - Error reporting, AI-powered issue creation and investigation, including the streamed answer form, the status and the conversation of an issue (see [Support Issue Status Format](#support-issue-status-format)), the `SupportIssueDetails` document an issue is reported with and the limits of an issue (see [Support Issue Format](#support-issue-format))
- **Signature Validation**: [models/signature.go](models/signature.go) - Ed25519 cryptographic signature validation
- **Language Models**: [models/llm.go](models/llm.go) - The list of the agents of Cloud LLM (the list object of the OpenAI API, with the bounds and the `supported_parameters` of each agent) and the events of an LLM call (`chunk`, `result`); [llm/](llm/) is the client that speaks the OpenAI API over these calls
- **Licence Status**: [models/license.go](models/license.go) - The tier of a licence, the features it enables and the share of its quotas used, in whole percent (see [Licence Status Format](#licence-status-format))
- **Response Envelope**: [models/envelope.go](models/envelope.go) - `ParseEnvelope[T]` unwraps the `{"status":…,"data":…}` wrapper every JSON response arrives in
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

Every combination of request shape, request body and response shape that the SDK generates:

| Request | Body | Response | Function Type | Use Case |
|---------|------|----------|---------------|----------|
| None | None | Bytes | `CallReqRespBytes` | Simple data retrieval |
| None | None | Reader | `CallReqRespReader` | Large file downloads |
| None | None | Writer | `CallReqRespWriter` | Direct output streaming |
| Query | None | Bytes | `CallReqQueryRespBytes` | Filtered data queries |
| Query | None | Reader | `CallReqQueryRespReader` | Query-based downloads |
| Query | None | Writer | `CallReqQueryRespWriter` | Query-based streaming (`packages/download`) |
| Args | None | Bytes | `CallReqWithArgsRespBytes` | Resource-specific requests |
| Args | None | Reader | `CallReqWithArgsRespReader` | Resource-specific downloads |
| Args | None | Writer | `CallReqWithArgsRespWriter` | Resource-specific streaming |
| Query+Args | None | Bytes | `CallReqQueryWithArgsRespBytes` | Combined path + query lookups |
| Query+Args | None | Reader | `CallReqQueryWithArgsRespReader` | Combined lookups, streamed response |
| Query+Args | None | Writer | `CallReqQueryWithArgsRespWriter` | Combined lookups streamed to a writer |
| None | Bytes | Bytes | `CallReqBytesRespBytes` | JSON API calls |
| None | Bytes | Reader | `CallReqBytesRespReader` | JSON request, SSE/streamed response |
| None | Bytes | Writer | `CallReqBytesRespWriter` | JSON request, response streamed to a writer |
| None | Reader | Bytes | `CallReqReaderRespBytes` | Large file uploads |
| None | Reader | Reader | `CallReqReaderRespReader` | Stream-to-stream processing |
| None | Reader | Writer | `CallReqReaderRespWriter` | Streamed upload with streamed output |
| Args | Bytes | Bytes | `CallReqBytesWithArgsRespBytes` | Resource updates |
| Args | Bytes | Reader | `CallReqBytesWithArgsRespReader` | Resource updates with a streamed response |
| Args | Bytes | Writer | `CallReqBytesWithArgsRespWriter` | Resource updates streamed to a writer |
| Args | Reader | Bytes | `CallReqReaderWithArgsRespBytes` | Streamed uploads to a specific resource |
| Args | Reader | Reader | `CallReqReaderWithArgsRespReader` | Resource-targeted stream processing |
| Args | Reader | Writer | `CallReqReaderWithArgsRespWriter` | Resource-targeted streamed upload/download |

Only `Bytes`-body calls are retried automatically on a temporary failure (see [Error Handling](#error-handling));
a `Reader`-body call cannot be rewound after a failed attempt, so the SDK forces a single attempt for it.

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

All endpoints return structured error responses. The SDK parses them into typed Go errors:

```json
{
  "status": "error",
  "code": "TooManyRequestsRPM"
}
```

### Error Codes

| Server Code | SDK Error | Retry | Notes |
|-------------|-----------|-------|-------|
| `BadGateway` | `sdk.ErrBadGateway` | Yes (3s) | Temporary backend overload |
| `Internal` | `sdk.ErrServerInternal` | Yes (3s) | Temporary server error |
| `BadRequest` | `sdk.ErrBadRequest` | No | Invalid request format |
| `Forbidden` | `sdk.ErrForbidden` | No | Invalid license or authentication |
| `NotFound` | `sdk.ErrNotFound` | No | Unknown endpoint |
| `TooManyRequests` | `*sdk.RateLimitError` (General) | Yes (5s) | General rate limit |
| `TooManyRequestsRPM` | `*sdk.RateLimitError` (RPM) | Yes (Retry-After, max 10s) | Per-minute window |
| `TooManyRequestsRPH` | `*sdk.RateLimitError` (RPH) | No | Per-hour window — too long to auto-retry |
| `TooManyRequestsRPD` | `*sdk.RateLimitError` (RPD) | No | Per-day window — too long to auto-retry |
| `QuotaBlocked` | `*sdk.QuotaError` (Blocked) | Never | Endpoint unavailable for this license tier |
| `QuotaExceededDaily` | `*sdk.QuotaError` (Daily) | No (Retry-After) | Daily quota exhausted |
| `QuotaExceededMonthly` | `*sdk.QuotaError` (Monthly) | No (Retry-After) | Monthly quota exhausted |

The support endpoints refuse some calls with codes of their own, which the SDK maps to no sentinel: the error of the call matches `sdk.ErrRequestFailed` under `errors.Is` and its message begins with the code (`Support.Busy: request execution failed`); inside an event stream the code is the `Code` of the `*sse.Error`. None of them is retried.

| Server Code | HTTP | Meaning |
|-------------|------|---------|
| `Support.InvalidRequest` | 400 | The request cannot be read: a body that is not the JSON of the request or is larger than `models.MaxSupportIssueRequestBytes`, an issue ID that is not a UUID |
| `Support.InvalidData` | 500 | The request was read and is not valid: what `Valid` of its model refuses, the [limits of an issue](#support-issue-format) included |
| `Support.NotFound` | 404 | No issue of this ID belongs to the licence of the caller |
| `Support.Busy` | 409 | A question sent while the issue is not `processed`: its logs are still processed, or another question of it is being answered (see [Support Issue Status Format](#support-issue-status-format)) |

### Retry-After Header

Rate-limit and quota responses carry a `Retry-After: <seconds>` header. The SDK embeds it in
`*RateLimitError.RetryAfter` and `*QuotaError.RetryAfter`. Use `sdk.RetryAfterOf(err)` to read it
from any error without type-asserting:

```go
if wait := sdk.RetryAfterOf(err); wait > 0 {
    time.Sleep(wait) // server-suggested cooldown
}
```

`*RateLimitError` wraps temporary rate-limit sentinels (General/RPM are auto-retried by the SDK;
RPH/RPD are surfaced to the caller). `*QuotaError` wraps license-tier quota sentinels — all quota
errors are fatal and never auto-retried.

### SDK Integration

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
        Path:   "/api/v1/proxy/updates/check",
        Method: sdk.CallMethodPOST,
    },
    {
        Calls:  []any{&reportError},
        Host:   "support.pentagi.com",
        Name:   "report-error",
        Path:   "/api/v1/proxy/errors/report",
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

### Endpoint Health Check

Use `sdk.Check()` to probe endpoint reachability and inspect allowed RPM **without making an actual API call**. Useful at startup or in health-check routines:

```go
statuses, err := sdk.Check(ctx, configs,
    sdk.WithClient("MySecTool", "1.0.0"),
    sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),
)
if err != nil {
    log.Fatal("SDK setup failed:", err)
}

for name, s := range statuses {
    log.Printf("[%s] reachable=%v allowedRPM=%d err=%v",
        name, s.IsReachable(), s.AllowedRPM(), s.LastError())
}

// Re-probe later (e.g. after a rate-limit cooldown)
_ = statuses["check-updates"].Recheck(ctx)
```
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
    IssueInvestigate sdk.CallReqBytesRespReader  // Stream response support
}

configs := []sdk.CallConfig{
    {
        Calls:  []any{&client.UpdatesCheck},
        Host:   "update.pentagi.com",
        Name:   "updates_check",
        Path:   "/api/v1/proxy/updates/check",
        Method: sdk.CallMethodPOST,
    },
    {
        Calls:  []any{&client.ErrorReport},
        Host:   "support.pentagi.com",
        Name:   "errors_report",
        Path:   "/api/v1/proxy/errors/report",
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

Ticket request (`GET /api/v1/ticket/:name`):
```
X-Installation-ID: <stable-machine-uuid>
X-Request-ID:      <random-uuid>
X-Request-Key:     <base64(clientPublicKey[32] + nonce[24] + encrypted(sessionKey+sessionIV+ts+len)[64])>
X-License-Key:     <base64-encrypted-license>  (optional)
User-Agent:        MyApp/1.0.0 sdk/1.0.0
```

Main API request:
```
X-Installation-ID: <stable-machine-uuid>
X-Request-ID:      <pow-derived-request-uuid>
X-Request-Sign:    <base64-AES-CBC-signature[48]>
X-License-Key:     <base64-encrypted-license>  (optional)
User-Agent:        MyApp/1.0.0 sdk/1.0.0
Content-Type:      application/json  (when body is present)
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

Successful responses return JSON data wrapped in an envelope:
```json
{
  "status": "success",
  "data": { /* model-specific response */ }
}
```

Error responses contain only `status` and `code` (see [Error Handling](#error-handling) for all codes):
```json
{
  "status": "error",
  "code": "TooManyRequestsRPM"
}
```

**Always decode the body through `models.ParseEnvelope[T]`, never straight into the payload type.** Unmarshalling `{"status":"success","data":{...}}` directly into e.g.
`CheckUpdatesResponse` does not fail — it silently produces a zero-value response, which reads as "nothing to report" instead of the actual answer:

```go
// Wrong: "succeeds" and yields an empty CheckUpdatesResponse
var resp models.CheckUpdatesResponse
json.Unmarshal(body, &resp)

// Right: unwraps the envelope, and returns *models.APIError on a "status":"error" body
resp, err := models.ParseEnvelope[models.CheckUpdatesResponse](body)
```

Event streams (`text/event-stream`) are the exception, not wrapped in this envelope: the answer of a streamed investigation (`SupportInvestigationRequest.UseStream: true`) and the answer of every LLM call (`/api/v1/proxy/llm/chat/completions`, `/api/v1/proxy/llm/embeddings`). A refusal before such a stream begins, and the list of agents (`/api/v1/proxy/llm/models`), are enveloped like any JSON answer; a package download is the file itself.

### Event Stream Format

A streamed answer is a sequence of frames: `event: <name>`, `data: <one JSON value on one line>`, a blank line. The grammar is `start`, then any number of `heartbeat` frames and of the events of the call, then exactly one of `done` and `error`; nothing follows the last frame.

| Event | Data | Meaning |
|-------|------|---------|
| `start` | what identifies the call, or nothing: `{"issue_id":"…"}` for an investigation, `{}` for an LLM call | the first frame |
| `heartbeat` | `{"timestamp":<unix seconds>}` | keeps the connection alive every few seconds; carries nothing else |
| `error` | `{"code":"<code>","message":"<text>"}` | the server refused or failed after the response began; `code` is the code of the error envelope the same refusal has before it |
| `done` | `{}` | the answer is complete |

An answer is complete **if and only if** `done` arrived. The end of the body before `done` or `error` means the stream was cut: what arrived is not an answer, and the request must not be repeated on account of it. The `sdk/sse` package reads the stream by these rules (`sse.Read`, `sse.NewReader`): it hands the caller `start` and the events of the call, consumes the heartbeats, returns `*sse.Error` for an `error` event — matched by `errors.Is` against the errors of the `sdk` package when given `sdk.ErrorFromCode` — and `sse.ErrStreamCut` for a cut one.

Requests ask for `Accept-Encoding: identity`: the body of an answer is ciphertext, and a hop that compresses would hold frames back.

### Licence Status Format

The endpoint `license_status` (`GET /api/v1/proxy/license/status`, no request body) answers a licensed installation with what its licence gives it, in the envelope of every JSON answer. The caller builds the call itself — the endpoint code is the `Name` of the call and is not the caller's to choose — and reads the answer with `ParseEnvelope`, then `Valid`:

```go
var licenseStatus sdk.CallReqRespBytes
err := sdk.Build([]sdk.CallConfig{{
    Calls:  []any{&licenseStatus},
    Host:   "update.pentagi.com",
    Name:   "license_status",
    Path:   "/api/v1/proxy/license/status",
    Method: sdk.CallMethodGET,
}}, options...)

body, err := licenseStatus(ctx)
status, err := models.ParseEnvelope[models.LicenseStatusResponse](body)
err = status.Valid() // refuse what is not a status rather than read it as one with nothing used
```

```json
{"tier":"enterprise","features":{"updates":true,"support":true,"knowledge_base":false,"cloud_llm":true},"quotas":[
  {"limit":"llm_agent","daily":{"requests":-1},"monthly":{"requests":-1}},
  {"limit":"llm_automation","daily":{"requests":100},"monthly":{"requests":30}},
  {"limit":"llm_completion","daily":{"requests":1,"tokens":13},"monthly":{"requests":1,"tokens":4}},
  {"limit":"llm_embedding","daily":{"requests":0,"tokens":0},"monthly":{"requests":1,"tokens":2}}
]}
```

| Field | Meaning |
|-------|---------|
| `tier` | the tier of the licence |
| `features` | `updates`, `support`, `knowledge_base`, `cloud_llm` — the last as served: false on a tier Cloud LLM does not serve, even when the key carries the flag |
| `quotas[].limit` | the name of the limit (`llm_agent`, `llm_automation`, `llm_completion`, `llm_embedding`; a limit added later is read by its name like these) |
| `daily` / `monthly` | today, a UTC day; this month of the licence, counted from the day of the month its first key was issued |
| `requests` | the share of the calls |
| `tokens` | the larger of the shares of the input and of the output tokens; absent for a limit that meters no tokens |

Every share is a whole percent of the quota used, with the overrides of the licence applied, computed by the server: `0` is nothing used, any use is at least `1`, a share between is rounded down and stays below `100`, and `100` is a quota used up — the next call of that limit is refused (`QuotaExceededDaily`, `QuotaExceededMonthly`). `-1` (`models.LicenseQuotaUnlimited`) is no ceiling in that period; `tokens` is `-1` only when neither kind of token has one. A limit the licence cannot call, or calls with no quota kept, is not in the list; `quotas` is `[]` for none, never null. The endpoint counts against no quota and has rate limits of its own per licence; a licence the API does not serve is refused, either as `Forbidden` like any other call of it or as `QuotaBlocked`: read both as the licence not served, not as a failure to retry.

### Support Issue Format

The endpoint `support_issues` (`POST /api/v1/proxy/support/issues`) creates an issue from a `models.SupportIssueRequest` and answers `201` with its `issue_id` (`models.SupportIssueResponse`) — the ID every later call of the issue names. An issue is read only by its ID; there is no list of them.

**Limits.** A request past any of them is refused, and nothing is created. `SupportIssueRequest.Valid` checks the lines and `error_details`, which no tag can state; the size of the body is the sender's to check after encoding it.

| Limit | Value | Refused as |
|-------|-------|------------|
| the body of the request | `models.MaxSupportIssueRequestBytes`: 2 MiB (2097152 bytes) | `Support.InvalidRequest` |
| the lines of logs, of all components together | `models.MaxSupportIssueLogLines`: 2000 | `Support.InvalidData` |
| one line of logs | 1–8192 characters | `Support.InvalidData` |
| `error_details`, as compact JSON with `<`, `>` and `&` written as themselves | `models.MaxSupportIssueDetailsBytes`: 256 KiB (262144 bytes) | `Support.InvalidData` |

**Error Details.** `error_details` is any JSON value: the server keeps it with the issue as it arrived, and other clients send forms of their own. A document of the schema `models.SupportIssueDetails` is what the support assistant reads as the context of the issue — what the user wrote about the problem and what the product could tell about itself and the flow concerned; a value of any other form is kept and tells the assistant nothing. The schema is versioned by `schema` (now `1`) and grows by adding fields: a reader skips the fields it does not know, and a document of a later schema is read by the fields of schema 1.

| Part | Fields | Meaning |
|------|--------|---------|
| top level | `schema` (at least 1), `description` (at most 4000 characters), `collected_at` | The version of the schema; what the user wrote about what does not work — a report, not a question to the assistant; when the document was collected |
| `product` (always) | `version` (a semantic version; `0.0.0` for a build that has none), `develop`, `os`, `arch`, `binary_hash`, `uptime_seconds`, `debug`, `docker_inside`, `default_image`, `multi_tenant` | The process of the product; `os` and `arch` are the platform it was built for — always `linux` for a product in Docker |
| `host` | `docker_version`, `os`, `os_type`, `architecture`, `kernel`, `cpus`, `memory_bytes` | The machine the Docker daemon of the product runs on, as the daemon describes it; the name of the host is not part of it |
| `license` | `tier`, `state`, `features` (as in [Licence Status Format](#licence-status-format)), `expires_at`, `checked_at` | The licence as the product last read its status; the key is not part of it, masked or not; `checked_at` is absent before the first answer |
| `providers[]` (at most 32) | `ref`, `type`, `source`, `created_at`, `models` | The LLM providers the product can use, without their names, addresses or keys: `ref` (`p1`, `p2`, …) is what a flow and the use of a model point to; `source` is `env` or `user`; `created_at` is set for a provider a user added; `models` maps a type of agent to its model |
| `installation` | `embedding_provider`, `oauth[]`, `features` (name → boolean), `counts` (name → number) | What the installation is made of; the use of tokens over the whole installation is not part of it |
| `flow` | `id`, `status`, `language`, `provider_ref`, `provider_type`, `model`, `created_at`, `updated_at`, `time_budget_seconds`, `max_subtasks`, `max_subagents`; `tasks`, `subtasks`, `assistants` (each `total` and `by_status`); `usage` (`in`, `out`, `cache_in`, `cache_out`, `cost_in`, `cost_out`); `toolcalls` (`total`, `failed`, `duration_seconds`, `by_function[]` of at most 10, each `name`, `is_agent`, `count`, `failed`); `usage_by_model[]` of at most 10 (`model`, `provider_ref`, `agents[]` and the six numbers of `usage`); `usage_by_agent[]` (`agent` and the six numbers); `chains` (`reflector`, `tool_call_fixer`, `subagents`, each `total` and `failed`); `container` (`image`, `status`, `live`: `running`, `stopped` or `unknown`); `errors[]` of at most 30 (`kind`, `name`, `status`, `error_class`, `result_length`, `created_at`) | The flow the issue is reported for, when there is one. `provider_ref` is the `ref` of its provider in `providers`, `null` when that provider is gone, never absent. No title, input or result of the flow travels: a failure is told by its kind, its status, the length of its result and `error_class`, a word of a closed vocabulary the product infers from the result |
| `logs` (always) | `available`, `lines`, `matched`, `files`, `from`, `to`, `truncated`, `dropped_long`, `filter` (`scope`, `admin`, `redacted_keys[]`), `counts` (name → number) | The lines of logs sent with the issue: `lines` sent and `matched` before repeats were folded, the times of the first and the last, how they were chosen — `scope` the flow they were chosen for, `admin` a reporter who may send the lines of every user, `redacted_keys` the keys whose values were replaced by their length — and the counts of the patterns of trouble by name |
| `findings[]` (at most 64) | `code`, `severity` (`info`, `warning`, `error`), `detail` | The known problems the product detected in what it collected |
| `skipped[]` (at most 32) | names | The parts the product failed to collect or could not collect in time; the document is built from the rest |

A part not marked "(always)" is absent when there is nothing to tell, and so are the lists, the maps, the times and `filter.scope` (lines chosen for no flow) that the model marks `omitempty`; every other field is written, zero or not. A document of only the parts that are always there:

```json
{"schema":1,"description":"The terminal of a flow never starts.","collected_at":"2026-10-16T10:00:00Z","product":{"version":"1.2.0","develop":false,"os":"linux","arch":"amd64","binary_hash":"","uptime_seconds":0,"debug":false,"docker_inside":false,"default_image":"","multi_tenant":false},"logs":{"available":false,"lines":0,"matched":0,"files":0,"truncated":false,"dropped_long":0,"filter":{"admin":false}}}
```

The document with every part present is `goldenSupportIssueDetails` in [models/contract_test.go](models/contract_test.go).

**Anonymisation.** Free text is anonymised by the sender: pass a pointer to the document to `Anonymize` of the [anonymizer](anonymizer/) package, as for the logs. The fields of closed vocabularies, versions and references (`schema`, `version`, `type`, `source`, `status`, `ref`, `provider_ref`, `agent`, `code`, `severity`, …) carry `anonymizer:"skip"` and stay as a reader matches them; numbers, booleans and the keys of maps — names of closed sets — are never touched. No field is `[]byte` or `json.RawMessage`: the walk leaves their bytes as they are, and raw text in them would pass unmasked.

**Sending.** Call `SupportIssueDetails.Valid` after anonymising — a marker can be longer than the text it replaces, and the description is bounded as it is sent — then `SupportIssueRequest.Valid` for the limits of the server. Write the request with a `json.Encoder` after `SetEscapeHTML(false)`: `json.Marshal` writes each `<`, `>` and `&` of tool output as six bytes, which grows the body toward its limit; `error_details` is measured without them either way.

### Support Issue Status Format

The endpoint `support_issue_status` (`GET /api/v1/proxy/support/issues/:issueID/status`, no request body) answers with what runs on an issue, in the envelope of every JSON answer. The ID of the issue is the argument of the path, so the call is a `CallReqWithArgsRespBytes`; the endpoint code is the `Name` of the call and is not the caller's to choose. Read the answer with `ParseEnvelope`, then `Valid`:

```go
var issueStatus sdk.CallReqWithArgsRespBytes
err := sdk.Build([]sdk.CallConfig{{
    Calls:  []any{&issueStatus},
    Host:   "support.pentagi.com",
    Name:   "support_issue_status",
    Path:   "/api/v1/proxy/support/issues/:issueID/status",
    Method: sdk.CallMethodGET,
}}, options...)

body, err := issueStatus(ctx, []string{issueID.String()})
status, err := models.ParseEnvelope[models.SupportIssueStatusResponse](body)
err = status.Valid() // refuse what is not a status rather than wait on it
```

```json
{"status":"processing"}
{"status":"processed","updated_at":"2026-10-16T10:00:00.123456Z"}
```

| Field | Meaning |
|-------|---------|
| `status` | `processing` — the server is working through the lines of logs the issue was reported with; `processed` — nothing runs, and a question may be sent; `answering` — the assistant is answering a question of the issue |
| `updated_at` | when the conversation of the issue last changed — a question asked, a call of the model — to the microsecond; absent before the first question. The answer of a turn is written after its last move, before the status returns to `processed` |

An issue is `processing` from its creation while there are lines of logs to work through, and `processed` from the start when there are none. Processing ends in `processed` whatever its outcome: there is no failed status, and the assistant answers from what was found. A question moves the issue from `processed` to `answering` and back; there is no move from `processing` to `answering`. The status is `processed` again before the last frame of the answer is written, so a status read after the `done` or the `error` of one's own stream does not show that question still running. The status is kept by the server, not by a connection: a turn this caller did not send reads `answering` too, and after a stream that was cut the status tells when the turn ended.

Compare `updated_at` with the one read before: when it moved, the conversation changed — read it again, and once more when the status leaves `answering`, since the answer of a turn is written after the last move of `updated_at` — from the endpoint `support_issue_messages` (`GET /api/v1/proxy/support/issues/:issueID/messages`, bound the same way), which answers `models.SupportIssueMessagesResponse`: the question (`input`), the steps of the assistant and its answer (`done`), each with `created_at`, and `[]` before the first question, never null. A streamed answer carries the answer as `content` and `update` events, not as a `done` message; the messages hold it once the turn ended.

```json
{"messages":[{"type":"input","message":"Why does the terminal of flow 12 never start?","created_at":"2026-10-16T10:01:00Z"},{"type":"search","message":"searching FAQ for terminal startup errors","created_at":"2026-10-16T10:01:02Z"},{"type":"done","message":"The image of the flow could not be pulled; check the registry the installation uses.","created_at":"2026-10-16T10:01:30.5Z"}]}
```

A question (`support_investigate`) is taken only while the issue is `processed`, one at a time whoever sends it; at any other time it is refused before the stream begins with `Support.Busy` (HTTP 409), and the refusal is not charged to a quota: wait for `processed` and send the question again. An issue belongs to the licence that created it, not to the installation that sent it: its status, its messages and its questions are open to every installation of that licence, also after the key of the licence was regenerated, and an issue of another licence is `Support.NotFound` (HTTP 404), as one that does not exist. The support endpoints serve a licence whose `features` include `support`; another caller is refused, either as `Forbidden` or as `QuotaBlocked`: read both as support not served, not as a failure to retry.

The status has rate limits of its own per licence and, on some tiers, a quota of its own, apart from those of the questions and the messages; the licence status does not report it. Poll it while an issue is `processing` or `answering` — every 30 seconds is enough — and seldom otherwise; after a `*sdk.RateLimitError` or a `*sdk.QuotaError` stop polling until `sdk.RetryAfterOf(err)`. The conversation does not depend on the status: a question may be sent while the status cannot be read, and the server answers `Support.Busy` if it comes too early.

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
