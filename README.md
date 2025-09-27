# VXControl Cloud SDK

<div align="center" style="font-size: 1.5em; margin: 20px 0;">
    Enterprise-grade Go SDK for secure integration with VXControl Cloud Intelligence Platform and Services.
</div>
<br>
<div align="center">

> 🚀 **Join the Community!** Connect with security researchers, AI enthusiasts, and fellow ethical hackers. Get support, share insights, and stay updated with the latest PentAGI developments.

[![Discord](https://img.shields.io/badge/Discord-7289DA?logo=discord&logoColor=white)](https://discord.gg/2xrMh7qX6m)⠀[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?logo=telegram&logoColor=white)](https://t.me/+Ka9i6CNwe71hMWQy)

</div>

## Overview

The VXControl Cloud SDK enables developers to integrate their security tools and applications with the VXControl Cloud Intelligence Platform, providing access to advanced cybersecurity services including threat intelligence, vulnerability databases, computational resources, AI-powered troubleshooting, and automated update systems.

## Key Features

- **Type-Safe API**: 24 strongly-typed function patterns covering all request/response scenarios
- **Transparent Security**: Automatic proof-of-work solving and end-to-end encryption
- **Performance Optimized**: HTTP/2 support, connection pooling, streaming encryption
- **Enterprise Ready**: Comprehensive error handling, retry logic, and production monitoring
- **License Integration**: Built-in premium feature validation and tier management

## Quick Start

### Installation

```bash
go get github.com/vxcontrol/cloud/sdk
```

### Basic Usage

```go
package main

import (
    "context"
    "encoding/json"
    "log"

    "github.com/vxcontrol/cloud/models"
    "github.com/vxcontrol/cloud/sdk"
    "github.com/vxcontrol/cloud/system"

    "github.com/sirupsen/logrus"
)

type Client struct {
    UpdatesCheck  sdk.CallReqBytesRespBytes
    ReportError   sdk.CallReqBytesRespBytes
}

func main() {
    var client Client

    // Configure endpoints
    configs := []sdk.CallConfig{
        {
            Calls:  []any{&client.UpdatesCheck},
            Host:   "update.pentagi.com",
            Name:   "updates_check",
            Path:   "/api/v1/updates/check",
            Method: sdk.CallMethodPOST,
        },
        {
            Calls:  []any{&client.ReportError},
            Host:   "support.pentagi.com",
            Name:   "error_report",
            Path:   "/api/v1/errors/report",
            Method: sdk.CallMethodPOST,
        },
    }

    // Initialize SDK
    err := sdk.Build(configs,
        sdk.WithClient("MySecTool", "1.0.0"),
        sdk.WithInstallationID(system.GetInstallationID()),
        sdk.WithLogger(sdk.WrapLogrus(logrus.StandardLogger())),
        sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),
    )
    if err != nil {
        log.Fatal("SDK initialization failed:", err)
    }

    // Check for updates
    updateReq := models.CheckUpdatesRequest{
        InstallerVersion: "1.0.0",
        InstallerOS:      models.OSTypeLinux,
        InstallerArch:    models.ArchTypeAMD64,
    }

    data, _ := json.Marshal(updateReq)
    response, err := client.UpdatesCheck(context.Background(), data)
    if err != nil {
        log.Fatal("Update check failed:", err)
    }

    var updateResp models.CheckUpdatesResponse
    json.Unmarshal(response, &updateResp)
    log.Printf("Available updates: %+v", updateResp.Updates)
}
```

## Architecture

```mermaid
graph TD
    A[Your Security Application] --> B[VXControl Cloud SDK]
    B --> C[PoW Challenge System]
    B --> D[Encrypted Transport Layer]
    D --> E[VXControl Cloud Platform]

    E --> F[Update Services]
    E --> G[Package Management]
    E --> H[Error Reporting & AI Support]
    E --> I[Threat Intelligence Hub]
    E --> J[Vulnerability Database]
    E --> K[Computational Resources]
    E --> L[Knowledge Base]

    A --> M[PentAGI]
    A --> N[Security Tools]
    A --> O[SOC Systems]
    A --> P[Red Team Tools]
    A --> Q[Custom Applications]

    C --> R[Memory-Hard Algorithm]
    C --> S[Rate Limiting]
    D --> T[End-to-End Encryption]
    D --> V[Forward Secrecy]
    D --> X[Ed25519 Signatures]
```

## Cloud Services Integration

### Update Management
Keep PentAGI with automated update checking:

```go
import "github.com/vxcontrol/cloud/models"

// Check for component updates
updateReq := models.CheckUpdatesRequest{
    InstallerVersion: "1.0.0",
    InstallerOS:      models.OSTypeLinux,
    InstallerArch:    models.ArchTypeAMD64,
    Components: []models.ComponentInfo{
        {
            Component: models.ComponentTypePentagi,
            Status:    models.ComponentStatusRunning,
            Version:   &[]string{"1.2.0"}[0],
        },
    },
}

data, _ := json.Marshal(updateReq)
response, err := client.UpdatesCheck(ctx, data)

var updateResp models.CheckUpdatesResponse
json.Unmarshal(response, &updateResp)
```

### Error Reporting & AI Support
Get intelligent assistance for troubleshooting:

```go
// Report an error for analysis
errorReq := models.SupportErrorRequest{
    Component:    models.ComponentTypePentagi,
    Version:      "1.0.0",
    OS:          models.OSTypeLinux,
    Arch:        models.ArchTypeAMD64,
    ErrorDetails: map[string]any{
        "error_type": "connection_timeout",
        "message":    "Failed to connect to target",
        "context":    map[string]string{"target": "192.168.1.1", "port": "443"},
    },
}

data, _ := json.Marshal(errorReq)
response, err := client.ReportError(ctx, data)
```

### Package Management
Download and validate software packages:

```go
// Get package information
packageReq := models.PackageInfoRequest{
    Component: models.ComponentTypePentagi,
    Version:   "1.0.0",
    OS:        models.OSTypeLinux,
    Arch:      models.ArchTypeAMD64,
}

// Validate package integrity with signatures
signature := models.SignatureValue("base64-encoded-signature")
fileData, _ := os.ReadFile("package.tar.gz")
if err := signature.ValidateData(fileData); err != nil {
    log.Fatal("Package signature validation failed:", err)
}
```

### AI-Powered Troubleshooting
Interactive support with investigation capabilities:

```go
// Create support issue
issueReq := models.SupportIssueRequest{
    Component:    models.ComponentTypeEngine,
    Version:      "2.0.0",
    OS:          models.OSTypeDarwin,
    Arch:        models.ArchTypeARM64,
    ErrorDetails: "Scanner fails to detect specific vulnerability patterns",
    Logs: []models.SupportLogs{
        {
            Component: models.ComponentTypeEngine,
            Logs:      []string{"ERROR: Pattern matching timeout", "WARN: Memory usage high"},
        },
    },
}

// Investigate with AI assistance
investigationReq := models.SupportInvestigationRequest{
    IssueID:   receivedIssueID,
    UserInput: "The scanner works fine with other patterns but fails on this specific CVE",
}
```

## Call Function Types

The SDK supports 24 function patterns to handle different request/response scenarios:

| Pattern | Request | Response | Use Case |
|---------|---------|----------|----------|
| `CallReqRespBytes` | None | Bytes | Simple data retrieval |
| `CallReqQueryRespBytes` | Query params | Bytes | Filtered data queries |
| `CallReqWithArgsRespBytes` | Path args | Bytes | Resource-specific requests |
| `CallReqBytesRespBytes` | Body data | Bytes | Data submission/processing |
| `CallReqReaderRespReader` | Stream | Stream | Large file processing |
| `CallReqReaderRespWriter` | Stream | Writer | Direct output streaming |

[Complete function reference](https://pkg.go.dev/github.com/vxcontrol/cloud/sdk)

## Configuration Options

### Basic Configuration

```go
err := sdk.Build(configs,
    // Required: Client identification
    sdk.WithClient("MyApp", "1.0.0"),

    // Optional: Premium features
    sdk.WithLicenseKey("XXXX-XXXX-XXXX-XXXX"),

    // Optional: Performance tuning
    sdk.WithPowTimeout(30*time.Second),
    sdk.WithMaxRetries(3),
)
```

### Advanced Configuration

```go
// Custom transport for proxies/certificates
transport := sdk.DefaultTransport()
transport.TLSClientConfig = &tls.Config{
    MinVersion: tls.VersionTLS12,
    // custom certificate validation
}
transport.Proxy = http.ProxyURL(proxyURL)

// Custom structured logging
logger := logrus.New()
logger.SetLevel(logrus.InfoLevel)

err := sdk.Build(configs,
    sdk.WithTransport(transport),
    sdk.WithLogger(sdk.WrapLogrus(logger)),
    sdk.WithInstallationID(system.GetInstallationID()),
)
```

## Security Model

### Proof-of-Work Protection
All API calls require solving computational challenges to prevent abuse and DDoS attacks. The SDK automatically:
- Requests challenge tickets from the server
- Solves memory-hard proof-of-work puzzles
- Includes cryptographic signatures with requests

### End-to-End Encryption
- **Session Keys**: Ephemeral AES keys for each request
- **NaCL Encryption**: Secure key exchange using Curve25519
- **Streaming Cipher**: AES-GCM for large data transfers
- **Forward Secrecy**: Cypher key rotation

### Rate Limiting Integration
- **Adaptive Difficulty**: PoW complexity scales with server load
- **Tier-Based Access**: License validation determines API quotas
- **Intelligent Retry**: Automatic backoff with server-provided timing

## Error Handling

### Automatic Retry Logic

```go
// Temporary errors (automatically retried):
// - Server overload (sdk.ErrBadGateway, sdk.ErrServerInternal)
// - Rate limits (sdk.ErrTooManyRequests, sdk.ErrTooManyRequestsRPM)
// - PoW timeouts (sdk.ErrExperimentTimeout)

// Fatal errors (no retry):
// - Invalid requests (sdk.ErrBadRequest, sdk.ErrForbidden)
// - Missing resources (sdk.ErrNotFound)
// - Long-term limits (sdk.ErrTooManyRequestsRPH, sdk.ErrTooManyRequestsRPD)
```

### Custom Error Handling

```go
data, err := api.QueryThreats(ctx, []byte(threatQuery))
if err != nil {
    switch {
    case errors.Is(err, sdk.ErrTooManyRequestsRPM):
        // Wait and retry with exponential backoff
        time.Sleep(60 * time.Second)

    case errors.Is(err, sdk.ErrForbidden):
        // Check license validity or authentication
        log.Error("access denied - verify license key")

    case errors.Is(err, sdk.ErrExperimentTimeout):
        // Increase PoW timeout for slower systems
        // Reconfigure with sdk.WithPowTimeout(60*time.Second)

    default:
        log.Error("unexpected error:", err)
    }
}
```

## Performance Characteristics

### Benchmarks
- **License validation**: ~334,000 operations/sec
- **Function generation**: ~2M path templates/sec
- **Streaming encryption**: ~50MB/sec throughput
- **Connection pooling**: 300 connections/host, 50 total idle

### Memory Usage
- **Per request**: ~300 bytes (context + headers + keys)
- **Per SDK instance**: ~200KB (connection pools + crypto keys)
- **PoW solving**: 20-1024KB (reused across attempts)

### Optimization Tips

```go
// Reuse SDK instances across requests
err := sdk.Build(configs, options...)

// Use streaming for large data
reader, err := api.ProcessLargeDataset(ctx, dataStream, dataSize)

// Configure connection pooling for high throughput
transport := sdk.DefaultTransport()
transport.MaxConnsPerHost = 500
sdk.WithTransport(transport)
```

## Production Deployment

### Required Configuration

```go
// Minimum production setup
err := sdk.Build(configs,
    sdk.WithClient("YourApp", version),    // Required: Identification
    sdk.WithLicenseKey(licenseKey),        // Optional: Authentication
    sdk.WithLogger(productionLogger),      // Recommended: Monitoring
)
```

### Monitoring Integration

```go
// Custom logger for metrics collection
type MetricsLogger struct {
    *logrus.Logger
    metrics MetricsCollector
}

func (m *MetricsLogger) WithError(err error) sdk.Entry {
    // Track error rates by type
    m.metrics.IncrementErrorCounter(err)
    return m.Logger.WithError(err)
}

// Integration
logger := &MetricsLogger{Logger: logrus.New(), metrics: yourMetrics}
sdk.WithLogger(logger)
```

### Security Considerations

- **Certificate Validating**: Validate server certificates in production
- **Proxy Support**: Configure corporate proxy settings if required
- **Timeout Tuning**: Adjust PoW timeouts based on hardware capabilities
- **Rate Limit Monitoring**: Track API quota usage and plan capacity

## Use Cases

### Security Tool Integration

```go
// Integrate update checking into security tools
func checkSecurityToolUpdates(components []models.ComponentInfo) error {
    updateReq := models.CheckUpdatesRequest{
        InstallerVersion: getCurrentVersion(),
        InstallerOS:      getCurrentOS(),
        InstallerArch:    getCurrentArch(),
        Components:       components,
    }

    data, _ := json.Marshal(updateReq)
    response, err := client.UpdatesCheck(context.Background(), data)
    if err != nil {
        return err
    }

    var updateResp models.CheckUpdatesResponse
    json.Unmarshal(response, &updateResp)

    for _, update := range updateResp.Updates {
        if update.HasUpdate {
            log.Printf("Update available for %s: %s -> %s",
                update.Stack, *update.CurrentVersion, *update.LatestVersion)
        }
    }

    return nil
}
```

### Automated Error Reporting

```go
// Integrate error reporting into application error handling
func reportSecurityToolError(component models.ComponentType, err error) error {
    errorReq := models.SupportErrorRequest{
        Component:    component,
        Version:      getComponentVersion(component),
        OS:          getCurrentOS(),
        Arch:        getCurrentArch(),
        ErrorDetails: map[string]any{
            "error_message": err.Error(),
            "stack_trace":   getStackTrace(),
            "context":       getCurrentContext(),
        },
    }

    data, _ := json.Marshal(errorReq)
    _, reportErr := client.ReportError(context.Background(), data)
    return reportErr
}
```

### Package Integrity Validation

```go
// Validate downloaded packages before installation
func validatePackageIntegrity(packagePath, signatureStr string) error {
    signature := models.SignatureValue(signatureStr)

    // Validate file signature
    if err := signature.ValidateFile(packagePath); err != nil {
        return fmt.Errorf("package signature validation failed: %w", err)
    }

    log.Println("Package integrity verified successfully")
    return nil
}

// Validate data integrity in memory
func validateDataIntegrity(data []byte, signatureStr string) error {
    signature := models.SignatureValue(signatureStr)

    if err := signature.ValidateData(data); err != nil {
        return fmt.Errorf("data signature validation failed: %w", err)
    }

    return nil
}
```

## Advanced Features

### Multiple Service Endpoints

```go
// Connect to different service clusters
type FullClient struct {
    UpdatesCheck     sdk.CallReqBytesRespBytes
    ErrorReport      sdk.CallReqBytesRespBytes
    PackageInfo      sdk.CallReqBytesRespBytes
    SupportIssue     sdk.CallReqBytesRespBytes
}

configs := []sdk.CallConfig{
    {
        Calls:  []any{&client.UpdatesCheck},
        Host:   "update.pentagi.com",
        Name:   "check_updates",
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
    {
        Calls:  []any{&client.PackageInfo},
        Host:   "update.pentagi.com",
        Name:   "package_info",
        Path:   "/api/v1/packages/info",
        Method: sdk.CallMethodPOST,
    },
}
```

### Timeout and Retry Configuration

```go
// Configure timeouts for different operation types
err := sdk.Build(configs,
    sdk.WithPowTimeout(30*time.Second),  // For slower systems (max 60s, default 10s)
    sdk.WithMaxRetries(5),               // For rate limiting and network issues
    sdk.WithTransport(customTransport),  // Custom HTTP configuration
)

// Per-request timeouts
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

response, err := client.UpdatesCheck(ctx, requestData)
```

## Error Reference

| Error | Type | Retry | Description |
|-------|------|-------|-------------|
| `sdk.ErrBadGateway` | Temporary | Yes (3s) | Server maintenance/overload |
| `sdk.ErrTooManyRequestsRPM` | Temporary | Yes (server-defined) | Rate limit exceeded |
| `sdk.ErrExperimentTimeout` | Temporary | Yes (10s) | PoW solving timeout |
| `sdk.ErrForbidden` | Fatal | No | Invalid license or authentication |
| `sdk.ErrBadRequest` | Fatal | No | Invalid request format |
| `sdk.ErrNotFound` | Fatal | No | Unknown endpoint or resource |

## Available Models

The SDK provides strongly-typed models for all API interactions:

### Component Management
- `ComponentType`: pentagi, scraper, langfuse-worker, langfuse-web, grafana, otelcol, worker, installer, engine
- `ComponentStatus`: unused, connected, installed, running
- `ProductStack`: pentagi, langfuse, observability, worker, installer, engine
- `OSType`: windows, linux, darwin
- `ArchType`: amd64, arm64

### Update Service Models
- `CheckUpdatesRequest` / `CheckUpdatesResponse`: Check for component updates
- `ComponentInfo`: Information about installed components
- `UpdateInfo`: Available update details with changelog

### Package Service Models
- `PackageInfoRequest` / `PackageInfoResponse`: Get package metadata
- `DownloadPackageRequest`: Request package downloads
- `SignatureValue`: Cryptographic signature validation

### Support Service Models
- `SupportErrorRequest` / `SupportErrorResponse`: Automated error reporting
- `SupportIssueRequest` / `SupportIssueResponse`: Manual issue creation with AI
- `SupportLogs`: Component log collection
- `SupportInvestigationRequest` / `SupportInvestigationResponse`: AI-powered troubleshooting

### System Utilities
- `system.GetInstallationID()`: Generates stable, machine-specific UUID for installation tracking

## Service Tiers

### Free Tier
- **Basic error reporting**: Automated error submission
- **Package validation**: Ed25519 signature verification
- **Rate limiting**: Standard PoW difficulty

### Professional Tier
- **AI troubleshooting**: x5 investigation sessions/day
- **Package downloads**: Access to all packages
- **Rate limiting**: Reduced PoW difficulty

### Enterprise Tier
- **Advanced AI troubleshooting**: x50 investigation sessions/day
- **Custom integrations**: Specialized endpoints and workflows
- **Priority processing**: Minimal PoW difficulty and fast-track handling

## Future Roadmap

The VXControl Cloud Platform is actively expanding. Future releases may include:

- **Threat Intelligence Services**: IOC/IOA database access and threat analysis
- **Vulnerability Assessment**: CVE database integration and security scanning
- **Computational Resources**: Cloud-based intensive task processing
- **Advanced Analytics**: Security metrics and reporting dashboards
- **Custom Workflows**: Specialized security automation pipelines

*Note: These features are in development and not yet available in the current SDK version.*

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- **Documentation**: [API Reference](API.md) | [Examples](examples/)
- **Issues**: [GitHub Issues](https://github.com/vxcontrol/cloud/issues)
- **Enterprise Support**: support@vxcontrol.com
- **Community**: [Discord](https://discord.gg/2xrMh7qX6m) and [Telegram](https://t.me/+Ka9i6CNwe71hMWQy)

## License and Terms

### SDK License

Copyright (c) 2025 VXControl LLC. All rights reserved.

The **SDK code** is licensed under **GNU Affero General Public License v3.0 (AGPL-3.0)** with specific exceptions:

**Open Source Use:**
- **Free for open source projects** under AGPL-3.0 terms  
- **Academic research and education**  
- **Non-commercial projects**

**Commercial Use:**  
- **Commercial/proprietary use requires a separate license**  
- **Enterprise licenses available** - Contact info@vxcontrol.com

**Special Exception:**  
- **Official PentAGI project** has a specific licensing exception - see [LICENSE](LICENSE) for details.

### Cloud Services Terms

⚠️ **Important:** Using VXControl Cloud Services requires compliance with additional terms.

The SDK provides access to **sensitive cybersecurity data**, **threat intelligence**, **vulnerability information**, and **AI-powered assistance**. Use of these cloud services and obtained data is governed by our [Terms of Service](TERMS_OF_SERVICE.md).

**Cloud services may ONLY be used for:**
- ✅ Defensive cybersecurity and authorized security testing
- ✅ Academic research and education in controlled environments  
- ✅ Incident response and compliance assessment
- ❌ **Prohibited:** Unauthorized access, malicious activities, or illegal purposes

📋 **Before using cloud services, read:** [TERMS_OF_SERVICE.md](TERMS_OF_SERVICE.md)

### Contact

For licensing questions: **info@vxcontrol.com**  
For Terms of Service violations: **info@vxcontrol.com** (Subject: "Cloud Services Terms")
