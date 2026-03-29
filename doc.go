// Package cloud provides enterprise-grade Go SDK for secure integration with VXControl Cloud Platform.
//
// The VXControl Cloud Platform offers a comprehensive suite of cybersecurity services
// accessible through secure, PoW-protected APIs. This package enables developers to integrate
// their security tools and applications with advanced cybersecurity services including
// update management, package distribution, AI-powered troubleshooting, and comprehensive
// data anonymization.
//
// # Architecture
//
// The cloud package consists of several core components:
//
//   - sdk: Main SDK package for API integration with 24 strongly-typed function patterns
//   - models: Type-safe data models with built-in validation for all API interactions
//   - anonymizer: Comprehensive PII/secrets masking engine with 300+ pattern recognition
//   - system: Cross-platform utilities for stable installation ID generation
//   - examples: Production-ready integration examples and usage patterns
//
// # Quick Start
//
// Basic usage involves configuring API endpoints and building the SDK:
//
//	import (
//	    "github.com/vxcontrol/cloud/sdk"
//	    "github.com/vxcontrol/cloud/models"
//	    "github.com/vxcontrol/cloud/system"
//	)
//
//	// Define client structure with API functions
//	type Client struct {
//	    UpdatesCheck sdk.CallReqBytesRespBytes
//	    ReportError  sdk.CallReqBytesRespBytes
//	}
//
//	// Configure endpoints
//	configs := []sdk.CallConfig{
//	    {
//	        Calls:  []any{&client.UpdatesCheck},
//	        Host:   "update.pentagi.com",
//	        Name:   "updates_check",
//	        Path:   "/api/v1/updates/check",
//	        Method: sdk.CallMethodPOST,
//	    },
//	}
//
//	// Initialize SDK
//	err := sdk.Build(configs,
//	    sdk.WithClient("MySecTool", "1.0.0"),
//	    sdk.WithInstallationID(system.GetInstallationID()),
//	    sdk.WithLicenseKey("your-license-key"),
//	)
//
// # Core Features
//
// Security-First Design:
//   - Memory-hard proof-of-work protection against abuse and DDoS attacks
//   - Ed25519 cryptographic signatures for data integrity verification
//   - AES-GCM end-to-end encryption with forward secrecy
//   - Stable machine identification for installation tracking
//   - Mandatory PII/secrets anonymization for AI troubleshooting
//
// Type Safety:
//   - 24 strongly-typed function patterns covering all request/response scenarios
//   - Comprehensive Go models with built-in validation (IValid interface)
//   - Automatic query parameter generation (IQuery interface)
//   - Database integration support with SQL driver interfaces
//
// Performance Optimized:
//   - HTTP/2 support with automatic protocol negotiation
//   - Connection pooling and streaming architecture
//   - Memory-efficient processing for large data transfers
//   - Dynamic difficulty scaling based on server load
//
// # Available Services
//
// Production Services:
//   - Update Service: Component update checking with changelogs
//   - Package Service: Secure package downloads with signature validation
//   - Support Service: Automated error reporting with AI assistance
//   - AI Investigation: Interactive troubleshooting with comprehensive anonymization
//
// Development Services:
//   - Threat Intelligence: IOC/IOA database access and threat analysis
//   - Vulnerability Assessment: CVE database integration and security scanning
//   - Knowledge Base: Cybersecurity knowledge search and best practices
//   - Computational Resources: Cloud-based intensive task processing
//
// # Data Anonymization
//
// The anonymizer package provides comprehensive protection for sensitive data:
//
//	import "github.com/vxcontrol/cloud/anonymizer"
//
//	// Initialize anonymizer
//	anon, err := anonymizer.NewAnonymizer(nil)
//	if err != nil {
//	    return err
//	}
//
//	// Anonymize sensitive data structures
//	sensitiveData := map[string]any{
//	    "user_email": "admin@company.com",
//	    "api_key": "sk-1234567890abcdef",
//	    "database_url": "postgres://user:pass@host:5432/db",
//	}
//
//	if err := anon.Anonymize(&sensitiveData); err != nil {
//	    return err
//	}
//	// Result: emails, credentials, URLs automatically masked
//
// Pattern Recognition:
//   - 300+ built-in patterns across General, PII, and Secrets categories
//   - Automatic detection of credentials, API keys, database URLs, IP addresses
//   - Structure-preserving anonymization maintains analytical value for AI
//   - Reflection-based processing for complex Go structures and nested data
//
// # Package Validation
//
// Cryptographic signature validation ensures package integrity:
//
//	import "github.com/vxcontrol/cloud/models"
//
//	// Validate package signatures
//	signature := models.SignatureValue("base64-signature")
//	if err := signature.ValidateFile("package.tar.gz"); err != nil {
//	    return fmt.Errorf("package validation failed: %w", err)
//	}
//
//	// Stream-based validation for large files
//	reader := signature.ValidateWrapReader(file)
//	// Process data while validating...
//	if err := reader.Valid(); err != nil {
//	    return fmt.Errorf("signature validation failed: %w", err)
//	}
//
// Signature Features:
//   - Ed25519 cryptographic signatures with SHA-512 hashing
//   - Streaming validation for large files without memory accumulation
//   - Built-in base64 encoding/decoding with validation
//   - Database integration support for signature storage
//
// # System Utilities
//
// Cross-platform machine identification for stable installation tracking:
//
//	import "github.com/vxcontrol/cloud/system"
//
//	// Generate stable installation ID
//	installationID := system.GetInstallationID()
//	// Returns same UUID for same machine across application restarts
//
//	// Use in SDK configuration
//	err := sdk.Build(configs,
//	    sdk.WithClient("MyApp", "1.0.0"),
//	    sdk.WithInstallationID(installationID),
//	)
//
// Platform Support:
//   - Linux: /var/lib/dbus/machine-id + SMBIOS data (when available)
//   - macOS: IOPlatformUUID from hardware registry via ioreg
//   - Windows: Registry MachineGuid + system product information via WMI
//
// Features:
//   - Deterministic: Same machine always generates same UUID
//   - Cross-Platform: Works on Linux, macOS, Windows
//   - Fallback Logic: Uses hostname when machine ID unavailable
//   - UUID Format: RFC4122 compliant UUID v3 (MD5-based)
//   - Performance: ~17ms generation time (acceptable for SDK initialization)
//
// # Examples
//
// Complete integration examples are available in the examples/ directory:
//
//   - examples/check-update: Update service integration with component management
//   - examples/download-installer: Package downloads with streaming signature validation
//   - examples/report-errors: Support workflow with automated data anonymization
//
// # License
//
// # Copyright (c) 2026 PentAGI Development Team
//
// This software is licensed under the **MIT License**.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// What this means for developers:
//
//	Free to use in any project (open source, commercial, proprietary)
//	No licensing fees for the SDK code itself
//	Modify and distribute freely with attribution
//	Integrate into commercial products without restrictions
//
// See LICENSE file for complete MIT license terms.
//
// # VXControl Cloud Services Access
//
// Important: While the SDK code is free (MIT), accessing VXControl Cloud Services
// requires a valid License Key and compliance with separate Terms of Service.
//
// The SDK provides client-side functionality to integrate with VXControl Cloud Platform,
// but actual access to sensitive cybersecurity data, threat intelligence, vulnerability
// information, and AI-powered assistance requires:
//
//	Valid License Key for API authentication
//	Compliance with VXControl Cloud Services Terms of Service
//	Authorized security testing and defensive cybersecurity use only
//	Responsible handling of obtained sensitive information
//
// Cloud Services Usage Model:
//
//	SDK Code: MIT licensed, free to use and modify
//	Cloud API Access: Requires License Key (contact info@vxcontrol.com)
//	Service Tiers: Free, Professional, and Enterprise levels available
//	Usage Restrictions: Governed by separate Terms of Service
//
// Before using cloud services, read: TERMS_OF_SERVICE.md
package cloud
