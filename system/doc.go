// Package system provides cross-platform utilities for stable machine identification and installation tracking.
//
// The system package implements secure, deterministic installation ID generation that remains
// stable across application restarts on the same machine. It uses platform-specific machine
// identification methods with graceful fallback to ensure reliable operation across different
// environments and privilege levels.
//
// # Core Functionality
//
// The main function generates stable installation IDs for SDK usage:
//
//	import "github.com/vxcontrol/cloud/system"
//
//	// Generate stable installation ID
//	installationID := system.GetInstallationID()
//	// Returns same UUID for same machine across application restarts
//
//	// Use with VXControl Cloud SDK
//	err := sdk.Build(configs,
//	    sdk.WithClient("MyApp", "1.0.0"),
//	    sdk.WithInstallationID(installationID),
//	)
//
// # Platform-Specific Implementation
//
// ## Linux Implementation
//
// Uses multiple identification sources for maximum stability:
//
//	// Primary: D-Bus machine ID
//	machineID := readFile("/var/lib/dbus/machine-id")
//	// Fallback: Alternative location
//	machineID := readFile("/etc/machine-id")
//
//	// Enhancement: SMBIOS data (when available)
//	systemUUID := getSMBIOSAttribute(SystemUUID)
//	systemManufacturer := getSMBIOSAttribute(SystemManufacturer)
//	systemProduct := getSMBIOSAttribute(SystemProductName)
//
// Linux Features:
//   - Primary: 32-character hex machine ID from systemd
//   - Enhancement: SMBIOS system information (requires root privileges)
//   - Fallback: hostname-based identification
//   - Graceful: Handles permission restrictions and missing files
//
// ## macOS Implementation
//
// Uses hardware platform UUID from system registry:
//
//	// Hardware platform UUID via ioreg
//	ioregOutput := exec("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
//	platformUUID := extractIOPlatformUUID(ioregOutput)
//
// macOS Features:
//   - Hardware-based: IOPlatformUUID from system firmware
//   - Stable: Persists across OS reinstalls and updates
//   - Secure: No special privileges required
//   - Format: Standard UUID format (36 characters)
//
// ## Windows Implementation
//
// Uses registry machine GUID with system product information:
//
//	// Registry machine GUID
//	machineGuid := registry.GetStringValue("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid")
//
//	// System product info via WMI
//	systemProduct := wmi.Query("SELECT * FROM Win32_ComputerSystemProduct")
//	combinedID := machineGuid + ":" + systemProduct.UUID
//
// Windows Features:
//   - Registry-based: Cryptographic machine GUID from Windows
//   - Enhanced: WMI system product information
//   - Stable: Survives most system changes and updates
//   - Comprehensive: Combines multiple identification sources
//
// # Fallback Strategy
//
// Graceful degradation when primary identification fails:
//
//	func GetInstallationID() uuid.UUID {
//	    machineID, err := getMachineID()
//	    if err != nil || machineID == "" {
//	        // Fallback to hostname
//	        machineID = getHostname()
//	        if machineID == "" {
//	            // Final fallback to static value
//	            machineID = "unknown-host"
//	        }
//	    }
//
//	    // Generate deterministic UUID
//	    hash := md5.Sum([]byte(machineID + salt))
//	    return uuid.NewMD5(uuid.NameSpaceURL, hash[:])
//	}
//
// Fallback Levels:
//  1. Platform-specific machine ID (preferred)
//  2. System hostname (degraded uniqueness)
//  3. Static identifier (stable but not unique)
//
// # Security Considerations
//
// ## Cryptographic Properties
//
//	// Deterministic UUID generation
//	salt := "*********************"
//	hash := md5.Sum([]byte(machineID + salt))
//	uuid := uuid.NewMD5(uuid.NameSpaceURL, hash[:])
//
// Security Features:
//   - Salt Protection: Fixed salt prevents rainbow table attacks
//   - MD5 Hashing: Sufficient for non-cryptographic identification
//   - UUID v3: RFC4122 compliant deterministic UUID generation
//   - NameSpace: URL namespace provides additional domain separation
//
// ## Privacy Protection
//
//	// Machine identifiers are hashed before use
//	// Original machine ID is never transmitted to cloud services
//	// Only the derived UUID is sent as X-Installation-ID header
//
// Privacy Features:
//   - Hash-based: Original machine identifiers never exposed
//   - Irreversible: Cannot derive machine ID from installation UUID
//   - Stable: Same UUID for legitimate re-installations
//   - Unique: Different UUID for different machines (in most cases)
//
// # Performance Characteristics
//
// ## Timing Analysis
//
// Benchmark results (Apple M2 Max):
//   - Average generation time: ~17ms per call
//   - Variation: Depends on platform and system access speed
//   - Caching: No internal caching (called once per SDK initialization)
//
// Performance Factors:
//   - Linux: File system access + optional SMBIOS reads
//   - macOS: Process execution (ioreg command)
//   - Windows: Registry access + WMI queries
//   - Network: No network dependencies
//
// ## Memory Usage
//
//	// Minimal memory footprint
//	// No persistent state or caching
//	// Platform-specific temporary allocations only
//
// Memory Characteristics:
//   - Zero persistent memory usage
//   - Temporary allocations for system calls
//   - No internal caching or state management
//   - Garbage collection friendly
//
// # Integration Guidelines
//
// ## SDK Integration
//
// Recommended usage pattern for VXControl Cloud SDK:
//
//	// Initialize once per application lifecycle
//	installationID := system.GetInstallationID()
//
//	// Use in SDK configuration
//	err := sdk.Build(configs,
//	    sdk.WithInstallationID(installationID),
//	    // ... other options
//	)
//
// ## Error Handling
//
// Robust error handling for system identification:
//
//	// GetInstallationID never fails or panics
//	// Always returns valid UUID, even in degraded environments
//	installationID := system.GetInstallationID()
//
//	// For diagnostic purposes, check machine ID separately
//	machineID, err := getMachineID()
//	if err != nil {
//	    log.Printf("Machine ID unavailable (using fallback): %v", err)
//	} else {
//	    log.Printf("Machine ID: %s", machineID)
//	}
//
// ## Threading Considerations
//
//	// GetInstallationID is thread-safe
//	// Can be called concurrently from multiple goroutines
//	// No internal state or synchronization required
//
// Thread Safety:
//   - Concurrent access safe
//   - No shared state
//   - Idempotent operation
//   - No race conditions
package system
