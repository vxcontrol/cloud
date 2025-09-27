package system

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGetInstallationID_Stability(t *testing.T) {
	// test that installation ID is stable across multiple calls
	id1 := GetInstallationID()
	id2 := GetInstallationID()

	if id1 != id2 {
		t.Errorf("installation ID is not stable: %s != %s", id1, id2)
	}

	// verify it's a valid UUID
	if id1 == uuid.Nil {
		t.Error("installation ID should not be nil UUID")
	}

	// test multiple calls to ensure consistency
	for i := range 10 {
		idN := GetInstallationID()
		if idN != id1 {
			t.Errorf("installation ID changed on call %d: %s != %s", i, idN, id1)
		}
	}
}

func TestGetInstallationID_ValidFormat(t *testing.T) {
	id := GetInstallationID()

	// verify UUID format
	idStr := id.String()
	if len(idStr) != 36 {
		t.Errorf("invalid UUID length: expected 36, got %d", len(idStr))
	}

	// verify it can be parsed back
	parsedID, err := uuid.Parse(idStr)
	if err != nil {
		t.Errorf("invalid UUID format: %v", err)
	}

	if parsedID != id {
		t.Errorf("UUID parsing mismatch: %s != %s", parsedID, id)
	}
}

func TestGetMachineID_NoError(t *testing.T) {
	// test that getMachineID doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("getMachineID panicked: %v", r)
		}
	}()

	machineID, err := getMachineID()

	t.Logf("Platform: %s", runtime.GOOS)
	t.Logf("Machine ID: %s", machineID)
	t.Logf("Error: %v", err)

	// on any platform, we should either get an ID or handle the error gracefully
	if err != nil {
		t.Logf("getMachineID failed (this is acceptable): %v", err)
	} else if machineID == "" {
		t.Log("getMachineID returned empty string (this is acceptable)")
	}
}

func TestGetHostname_NoError(t *testing.T) {
	// test that getHostname doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("getHostname panicked: %v", r)
		}
	}()

	hostname := getHostname()
	t.Logf("Hostname: %s", hostname)

	// hostname can be empty in some environments, that's acceptable
}

func BenchmarkGetInstallationID(b *testing.B) {
	for b.Loop() {
		_ = GetInstallationID()
	}
}

func TestInstallationID_CrossPlatformConsistency(t *testing.T) {
	// test that installation ID generation doesn't panic on any platform
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GetInstallationID panicked: %v", r)
		}
	}()

	id := GetInstallationID()
	t.Logf("Platform: %s", runtime.GOOS)
	t.Logf("Installation ID: %s", id.String())

	// verify UUID version (should be version 3 for MD5-based UUID)
	if id.Version() != 3 {
		t.Errorf("expected UUID version 3 (MD5), got version %d", id.Version())
	}

	// verify UUID variant
	if id.Variant() != uuid.RFC4122 {
		t.Errorf("expected RFC4122 variant, got %d", id.Variant())
	}
}

func TestMachineID_PlatformSpecific(t *testing.T) {
	machineID, err := getMachineID()

	t.Logf("Platform: %s", runtime.GOOS)
	t.Logf("Machine ID: %s", machineID)
	t.Logf("Error: %v", err)

	// Platform-specific validation
	switch runtime.GOOS {
	case "darwin":
		// on macOS, we expect either a valid UUID or an error
		if err == nil && machineID != "" {
			// should be a valid UUID format from IOPlatformUUID
			if len(machineID) != 36 {
				t.Logf("macOS machine ID has unexpected length: %d (expected 36)", len(machineID))
			}
		}

	case "linux":
		// on Linux, we expect either machine-id or an error
		if err == nil && machineID != "" {
			// machine-id is usually 32 hex characters, but can be extended with SMBIOS
			if len(machineID) < 32 {
				t.Logf("Linux machine ID shorter than expected: %d", len(machineID))
			}
		}

	case "windows":
		// on Windows, we expect either MachineGuid or an error
		if err == nil && machineID != "" {
			// should contain both MachineGuid and system product info
			if !strings.Contains(machineID, ":") {
				t.Logf("Windows machine ID missing system product info")
			}
		}
	}

	// test that fallback logic works correctly
	// even if machine ID fails, GetInstallationID should still work
	installationID := GetInstallationID()
	if installationID == uuid.Nil {
		t.Error("installation ID should not be nil even when machine ID fails")
	}
}

func TestInstallationID_UniqueAcrossSessions(t *testing.T) {
	// simulate getting installation ID multiple times
	// to ensure it's deterministic

	ids := make(map[uuid.UUID]bool)

	// get installation ID 100 times
	for range 100 {
		id := GetInstallationID()
		ids[id] = true
	}

	// should always be exactly 1 unique ID
	if len(ids) != 1 {
		t.Errorf("installation ID not deterministic: got %d unique IDs", len(ids))
		for id := range ids {
			t.Logf("ID: %s", id.String())
		}
	}
}
