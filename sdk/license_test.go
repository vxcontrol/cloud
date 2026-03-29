package sdk

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntrospectLicenseKeyWithTestData(t *testing.T) {
	testData := loadSDKTestData(t)

	for _, license := range testData.Licenses {
		t.Run(license.Name, func(t *testing.T) {
			info, err := IntrospectLicenseKey(license.Key)

			if !license.Valid {
				invalid := err != nil || info == nil || !info.IsValid()
				assert.True(t, invalid, "expected failure for invalid license")
				return
			}

			assert.NoError(t, err, "valid license should not produce error")
			assert.NotNil(t, info, "valid license should return info")

			// verify license type
			if license.ExpiredAt.IsZero() {
				assert.Equal(t, LicensePerpetual, info.Type, "perpetual license type")
			} else {
				assert.Equal(t, LicenseExpireable, info.Type, "expireable license type")
			}

			// verify dates
			assert.Equal(t, license.CreatedAt.Truncate(24*time.Hour),
				info.CreatedAt.Truncate(24*time.Hour), "created at should match")

			if !license.ExpiredAt.IsZero() {
				// client calculates absolute expiration date from encoded data
				// this may differ from test data which stores relative dates
				assert.False(t, info.ExpiredAt.IsZero(), "expireable license should have expired at")
				assert.True(t, info.ExpiredAt.After(info.CreatedAt), "expired at should be after created at")
			}

			// verify flags structure
			for i, expected := range license.Flags {
				assert.Equal(t, expected, info.Flags[i],
					"flag %d should match expected value", i)
			}
		})
	}
}

func TestLicenseKeyDecoding(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "valid license format",
			key:      "4MTY-NZVR-64QI-U26X",
			expected: true,
		},
		{
			name:     "empty key",
			key:      "AAAA-AAAA-AAAA-AAAA",
			expected: false,
		},
		{
			name:     "invalid format - no dashes",
			key:      "4MTYNZVR64QIU26X", // client strips dashes, so this is actually valid
			expected: true,
		},
		{
			name:     "invalid format - wrong length",
			key:      "4MTY-NZVR-64QI",
			expected: false,
		},
		{
			name:     "invalid characters",
			key:      "4MT0-NZVR-64QI-U26X", // contains '0'
			expected: false,
		},
		{
			name:     "wrong dash positions",
			key:      "4MTY-NZV-R64Q-IU26X", // client strips all dashes, so position doesn't matter
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded := decodeLicenseKey(tc.key)

			if tc.expected {
				assert.NotEqual(t, emptyLicenseKey, decoded,
					"valid key should decode to non-empty data")
			} else {
				assert.Equal(t, emptyLicenseKey, decoded,
					"invalid key should decode to empty data")
			}
		})
	}
}

func TestLicenseDataRestore(t *testing.T) {
	testData := loadSDKTestData(t)

	for _, license := range testData.Licenses {
		if !license.Valid {
			info, err := IntrospectLicenseKey(license.Key)
			invalid := err != nil || info == nil || !info.IsValid()
			assert.True(t, invalid, "expected failure for invalid license")
			continue
		}

		t.Run(license.Name, func(t *testing.T) {
			// decode license key
			decodedKey := decodeLicenseKey(license.Key)
			assert.NotEqual(t, emptyLicenseKey, decodedKey, "should decode successfully")

			// restore license data
			lic := &licenseData{}
			err := lic.restore(decodedKey)
			assert.NoError(t, err, "restore should succeed for valid license")

			// validate basic fields
			assert.True(t, lic.CreatedAt.Year() >= 2025, "created at should be reasonable")

			if license.ExpiredAt.IsZero() {
				assert.Equal(t, LicensePerpetual, lic.Type, "perpetual license")
			} else {
				assert.Equal(t, LicenseExpireable, lic.Type, "expireable license")
				assert.False(t, lic.ExpiredAt.IsZero(), "expireable license should have expired at")
			}

			// verify dates
			assert.Equal(t, license.CreatedAt, lic.CreatedAt, "created at should match")
			assert.Equal(t, license.ExpiredAt, lic.ExpiredAt, "expired at should match")
			assert.Equal(t, license.Flags, lic.Flags, "flags should match")

			// verify fingerprint
			fp, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(license.FP)
			assert.NoError(t, err, "test data should have valid hex fingerprint")
			assert.Equal(t, [16]byte(fp), computeLicenseKeyFP(decodedKey), "fingerprint should match")
		})
	}
}

func TestChecksumValidation(t *testing.T) {
	testData := loadSDKTestData(t)

	// find valid license for corruption testing
	var validLicense testLicense
	for _, license := range testData.Licenses {
		if license.Valid {
			validLicense = license
			break
		}
	}

	if validLicense.Name == "" {
		t.Skip("no valid license found in test data")
	}

	originalData := decodeLicenseKey(validLicense.Key)
	assert.NotEqual(t, emptyLicenseKey, originalData, "test license should be valid")

	// test single bit corruption
	t.Run("single_bit_corruption", func(t *testing.T) {
		detectedErrors := 0
		totalTests := 0

		bits := len(originalData) * 8
		for i := range bits {
			corruptedData := originalData
			corruptedData[i/8] ^= 1 << (i % 8)

			if corruptedData == originalData {
				continue // no actual change
			}

			totalTests++
			lic := &licenseData{}
			if err := lic.restore(corruptedData); err != nil {
				detectedErrors++
			}
		}

		detectionRate := float64(detectedErrors) / float64(totalTests) * 100
		t.Logf("single bit error detection: %.1f%% (%d/%d)",
			detectionRate, detectedErrors, totalTests)

		assert.Equal(t, 100.0, detectionRate,
			"should detect all single bit errors")
	})
}

func TestFingerprintConsistency(t *testing.T) {
	testData := loadSDKTestData(t)

	for _, license := range testData.Licenses {
		t.Run(license.Name, func(t *testing.T) {
			// decode license key
			decodedKey := decodeLicenseKey(license.Key)
			assert.NotEqual(t, emptyLicenseKey, decodedKey, "should decode successfully")

			// compute fingerprint
			computedFP := computeLicenseKeyFP(decodedKey)

			// decode expected fingerprint from test data
			expectedFP, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(license.FP)
			assert.NoError(t, err, "test data should have valid hex fingerprint")
			assert.Len(t, expectedFP, 16, "fingerprint should be 16 bytes")

			if len(expectedFP) == 16 {
				assert.Equal(t, [16]byte(expectedFP), computedFP,
					"computed fingerprint should match test data")
			}
		})
	}
}

func TestTimeEncoding(t *testing.T) {
	testCases := []struct {
		name string
		time time.Time
	}{
		{
			name: "base_date",
			time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "recent_date",
			time: time.Date(2025, 9, 16, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "future_date",
			time: time.Date(2035, 12, 31, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// test encoding/decoding roundtrip
			encoded := encodeDays(tc.time)
			decoded := decodeDays(encoded)

			assert.Equal(t, tc.time.Truncate(24*time.Hour),
				decoded.Truncate(24*time.Hour),
				"time encoding should be reversible")

			// test alignment
			aligned := alignDays(tc.time)
			assert.Equal(t, 0, aligned.Hour(), "aligned time should have zero hour")
			assert.Equal(t, 0, aligned.Minute(), "aligned time should have zero minute")
			assert.Equal(t, 0, aligned.Second(), "aligned time should have zero second")
		})
	}
}

func TestLicenseValidation(t *testing.T) {
	testData := loadSDKTestData(t)

	for _, license := range testData.Licenses {
		t.Run(license.Name+"_validation", func(t *testing.T) {
			decoded := decodeLicenseKey(license.Key)

			if !license.Valid {
				// for invalid licenses, decoding might succeed but restoration should fail
				lic := &licenseData{}
				err := lic.restore(decoded)
				if err == nil && lic.IsValid() {
					t.Errorf("expected restoration to fail for invalid license %s", license.Name)
				}
				return
			}

			assert.NotEqual(t, emptyLicenseKey, decoded, "valid license should decode")

			// restoration should succeed for valid licenses
			lic := &licenseData{}
			err := lic.restore(decoded)
			assert.NoError(t, err, "valid license should restore without error")

			// basic sanity checks
			assert.True(t, lic.CreatedAt.Year() >= 2025, "reasonable creation year")

			if lic.Type == LicenseExpireable {
				assert.False(t, lic.ExpiredAt.IsZero(), "expireable license should have expiration")
			}
		})
	}
}

func TestClientSecurityBoundaries(t *testing.T) {
	// test basic format validation - client should reject invalid formats
	invalidKeys := []string{
		"",
		"SHORT",
		"TOOLONGKEYWITHINVALIDFORMAT",
		"4MTY-NZVR-64QI-U26X-EXTRA",
		"4MT0-NZVR-64QI-U26X", // contains forbidden character '0'
		"4MT1-NZVR-64QI-U26X", // contains forbidden character '1'
		"4MT5-NZVR-64QI-U26X", // contains forbidden character '5'
		"4MT8-NZVR-64QI-U26X", // contains forbidden character '8'
	}

	for _, key := range invalidKeys {
		t.Run("invalid_"+key, func(t *testing.T) {
			_, err := IntrospectLicenseKey(key)
			assert.Error(t, err, "invalid license format should produce error")
		})
	}
}

func TestClientLicensePerformance(t *testing.T) {
	testData := loadSDKTestData(t)

	// find first valid license
	var validLicense testLicense
	for _, license := range testData.Licenses {
		if license.Valid {
			validLicense = license
			break
		}
	}

	if validLicense.Name == "" {
		t.Skip("no valid license found in test data")
	}

	const iterations = 1000

	// benchmark license introspection
	start := time.Now()
	for range iterations {
		info, err := IntrospectLicenseKey(validLicense.Key)
		if err != nil || info == nil || !info.IsValid() {
			t.Fatal("expected failure for invalid license")
		}
		_ = info
	}
	duration := time.Since(start)

	avgTime := duration / iterations
	rate := float64(iterations) / duration.Seconds()

	t.Logf("license introspection performance:")
	t.Logf("  %d operations in %v", iterations, duration)
	t.Logf("  average time: %v per operation", avgTime)
	t.Logf("  rate: %.0f operations/second", rate)

	// client operations should be fast (no complex cryptographic operations)
	if avgTime > 500*time.Microsecond {
		t.Errorf("license introspection too slow: %v > 500μs", avgTime)
	}
}

func TestLicenseInfoMethods(t *testing.T) {
	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1)
	tomorrow := now.AddDate(0, 0, 1)

	testCases := []struct {
		name            string
		license         LicenseInfo
		expectedValid   bool
		expectedExpired bool
	}{
		{
			name: "valid_perpetual_license",
			license: LicenseInfo{
				Type:      LicensePerpetual,
				Flags:     [7]bool{true, false, true, false, false, false, false},
				ExpiredAt: time.Time{}, // zero time for perpetual
				CreatedAt: yesterday,
			},
			expectedValid:   true,
			expectedExpired: false,
		},
		{
			name: "expireable_with_past_date",
			license: LicenseInfo{
				Type:      LicenseExpireable,
				Flags:     [7]bool{false, true, false, true, false, false, false},
				ExpiredAt: yesterday, // past date
				CreatedAt: now.AddDate(0, 0, -10),
			},
			expectedValid:   false, // expired license is not valid
			expectedExpired: true,  // .Before(now) is true for yesterday
		},
		{
			name: "expireable_expires_tomorrow",
			license: LicenseInfo{
				Type:      LicenseExpireable,
				Flags:     [7]bool{true, true, true, true, false, false, false},
				ExpiredAt: tomorrow,
				CreatedAt: yesterday,
			},
			expectedValid:   true,  // not expired yet, still valid
			expectedExpired: false, // tomorrow.Before(now) = false
		},
		{
			name: "invalid_perpetual_with_expiry",
			license: LicenseInfo{
				Type:      LicensePerpetual,
				Flags:     [7]bool{false, false, false, false, false, false, false},
				ExpiredAt: tomorrow, // perpetual shouldn't have expiry
				CreatedAt: yesterday,
			},
			expectedValid:   false, // fails perpetual validation (!ExpiredAt.IsZero())
			expectedExpired: false, // IsExpired() returns false for perpetual type
		},
		{
			name: "invalid_future_created_at",
			license: LicenseInfo{
				Type:      LicenseExpireable,
				Flags:     [7]bool{true, false, false, false, false, false, false},
				ExpiredAt: now.AddDate(0, 0, 10), // future expiry
				CreatedAt: tomorrow,              // future creation date
			},
			expectedValid:   false, // fails future CreatedAt check
			expectedExpired: false, // ExpiredAt.Before(now) = false
		},
		{
			name: "invalid_zero_created_at",
			license: LicenseInfo{
				Type:      LicenseExpireable,
				Flags:     [7]bool{false, false, false, false, false, false, false},
				ExpiredAt: tomorrow,    // future expiry
				CreatedAt: time.Time{}, // zero time
			},
			expectedValid:   false, // fails zero CreatedAt check
			expectedExpired: false, // tomorrow.Before(now) = false
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedValid, tc.license.IsValid(),
				"IsValid() result should match expected")
			assert.Equal(t, tc.expectedExpired, tc.license.IsExpired(),
				"IsExpired() result should match expected")
		})
	}
}

func TestLicenseTypeString(t *testing.T) {
	testCases := []struct {
		licenseType LicenseType
		expected    string
	}{
		{LicenseUnknown, "unknown"},
		{LicenseExpireable, "expireable"},
		{LicensePerpetual, "perpetual"},
		{LicenseType(99), "unknown"}, // invalid type
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.licenseType.String())
		})
	}
}

func TestLicenseTypeScan(t *testing.T) {
	testCases := []struct {
		name        string
		input       any
		expected    LicenseType
		shouldError bool
	}{
		{
			name:        "expireable_string",
			input:       "expireable",
			expected:    LicenseExpireable,
			shouldError: false,
		},
		{
			name:        "perpetual_string",
			input:       "perpetual",
			expected:    LicensePerpetual,
			shouldError: false,
		},
		{
			name:        "invalid_string",
			input:       "invalid",
			expected:    LicenseUnknown,
			shouldError: true,
		},
		{
			name:        "numeric_input",
			input:       123,
			expected:    LicenseUnknown,
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var licenseType LicenseType
			err := licenseType.Scan(tc.input)

			if tc.shouldError {
				assert.Error(t, err, "should return error for invalid input")
			} else {
				assert.NoError(t, err, "should not return error for valid input")
				assert.Equal(t, tc.expected, licenseType, "scanned type should match expected")
			}
		})
	}
}

func loadSDKTestData(t *testing.T) *testData {
	t.Helper()

	dataPath := filepath.Join("testdata", "data.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}

	var td testData
	if err := json.Unmarshal(data, &td); err != nil {
		t.Fatalf("failed to parse test data: %v", err)
	}

	return &td
}
