package models

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"os"
	"testing"
)

// test scenario with data and expected signature
type testScenario struct {
	name      string
	data      []byte
	signature string
}

// static test scenarios with pre-generated signatures
var testScenarios = []testScenario{
	{
		name:      "empty_data",
		data:      []byte(nil),
		signature: "kXpU580XomsHUc0W1Epv83kx9958ZEoc82c6v9CWn4VCzUhiv2d65Z6pxyvcDAqcTWVksFNTq+WSuQI4BPgcDQ",
	},
	{
		name:      "short_text",
		data:      []byte("hello"),
		signature: "HBn0P1kMfFysBgg8I7mFws2IPDFMGd7sodrVCheJjmwNIq0Fnw1YVarizd0UgFC50hZ2HAsCAhyqWKkJToaqCw",
	},
	{
		name:      "medium_text",
		data:      []byte("test signature validation"),
		signature: "QPLFdvQOth0fD5p47Dv+DFePquvqp1tvSafsUtM31ylKKoTMrJUc3Xd2wrqVGDU2KhwjuA0FH6CgDdlmZ73PAw",
	},
	{
		name:      "json_data",
		data:      []byte(`{"version":"1.0","component":"pentagi","action":"update"}`),
		signature: "kqTQFYJr2ExaYpjPltYtHBBN/MGIyuqLufOJC2VuWw2Lx0LsLfTrEqCVZZBJQMq80lbUP822AvMgJRGXqddEDQ",
	},
	{
		name:      "binary_data",
		data:      []byte("\x00\x01\x02\x03\xff\xfe\xfd\xfc"),
		signature: "3NsPpsAQWatTJFg2D8jvvHmN3yIVKtCn/fFKiE2+emGKY1NlLh25OFFDBC0K5gx3bLJUOBQfprY7wVugXOw6AA",
	},
	{
		name:      "repeated_pattern_256b",
		data:      bytes.Repeat([]byte("A"), 256),
		signature: "xZEOlq7qcr+ONVMxqCaNLXcJY/R5y7Jr1CVM7nYZmrUNMfQlC+7c/FMfaBNivxZTq4+8WYcDXNeh8RpUbkXeDg",
	},
	{
		name:      "repeated_pattern_700b",
		data:      bytes.Repeat([]byte("pattern"), 100),
		signature: "x8ufqgotq9jzOIi6+9ONOTvRtx02bGnnHkgyz+UFJK2kNzXlaI0RDnN/iEWfVUy6qzxF+K4H0gLw7+LdulmOAA",
	},
	{
		name: "random_64b",
		data: func() []byte {
			r := rand.New(rand.NewSource(42))
			data := make([]byte, 64)
			r.Read(data)
			return data
		}(),
		signature: "Nar735e4spAROIEzmSBgNC9fyF/hQLg0WMHv4legbksB3ag3nBvGGGgcryJ3u3E/svYQRXaTKKbgZT08a7OdBQ",
	},
	{
		name: "random_10kb",
		data: func() []byte {
			data := make([]byte, 10*1024)
			r := rand.New(rand.NewSource(123))
			r.Read(data)
			return data
		}(),
		signature: "4jjazjdCwcn6anPK4j6yTmcZBuEByZCD6dAz8XMRER9mCSyYiFWJHxeeCIp5Q18zzbUpXJP5Gy+7AcTH6s+3CQ",
	},
	{
		name: "structured_100kb",
		data: func() []byte {
			data := make([]byte, 100*1024)
			for i := range data {
				data[i] = byte(i % 256)
			}
			return data
		}(),
		signature: "/qVFpJ8CTXgF4DZmsIsztDiLg7Wdr2OUolaWnNCBGB7CP8XHq7Mb9t8wo4vOU9tC3iiPKMaDiz1wN04KfyJxCw",
	},
	{
		name: "stress_10mb",
		data: func() []byte {
			data := make([]byte, 10*1024*1024)
			r := rand.New(rand.NewSource(456))
			for i := 0; i < len(data); i += 4096 {
				end := min(i+4096, len(data))
				_, _ = r.Read(data[i:end])
			}
			return data
		}(),
		signature: "ynchaH0EPK+vwyjUcXN6IONf0RkYn0BdReTqjobmAVkK0eNUObsXYZoaCmw9ImcVtASVgEJ3VPo8TOV7cnCBDw",
	},
}

func TestSignatureValue_FromBytes(t *testing.T) {
	// test with real signature from first scenario
	realSig, _ := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(testScenarios[0].signature)

	t.Run("valid_signature", func(t *testing.T) {
		var sv SignatureValue
		result, err := sv.FromBytes(realSig)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != SignatureValue(testScenarios[0].signature) {
			t.Error("signature mismatch")
		}
	})

	t.Run("invalid_length", func(t *testing.T) {
		var sv SignatureValue
		_, err := sv.FromBytes([]byte("short"))
		if err == nil {
			t.Error("expected error for invalid length")
		}
	})

	t.Run("nil_receiver", func(t *testing.T) {
		var sv *SignatureValue
		_, err := sv.FromBytes(realSig)
		if err == nil {
			t.Error("expected error for nil receiver")
		}
	})
}

func TestSignatureValue_ValidateData(t *testing.T) {
	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			signature := SignatureValue(scenario.signature)
			err := signature.ValidateData(scenario.data)
			if err != nil {
				t.Errorf("validation failed for %s: %v", scenario.name, err)
			}
		})
	}

	// test with corrupted signature
	t.Run("corrupted_signature", func(t *testing.T) {
		corruptedSig := SignatureValue("invalid_signature_base64")
		err := corruptedSig.ValidateData(testScenarios[0].data)
		if err == nil {
			t.Error("expected validation failure for corrupted signature")
		}
	})

	// test with wrong data
	t.Run("wrong_data", func(t *testing.T) {
		signature := SignatureValue(testScenarios[1].signature)
		wrongData := append(testScenarios[1].data, byte('x'))
		err := signature.ValidateData(wrongData)
		if err == nil {
			t.Error("expected validation failure for wrong data")
		}
	})
}

func TestSignatureValue_ValidateFile(t *testing.T) {
	// create temp file with known data
	tmpfile, err := os.CreateTemp("", "signature_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	testData := testScenarios[2].data
	if _, err := tmpfile.Write(testData); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	t.Run("valid_file", func(t *testing.T) {
		signature := SignatureValue(testScenarios[2].signature)
		err := signature.ValidateFile(tmpfile.Name())
		if err != nil {
			t.Errorf("file validation failed: %v", err)
		}
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		signature := SignatureValue(testScenarios[0].signature)
		err := signature.ValidateFile("/nonexistent/path")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestSignatureValue_WrapReader(t *testing.T) {
	scenario := testScenarios[3] // json data scenario
	reader := bytes.NewReader(scenario.data)
	signature := SignatureValue(scenario.signature)

	wrappedReader := signature.ValidateWrapReader(reader)

	// read all data
	readData, err := bytes.NewBuffer(nil).ReadFrom(wrappedReader)
	if err != nil {
		t.Errorf("read error: %v", err)
	}
	if readData != int64(len(scenario.data)) {
		t.Errorf("read %d bytes, expected %d", readData, len(scenario.data))
	}

	// validate
	if err := wrappedReader.Valid(); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

func TestSignatureValue_WrapWriter(t *testing.T) {
	scenario := testScenarios[4] // binary data scenario
	var buffer bytes.Buffer
	signature := SignatureValue(scenario.signature)

	wrappedWriter := signature.ValidateWrapWriter(&buffer)

	// write data
	n, err := wrappedWriter.Write(scenario.data)
	if err != nil {
		t.Errorf("write error: %v", err)
	}
	if n != len(scenario.data) {
		t.Errorf("wrote %d bytes, expected %d", n, len(scenario.data))
	}

	// validate
	if err := wrappedWriter.Valid(); err != nil {
		t.Errorf("validation failed: %v", err)
	}

	// verify written data
	if !bytes.Equal(buffer.Bytes(), scenario.data) {
		t.Error("written data doesn't match original")
	}
}

func TestSignatureValue_EdgeCases(t *testing.T) {
	t.Run("invalid_base64", func(t *testing.T) {
		signature := SignatureValue("invalid!@#base64")
		err := signature.Valid()
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("wrong_length_base64", func(t *testing.T) {
		shortSig := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(make([]byte, 32))
		signature := SignatureValue(shortSig)
		err := signature.Valid()
		if err == nil {
			t.Error("expected error for wrong signature length")
		}
	})

	t.Run("invalid_hash_length", func(t *testing.T) {
		signature := SignatureValue(testScenarios[0].signature)
		err := signature.ValidateHash([]byte("short_hash"))
		if err == nil {
			t.Error("expected error for invalid hash length")
		}
	})
}

// benchmarks for performance testing
func BenchmarkSignatureValue_ValidateData_Small(b *testing.B) {
	signature := SignatureValue(testScenarios[1].signature) // short text
	data := testScenarios[1].data

	b.ResetTimer()
	for b.Loop() {
		_ = signature.ValidateData(data)
	}
}

func BenchmarkSignatureValue_ValidateData_Large(b *testing.B) {
	signature := SignatureValue(testScenarios[8].signature) // 10KB
	data := testScenarios[8].data

	b.ResetTimer()
	for b.Loop() {
		_ = signature.ValidateData(data)
	}
}

func BenchmarkSignatureValue_ValidateData_Huge(b *testing.B) {
	signature := SignatureValue(testScenarios[10].signature) // 10MB
	data := testScenarios[10].data

	b.ResetTimer()
	for b.Loop() {
		_ = signature.ValidateData(data)
	}
}
