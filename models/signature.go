package models

import (
	"crypto/ed25519"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"os"
)

type SignatureValue string

func (sv *SignatureValue) FromBytes(b []byte) (SignatureValue, error) {
	if sv == nil {
		return "", fmt.Errorf("signature value is nil")
	}

	if len(b) != ed25519.SignatureSize {
		return "", fmt.Errorf("invalid signature length")
	}

	*sv = SignatureValue(base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(b))

	return *sv, nil
}

func (sv SignatureValue) ToBytes() ([]byte, error) {
	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(string(sv))
}

func (sv SignatureValue) String() string {
	return string(sv)
}

func (sv *SignatureValue) Scan(value any) error {
	if value == nil {
		*sv = ""
		return nil
	}

	if bv, err := driver.String.ConvertValue(value); err == nil {
		if v, ok := bv.(string); ok {
			*sv = SignatureValue(v)
			return nil
		}
	}

	return fmt.Errorf("cannot scan %T into SignatureValue", value)
}

func (sv SignatureValue) Value() (driver.Value, error) {
	return string(sv), nil
}

func (sv SignatureValue) Valid() error {
	signature, err := sv.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}

	return nil
}

func (sv SignatureValue) ValidateFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := sv.ValidateWrapReader(file)

	if _, err = io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("failed to validate file: %w", err)
	}

	return reader.Valid()
}

func (sv SignatureValue) ValidateData(data []byte) error {
	h := sha512.New()
	h.Write(data)
	return sv.ValidateHash(h.Sum(nil))
}

func (sv SignatureValue) ValidateHash(hash []byte) error {
	if len(hash) != sha512.Size {
		return fmt.Errorf("invalid hash length")
	}

	signature, err := sv.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	valid := ed25519.Verify(getSignaturePublicKey(), hash, signature)
	if !valid {
		return fmt.Errorf("failed to verify signature")
	}

	return nil
}

func (sv SignatureValue) ValidateWrapReader(r io.Reader) SignatureReader {
	return &signatureReader{h: sha512.New(), r: r, s: sv}
}

func (sv SignatureValue) ValidateWrapWriter(w io.Writer) SignatureWriter {
	return &signatureWriter{h: sha512.New(), w: w, s: sv}
}

type SignatureWriter interface {
	io.Writer
	IValid
}

type signatureWriter struct {
	h hash.Hash
	w io.Writer
	s SignatureValue
}

func (w *signatureWriter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	if n != 0 {
		_, _ = w.h.Write(p[:n])
	}
	return
}

func (w *signatureWriter) Valid() error {
	return w.s.ValidateHash(w.h.Sum(nil))
}

type SignatureReader interface {
	io.Reader
	IValid
}

type signatureReader struct {
	h hash.Hash
	r io.Reader
	s SignatureValue
}

func (r *signatureReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if n != 0 {
		_, _ = r.h.Write(p[:n])
	}
	return
}

func (r *signatureReader) Valid() error {
	return r.s.ValidateHash(r.h.Sum(nil))
}
