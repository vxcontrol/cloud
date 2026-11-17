package models

import (
	"crypto/sha512"
	"fmt"
	"regexp"
	"time"
)

// LicenseQuotaUnlimited is the share of a quota that has no ceiling.
const LicenseQuotaUnlimited = -1

// The quotas a licence is told of, by the name of their limit. Known names, not a closed
// list: a limit the server adds later is read by its name like these.
const (
	LicenseQuotaLLMAgent      = "llm_agent"
	LicenseQuotaLLMAutomation = "llm_automation"
	LicenseQuotaLLMCompletion = "llm_completion"
	LicenseQuotaLLMEmbedding  = "llm_embedding"
)

// LicenseFeatures are the features a licence enables, as they are served: CloudLLM is
// false for a licence whose tier is not served Cloud LLM even when its key carries the
// flag.
type LicenseFeatures struct {
	Updates       bool `json:"updates"`
	Support       bool `json:"support"`
	KnowledgeBase bool `json:"knowledge_base"`
	CloudLLM      bool `json:"cloud_llm"`
}

// LicenseQuotaUsage is the share of a quota used in one period, in whole percent from 0
// to 100, or LicenseQuotaUnlimited for no ceiling. 0 is nothing used, any use is at least
// 1, and 100 is a quota used up — the next call is refused. Tokens is the larger share of
// the input and the output tokens, and is absent for a quota that meters no tokens.
type LicenseQuotaUsage struct {
	Requests int  `json:"requests" validate:"min=-1,max=100"`
	Tokens   *int `json:"tokens,omitempty" validate:"omitempty,min=-1,max=100"`
}

// LicenseQuota is the use of one limit of a licence: today, a UTC day, and this month of
// the licence — counted from the day of the month its first key was issued.
type LicenseQuota struct {
	Limit   string            `json:"limit" validate:"required"`
	Daily   LicenseQuotaUsage `json:"daily"`
	Monthly LicenseQuotaUsage `json:"monthly"`
}

func (q LicenseQuota) Valid() error {
	return validate.Struct(q)
}

// LicenseStatusResponse is what a licensed installation is told of its licence: the tier
// the licence is of, the features it enables and the share of its quotas used, with the
// overrides of the licence applied. A limit the licence cannot call, or calls with no quota
// kept, is not in the list: a limit absent says nothing of its use. Quotas is a list, empty
// for none, never null.
type LicenseStatusResponse struct {
	Tier     string          `json:"tier" validate:"required"`
	Features LicenseFeatures `json:"features"`
	Quotas   []LicenseQuota  `json:"quotas" validate:"required"`
}

func (r LicenseStatusResponse) Valid() error {
	if err := validate.Struct(r); err != nil {
		return err
	}
	for _, quota := range r.Quotas {
		if err := quota.Valid(); err != nil {
			return fmt.Errorf("quota %q: %w", quota.Limit, err)
		}
	}
	return nil
}

// LicenseModuleMaxSize is the largest license module the API serves, in bytes: a size
// above it is refused in a description and while a download is written.
const LicenseModuleMaxSize = 40 << 20

var licenseModuleID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// licenseModuleSignatureContext keeps the signature of a license module from verifying as
// that of an installer package.
const licenseModuleSignatureContext = "pentagi/license-module/v1\x00"

// LicenseModuleDigest is the digest the signature of a license module covers:
// SHA-512(context ‖ moduleSHA512), where moduleSHA512 is the SHA-512 of the module's bytes.
// A module's signature therefore never verifies as a package's, nor a package's as a
// module's.
func LicenseModuleDigest(moduleSHA512 []byte) []byte {
	digest := sha512.New()
	digest.Write([]byte(licenseModuleSignatureContext))
	digest.Write(moduleSHA512)
	return digest.Sum(nil)
}

// IsLicenseModuleID reports whether id has the form of the ID of a license module: 32
// lowercase hex digits.
func IsLicenseModuleID(id string) bool {
	return licenseModuleID.MatchString(id)
}

// LicenseModuleInfo describes the license module the API serves for a licence. When Ready,
// the server sets every field but RetryAfterSeconds, and Size, Hash (the SHA-256 in hex)
// and Signature (Ed25519 over LicenseModuleDigest of the SHA-512) describe the bytes of
// the download; Valid checks the ID and those three, and leaves the dates, which no
// download depends on, to the reader. When not Ready no module is served yet,
// RetryAfterSeconds is when to ask again, and the other fields are absent.
type LicenseModuleInfo struct {
	Ready             bool           `json:"ready"`
	ModuleID          string         `json:"module_id,omitempty"`
	BuiltAt           *time.Time     `json:"built_at,omitempty"`
	RefreshBy         *time.Time     `json:"refresh_by,omitempty"`
	Size              int64          `json:"size,omitempty"`
	Hash              string         `json:"hash,omitempty"`
	Signature         SignatureValue `json:"signature,omitempty"`
	RetryAfterSeconds int            `json:"retry_after_seconds"`
}

func (i LicenseModuleInfo) Valid() error {
	if !i.Ready {
		if i.RetryAfterSeconds < 1 {
			return fmt.Errorf("a module not ready without the seconds to wait: %d", i.RetryAfterSeconds)
		}
		return nil
	}
	if !IsLicenseModuleID(i.ModuleID) {
		return fmt.Errorf("module ID %q is not 32 lowercase hex digits", i.ModuleID)
	}
	if i.Size < 1 || i.Size > LicenseModuleMaxSize {
		return fmt.Errorf("module size %d is outside 1..%d", i.Size, LicenseModuleMaxSize)
	}
	if err := validate.Var(i.Hash, "sha256"); err != nil {
		return fmt.Errorf("module hash %q is not a SHA-256 in hex", i.Hash)
	}
	if err := i.Signature.Valid(); err != nil {
		return fmt.Errorf("module signature: %w", err)
	}
	return nil
}
