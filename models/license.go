package models

import "fmt"

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
