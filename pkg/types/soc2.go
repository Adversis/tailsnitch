package types

import (
	"time"
)

// SOC2Status represents the status of a control test
type SOC2Status string

const (
	SOC2Pass SOC2Status = "PASS"
	SOC2Fail SOC2Status = "FAIL"
	SOC2NA   SOC2Status = "N/A"
)

// SOC2ControlTest represents a single control test against a resource
type SOC2ControlTest struct {
	ResourceType string     `json:"resource_type"` // device, key, acl_rule, config
	ResourceID   string     `json:"resource_id"`
	ResourceName string     `json:"resource_name"`
	CheckID      string     `json:"check_id"`
	CheckTitle   string     `json:"check_title"`
	CCCodes      []string   `json:"cc_codes"`
	Status       SOC2Status `json:"status"`
	Details      string     `json:"details,omitempty"`
	TestedAt     time.Time  `json:"tested_at"`
}

// SOC2Summary contains aggregate statistics for the SOC2 report
type SOC2Summary struct {
	TotalTests  int            `json:"total_tests"`
	PassedTests int            `json:"passed_tests"`
	FailedTests int            `json:"failed_tests"`
	NATests     int            `json:"na_tests"`
	ByCC        map[string]int `json:"by_cc"`       // Count of failures per CC code
	ByResource  map[string]int `json:"by_resource"` // Count of tests per resource type
	PassRate    float64        `json:"pass_rate"`   // Percentage of passing tests
}

// SOC2Report contains the complete SOC2 evidence export
type SOC2Report struct {
	Tailnet     string            `json:"tailnet"`
	GeneratedAt time.Time         `json:"generated_at"`
	Summary     SOC2Summary       `json:"summary"`
	Tests       []SOC2ControlTest `json:"tests"`
}

// CalculateSummary computes summary statistics from the tests
func (r *SOC2Report) CalculateSummary() {
	r.Summary = SOC2Summary{
		ByCC:       make(map[string]int),
		ByResource: make(map[string]int),
	}

	for _, t := range r.Tests {
		r.Summary.TotalTests++
		r.Summary.ByResource[t.ResourceType]++

		switch t.Status {
		case SOC2Pass:
			r.Summary.PassedTests++
		case SOC2Fail:
			r.Summary.FailedTests++
			// Track failures by CC code
			for _, cc := range t.CCCodes {
				r.Summary.ByCC[cc]++
			}
		case SOC2NA:
			r.Summary.NATests++
		}
	}

	// Calculate pass rate (excluding N/A)
	applicable := r.Summary.TotalTests - r.Summary.NATests
	if applicable > 0 {
		r.Summary.PassRate = float64(r.Summary.PassedTests) / float64(applicable) * 100
	}
}
