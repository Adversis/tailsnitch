package types

import "time"

// Severity represents the severity level of a security finding
type Severity string

const (
	Critical      Severity = "CRITICAL"
	High          Severity = "HIGH"
	Medium        Severity = "MEDIUM"
	Low           Severity = "LOW"
	Informational Severity = "INFO"
)

// SeverityOrder returns the numeric priority of a severity (lower = more severe)
func (s Severity) Order() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	case Informational:
		return 4
	default:
		return 5
	}
}

// Category represents the category of a security finding
type Category string

const (
	AccessControl    Category = "Access Controls"
	Authentication   Category = "Authentication & Keys"
	NetworkExposure  Category = "Network Exposure"
	SSHSecurity      Category = "SSH & Device Security"
	LoggingAdmin     Category = "Logging & Admin"
	DeviceSecurity   Category = "Device Security"
	DNSConfiguration Category = "DNS Configuration"
)

// FixType indicates how a finding can be fixed
type FixType string

const (
	FixTypeNone     FixType = "none"     // Cannot be fixed via CLI
	FixTypeAPI      FixType = "api"      // Can be fixed via Tailscale API
	FixTypeManual   FixType = "manual"   // Requires admin console
	FixTypeExternal FixType = "external" // Requires external system (IdP, etc)
)

// FixableItem represents a single item that can be fixed
type FixableItem struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Selected    bool        `json:"-"` // For TUI selection, not serialized
	Metadata    interface{} `json:"metadata,omitempty"`
}

// FixInfo contains remediation information for a finding
type FixInfo struct {
	Type        FixType       `json:"type"`
	Description string        `json:"description"`
	AdminURL    string        `json:"admin_url,omitempty"`
	DocURL      string        `json:"doc_url,omitempty"`
	Items       []FixableItem `json:"items,omitempty"`
	AutoFixSafe bool          `json:"auto_fix_safe"`
}

// Suggestion represents a single audit suggestion
type Suggestion struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Severity    Severity    `json:"severity"`
	Category    Category    `json:"category"`
	Description string      `json:"description"`
	Remediation string      `json:"remediation"`
	Source      string      `json:"source,omitempty"` // KB URL
	Details     interface{} `json:"details,omitempty"`
	Pass        bool        `json:"pass"`          // true if check passed (no issue found)
	Fix         *FixInfo    `json:"fix,omitempty"` // Remediation action info
}

// Summary contains aggregate counts of findings by severity
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Passed   int `json:"passed"`
	Total    int `json:"total"`
}

// AuditReport represents the complete audit report
type AuditReport struct {
	Timestamp   time.Time    `json:"timestamp"`
	Tailnet     string       `json:"tailnet"`
	Suggestions []Suggestion `json:"suggestions"`
	Summary     Summary      `json:"summary"`
}

// CalculateSummary computes the summary from suggestions
func (r *AuditReport) CalculateSummary() {
	r.Summary = Summary{}
	for _, f := range r.Suggestions {
		if f.Pass {
			r.Summary.Passed++
		} else {
			switch f.Severity {
			case Critical:
				r.Summary.Critical++
			case High:
				r.Summary.High++
			case Medium:
				r.Summary.Medium++
			case Low:
				r.Summary.Low++
			case Informational:
				r.Summary.Info++
			}
		}
	}
	r.Summary.Total = len(r.Suggestions)
}

// FilterBySeverity returns suggestions at or above the given severity
func FilterBySeverity(suggestions []Suggestion, minSeverity Severity) []Suggestion {
	var result []Suggestion
	minOrder := minSeverity.Order()
	for _, s := range suggestions {
		if s.Severity.Order() <= minOrder {
			result = append(result, s)
		}
	}
	return result
}

// FilterByCategory returns suggestions matching the given category
func FilterByCategory(suggestions []Suggestion, category Category) []Suggestion {
	var result []Suggestion
	for _, s := range suggestions {
		if s.Category == category {
			result = append(result, s)
		}
	}
	return result
}

// FilterFailed returns only failed suggestions (Pass == false)
func FilterFailed(suggestions []Suggestion) []Suggestion {
	var result []Suggestion
	for _, s := range suggestions {
		if !s.Pass {
			result = append(result, s)
		}
	}
	return result
}

// FilterByFixType returns suggestions with the specified fix type
func FilterByFixType(suggestions []Suggestion, fixType FixType) []Suggestion {
	var result []Suggestion
	for _, s := range suggestions {
		if s.Fix != nil && s.Fix.Type == fixType {
			result = append(result, s)
		}
	}
	return result
}

// FilterFixable returns suggestions that have any fix info (not none)
func FilterFixable(suggestions []Suggestion) []Suggestion {
	var result []Suggestion
	for _, s := range suggestions {
		if s.Fix != nil && s.Fix.Type != FixTypeNone {
			result = append(result, s)
		}
	}
	return result
}

// FilterByCheckIDs returns suggestions matching any of the given check IDs
func FilterByCheckIDs(suggestions []Suggestion, ids []string) []Suggestion {
	if len(ids) == 0 {
		return suggestions
	}

	// Build a set for O(1) lookup
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}

	var result []Suggestion
	for _, s := range suggestions {
		if idSet[s.ID] {
			result = append(result, s)
		}
	}
	return result
}
