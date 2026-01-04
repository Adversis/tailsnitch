package types

import (
	"testing"
)

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{Critical, 0},
		{High, 1},
		{Medium, 2},
		{Low, 3},
		{Informational, 4},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := tt.severity.Order(); got != tt.want {
				t.Errorf("Order() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test ordering comparison
	if Critical.Order() >= High.Order() {
		t.Error("Critical should have lower order than High")
	}
	if High.Order() >= Medium.Order() {
		t.Error("High should have lower order than Medium")
	}
}

func TestFilterBySeverity(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "1", Severity: Critical},
		{ID: "2", Severity: High},
		{ID: "3", Severity: Medium},
		{ID: "4", Severity: Low},
		{ID: "5", Severity: Informational},
	}

	tests := []struct {
		name        string
		minSeverity Severity
		wantCount   int
		wantIDs     []string
	}{
		{
			name:        "filter critical only",
			minSeverity: Critical,
			wantCount:   1,
			wantIDs:     []string{"1"},
		},
		{
			name:        "filter high and above",
			minSeverity: High,
			wantCount:   2,
			wantIDs:     []string{"1", "2"},
		},
		{
			name:        "filter medium and above",
			minSeverity: Medium,
			wantCount:   3,
			wantIDs:     []string{"1", "2", "3"},
		},
		{
			name:        "filter all",
			minSeverity: Informational,
			wantCount:   5,
			wantIDs:     []string{"1", "2", "3", "4", "5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterBySeverity(suggestions, tt.minSeverity)
			if len(result) != tt.wantCount {
				t.Errorf("FilterBySeverity() count = %v, want %v", len(result), tt.wantCount)
			}
		})
	}
}

func TestFilterByCategory(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "1", Category: AccessControl},
		{ID: "2", Category: AccessControl},
		{ID: "3", Category: Authentication},
		{ID: "4", Category: DeviceSecurity},
	}

	result := FilterByCategory(suggestions, AccessControl)
	if len(result) != 2 {
		t.Errorf("FilterByCategory() count = %v, want 2", len(result))
	}

	result = FilterByCategory(suggestions, NetworkExposure)
	if len(result) != 0 {
		t.Errorf("FilterByCategory() count = %v, want 0", len(result))
	}
}

func TestFilterFailed(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "1", Pass: true},
		{ID: "2", Pass: false},
		{ID: "3", Pass: false},
		{ID: "4", Pass: true},
	}

	result := FilterFailed(suggestions)
	if len(result) != 2 {
		t.Errorf("FilterFailed() count = %v, want 2", len(result))
	}

	for _, s := range result {
		if s.Pass {
			t.Errorf("FilterFailed() returned passing suggestion: %s", s.ID)
		}
	}
}

func TestFilterByFixType(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "1", Fix: &FixInfo{Type: FixTypeAPI}},
		{ID: "2", Fix: &FixInfo{Type: FixTypeManual}},
		{ID: "3", Fix: &FixInfo{Type: FixTypeAPI}},
		{ID: "4", Fix: nil},
	}

	result := FilterByFixType(suggestions, FixTypeAPI)
	if len(result) != 2 {
		t.Errorf("FilterByFixType() count = %v, want 2", len(result))
	}

	result = FilterByFixType(suggestions, FixTypeManual)
	if len(result) != 1 {
		t.Errorf("FilterByFixType() count = %v, want 1", len(result))
	}
}

func TestFilterFixable(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "1", Fix: &FixInfo{Type: FixTypeAPI}},
		{ID: "2", Fix: &FixInfo{Type: FixTypeManual}},
		{ID: "3", Fix: &FixInfo{Type: FixTypeNone}},
		{ID: "4", Fix: nil},
	}

	result := FilterFixable(suggestions)
	if len(result) != 2 {
		t.Errorf("FilterFixable() count = %v, want 2", len(result))
	}
}

func TestFilterByCheckIDs(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "ACL-001"},
		{ID: "ACL-002"},
		{ID: "AUTH-001"},
		{ID: "DEV-001"},
	}

	tests := []struct {
		name      string
		ids       []string
		wantCount int
	}{
		{
			name:      "empty IDs returns all",
			ids:       nil,
			wantCount: 4,
		},
		{
			name:      "single ID",
			ids:       []string{"ACL-001"},
			wantCount: 1,
		},
		{
			name:      "multiple IDs",
			ids:       []string{"ACL-001", "AUTH-001"},
			wantCount: 2,
		},
		{
			name:      "non-existent ID",
			ids:       []string{"FAKE-001"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterByCheckIDs(suggestions, tt.ids)
			if len(result) != tt.wantCount {
				t.Errorf("FilterByCheckIDs() count = %v, want %v", len(result), tt.wantCount)
			}
		})
	}
}

func TestCalculateSummary(t *testing.T) {
	report := &AuditReport{
		Suggestions: []Suggestion{
			{ID: "1", Severity: Critical, Pass: false},
			{ID: "2", Severity: High, Pass: false},
			{ID: "3", Severity: High, Pass: false},
			{ID: "4", Severity: Medium, Pass: false},
			{ID: "5", Severity: Low, Pass: false},
			{ID: "6", Severity: Informational, Pass: false},
			{ID: "7", Severity: Medium, Pass: true},
			{ID: "8", Severity: Low, Pass: true},
		},
	}

	report.CalculateSummary()

	if report.Summary.Critical != 1 {
		t.Errorf("Summary.Critical = %v, want 1", report.Summary.Critical)
	}
	if report.Summary.High != 2 {
		t.Errorf("Summary.High = %v, want 2", report.Summary.High)
	}
	if report.Summary.Medium != 1 {
		t.Errorf("Summary.Medium = %v, want 1", report.Summary.Medium)
	}
	if report.Summary.Low != 1 {
		t.Errorf("Summary.Low = %v, want 1", report.Summary.Low)
	}
	if report.Summary.Info != 1 {
		t.Errorf("Summary.Info = %v, want 1", report.Summary.Info)
	}
	if report.Summary.Passed != 2 {
		t.Errorf("Summary.Passed = %v, want 2", report.Summary.Passed)
	}
	if report.Summary.Total != 8 {
		t.Errorf("Summary.Total = %v, want 8", report.Summary.Total)
	}
}
