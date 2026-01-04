package types

import (
	"testing"
	"time"
)

func TestSOC2ReportCalculateSummary(t *testing.T) {
	now := time.Now()

	report := &SOC2Report{
		Tailnet:     "test-tailnet",
		GeneratedAt: now,
		Tests: []SOC2ControlTest{
			{ResourceType: "device", CheckID: "DEV-001", CCCodes: []string{"CC6.1"}, Status: SOC2Pass, TestedAt: now},
			{ResourceType: "device", CheckID: "DEV-003", CCCodes: []string{"CC6.1", "CC7.1"}, Status: SOC2Fail, TestedAt: now},
			{ResourceType: "key", CheckID: "AUTH-001", CCCodes: []string{"CC6.1", "CC6.2"}, Status: SOC2Pass, TestedAt: now},
			{ResourceType: "key", CheckID: "AUTH-002", CCCodes: []string{"CC6.1", "CC6.2"}, Status: SOC2Fail, TestedAt: now},
			{ResourceType: "acl_policy", CheckID: "ACL-001", CCCodes: []string{"CC6.1"}, Status: SOC2NA, TestedAt: now},
		},
	}

	report.CalculateSummary()

	if report.Summary.TotalTests != 5 {
		t.Errorf("TotalTests = %d, want 5", report.Summary.TotalTests)
	}

	if report.Summary.PassedTests != 2 {
		t.Errorf("PassedTests = %d, want 2", report.Summary.PassedTests)
	}

	if report.Summary.FailedTests != 2 {
		t.Errorf("FailedTests = %d, want 2", report.Summary.FailedTests)
	}

	if report.Summary.NATests != 1 {
		t.Errorf("NATests = %d, want 1", report.Summary.NATests)
	}

	// Check by resource type
	if report.Summary.ByResource["device"] != 2 {
		t.Errorf("ByResource[device] = %d, want 2", report.Summary.ByResource["device"])
	}

	if report.Summary.ByResource["key"] != 2 {
		t.Errorf("ByResource[key] = %d, want 2", report.Summary.ByResource["key"])
	}

	// Check by CC code (only failures are counted)
	if report.Summary.ByCC["CC6.1"] != 2 {
		t.Errorf("ByCC[CC6.1] = %d, want 2", report.Summary.ByCC["CC6.1"])
	}

	if report.Summary.ByCC["CC7.1"] != 1 {
		t.Errorf("ByCC[CC7.1] = %d, want 1", report.Summary.ByCC["CC7.1"])
	}

	// Pass rate should be 50% (2 pass out of 4 applicable, excluding 1 N/A)
	if report.Summary.PassRate != 50.0 {
		t.Errorf("PassRate = %f, want 50.0", report.Summary.PassRate)
	}
}

func TestSOC2StatusConstants(t *testing.T) {
	tests := []struct {
		status SOC2Status
		want   string
	}{
		{SOC2Pass, "PASS"},
		{SOC2Fail, "FAIL"},
		{SOC2NA, "N/A"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("SOC2Status = %s, want %s", tt.status, tt.want)
		}
	}
}

func TestSOC2ReportEmptySummary(t *testing.T) {
	report := &SOC2Report{
		Tailnet:     "test",
		GeneratedAt: time.Now(),
		Tests:       []SOC2ControlTest{},
	}

	report.CalculateSummary()

	if report.Summary.TotalTests != 0 {
		t.Errorf("TotalTests = %d, want 0", report.Summary.TotalTests)
	}

	if report.Summary.PassRate != 0 {
		t.Errorf("PassRate = %f, want 0", report.Summary.PassRate)
	}
}
