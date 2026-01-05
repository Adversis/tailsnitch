package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Adversis/tailsnitch/pkg/types"
)

func TestSOC2JSON(t *testing.T) {
	now := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	report := &types.SOC2Report{
		Tailnet:     "test-tailnet",
		GeneratedAt: now,
		Tests: []types.SOC2ControlTest{
			{
				ResourceType: "device",
				ResourceID:   "n123",
				ResourceName: "web-server",
				CheckID:      "DEV-001",
				CheckTitle:   "Tagged devices with key expiry disabled",
				CCCodes:      []string{"CC6.1", "CC6.3"},
				Status:       types.SOC2Pass,
				Details:      "No tags assigned",
				TestedAt:     now,
			},
			{
				ResourceType: "key",
				ResourceID:   "k456",
				ResourceName: "CI-Key",
				CheckID:      "AUTH-001",
				CheckTitle:   "Reusable auth keys exist",
				CCCodes:      []string{"CC6.1", "CC6.2"},
				Status:       types.SOC2Fail,
				Details:      "Reusable key, expires in 45 days",
				TestedAt:     now,
			},
		},
	}
	report.CalculateSummary()

	var buf bytes.Buffer
	err := SOC2JSON(&buf, report)
	if err != nil {
		t.Fatalf("SOC2JSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed types.SOC2Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify content
	if parsed.Tailnet != "test-tailnet" {
		t.Errorf("Tailnet = %q, want %q", parsed.Tailnet, "test-tailnet")
	}

	if len(parsed.Tests) != 2 {
		t.Errorf("Tests count = %d, want 2", len(parsed.Tests))
	}

	if parsed.Summary.PassedTests != 1 {
		t.Errorf("PassedTests = %d, want 1", parsed.Summary.PassedTests)
	}
}

func TestSOC2CSV(t *testing.T) {
	now := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	report := &types.SOC2Report{
		Tailnet:     "test-tailnet",
		GeneratedAt: now,
		Tests: []types.SOC2ControlTest{
			{
				ResourceType: "device",
				ResourceID:   "n123",
				ResourceName: "web-server",
				CheckID:      "DEV-001",
				CheckTitle:   "Tagged devices with key expiry disabled",
				CCCodes:      []string{"CC6.1", "CC6.3"},
				Status:       types.SOC2Pass,
				Details:      "No tags assigned",
				TestedAt:     now,
			},
			{
				ResourceType: "key",
				ResourceID:   "k456",
				ResourceName: "CI-Key",
				CheckID:      "AUTH-001",
				CheckTitle:   "Reusable auth keys exist",
				CCCodes:      []string{"CC6.1", "CC6.2"},
				Status:       types.SOC2Fail,
				Details:      "Reusable key, expires in 45 days",
				TestedAt:     now,
			},
		},
	}

	var buf bytes.Buffer
	err := SOC2CSV(&buf, report)
	if err != nil {
		t.Fatalf("SOC2CSV failed: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have header + 2 data rows
	if len(lines) != 3 {
		t.Errorf("Line count = %d, want 3", len(lines))
	}

	// Check header
	header := lines[0]
	expectedHeader := "resource_type,resource_id,resource_name,check_id,check_title,cc_codes,status,details,tested_at"
	if header != expectedHeader {
		t.Errorf("Header = %q, want %q", header, expectedHeader)
	}

	// Check first data row contains expected values
	if !strings.Contains(lines[1], "device") {
		t.Error("First row should contain 'device'")
	}
	if !strings.Contains(lines[1], "CC6.1;CC6.3") {
		t.Error("First row should contain CC codes separated by semicolons")
	}
	if !strings.Contains(lines[1], "PASS") {
		t.Error("First row should contain 'PASS'")
	}

	// Check second data row
	if !strings.Contains(lines[2], "FAIL") {
		t.Error("Second row should contain 'FAIL'")
	}
}

func TestSOC2CSVEmptyReport(t *testing.T) {
	report := &types.SOC2Report{
		Tailnet:     "test",
		GeneratedAt: time.Now(),
		Tests:       []types.SOC2ControlTest{},
	}

	var buf bytes.Buffer
	err := SOC2CSV(&buf, report)
	if err != nil {
		t.Fatalf("SOC2CSV failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Should only have header
	if len(lines) != 1 {
		t.Errorf("Line count = %d, want 1 (header only)", len(lines))
	}
}
