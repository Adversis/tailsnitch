package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Adversis/tailsnitch/pkg/types"
)

func TestSanitizeStripsTerminalControls(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"escape sequence", "laptop\x1b[32mgreen\x1b[0m", "laptop[32mgreen[0m"},
		{"carriage return", "real\rfake", "real fake"},
		{"erase line", "a\x1b[2Kb", "a[2Kb"},
		{"newline and tab", "a\nb\tc", "a b c"},
		{"del and C1", "a\x7fb\u009bc", "abc"},
		{"plain text untouched", "prod-db-01 (ubuntu)", "prod-db-01 (ubuntu)"},
		{"unicode kept", "café-日本", "café-日本"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.in); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTextReportNeutralizesDeviceSuppliedEscapes(t *testing.T) {
	// A tailnet member controls their own device name, so this is untrusted
	// input reaching the terminal of the person auditing them.
	evil := "laptop\x1b[32m [PASS] no issues\x1b[0m\r\x1b[2K  • laptop (clean)"
	report := &types.AuditReport{
		Timestamp: time.Now(),
		Suggestions: []types.Suggestion{{
			ID: "DEV-004", Title: "Stale devices", Severity: types.Critical,
			Category: types.DeviceSecurity, Pass: false,
			Description: "Found 1 stale device.",
			Details:     []string{evil},
		}},
	}

	var buf bytes.Buffer
	if err := Text(&buf, report, false); err != nil {
		t.Fatal(err)
	}

	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Error("report contains a raw ESC byte")
	}
	if strings.ContainsRune(buf.String(), '\r') {
		t.Error("report contains a raw CR byte")
	}
}

func TestCSVFieldNeutralizesFormulas(t *testing.T) {
	for _, in := range []string{"=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(1)"} {
		got := csvField(in)
		if !strings.HasPrefix(got, "'") {
			t.Errorf("csvField(%q) = %q, want a leading apostrophe", in, got)
		}
	}

	for _, in := range []string{"prod-db-01", "1.86.2", ""} {
		if got := csvField(in); got != in {
			t.Errorf("csvField(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestSOC2CSVNeutralizesDeviceSuppliedFormulas(t *testing.T) {
	report := &types.SOC2Report{Tests: []types.SOC2ControlTest{{
		ResourceType: "device",
		ResourceID:   "node-1",
		ResourceName: `=cmd|'/c calc.exe'!A1`,
		CheckID:      "DEV-004",
		CheckTitle:   "Stale devices",
		Status:       types.SOC2Pass,
		Details:      `@SUM(1+1)`,
		TestedAt:     time.Now(),
	}}}

	var buf bytes.Buffer
	if err := SOC2CSV(&buf, report); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{`'=cmd`, `'@SUM(1+1)`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("CSV missing %q:\n%s", want, buf.String())
		}
	}
}
