package auditor

import (
	"strings"
	"testing"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// A confirmed-off setting is a real gap, not an FYI. Flow logs are reported by
// both ends of a connection, so they still record a node that suppresses its
// own telemetry - which is what makes the setting worth flagging.
func TestFlowLogsDisabledIsLow(t *testing.T) {
	l := &LoggingAuditor{}

	f := l.checkNetworkFlowLogs(settingsCtx(client.TailnetSettings{NetworkFlowLoggingOn: false}))

	if f.Pass {
		t.Error("checkNetworkFlowLogs() Pass = true, want false when flow logging is confirmed off")
	}
	if f.Severity != types.Low {
		t.Errorf("checkNetworkFlowLogs() Severity = %s, want %s for a confirmed gap", f.Severity, types.Low)
	}
	if !strings.Contains(f.Description, "both ends") {
		t.Errorf("checkNetworkFlowLogs() Description = %q, want it to explain that both ends of a connection report flow logs", f.Description)
	}
}

func TestFlowLogsEnabledPasses(t *testing.T) {
	l := &LoggingAuditor{}

	f := l.checkNetworkFlowLogs(settingsCtx(client.TailnetSettings{NetworkFlowLoggingOn: true}))

	if !f.Pass {
		t.Error("checkNetworkFlowLogs() Pass = false, want true when flow logging is on")
	}
	// FilterBySeverity ignores Pass, so a passing finding rated LOW would
	// surface under --min-severity low as if it were a gap. The severity bump
	// belongs to the confirmed-off branch alone.
	if f.Severity != types.Informational {
		t.Errorf("checkNetworkFlowLogs() Severity = %s, want %s: a passing finding must not carry a gap's severity",
			f.Severity, types.Informational)
	}
}

// Nothing was confirmed when the setting could not be read, so the severity
// bump belongs to the confirmed-off branch alone and not to the finding's
// initialiser.
func TestFlowLogsUnavailableStaysInformational(t *testing.T) {
	l := &LoggingAuditor{}

	f := l.checkNetworkFlowLogs(&TailnetContext{SettingsErr: client.ErrPermission})

	if f.Pass {
		t.Error("checkNetworkFlowLogs() Pass = true, want false when the setting could not be read")
	}
	if f.Severity != types.Informational {
		t.Errorf("checkNetworkFlowLogs() Severity = %s, want %s when nothing was confirmed", f.Severity, types.Informational)
	}
}
