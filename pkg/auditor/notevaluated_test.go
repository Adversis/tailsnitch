package auditor

import (
	"context"
	"testing"

	"github.com/Adversis/tailsnitch/pkg/types"
)

// A check that could not run must not report Pass. FilterFailed drops passing
// findings from the default output and CalculateSummary counts them in
// Summary.Passed, so a passing finding would present a skipped control as a
// satisfied one.
func assertNotEvaluated(t *testing.T, findings []types.Suggestion, wantIDs ...string) {
	t.Helper()

	byID := make(map[string]types.Suggestion, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}

	for _, id := range wantIDs {
		f, ok := byID[id]
		if !ok {
			t.Errorf("%s missing from findings", id)
			continue
		}
		if f.Pass {
			t.Errorf("%s reports Pass=true, but it was never evaluated", id)
		}
	}
}

func TestSSHAuditSkipsChecksWhenPolicyUnparsed(t *testing.T) {
	s := NewSSHAuditor(nil)

	findings, err := s.Audit(context.Background(), ACLPolicy{}, false)
	if err != nil {
		t.Fatal(err)
	}

	assertNotEvaluated(t, findings, sshPolicyChecks...)

	if len(findings) != len(sshPolicyChecks) {
		t.Errorf("len(findings) = %d, want %d", len(findings), len(sshPolicyChecks))
	}
}

func TestSSHAuditRunsChecksWhenPolicyParsed(t *testing.T) {
	s := NewSSHAuditor(nil)

	findings, err := s.Audit(context.Background(), ACLPolicy{}, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if got := f.Title; got == "" {
			t.Errorf("%s has no title", f.ID)
		}
	}
	if len(findings) != len(sshPolicyChecks) {
		t.Errorf("len(findings) = %d, want %d", len(findings), len(sshPolicyChecks))
	}
}

func TestNotEvaluatedCarriesRegistryMetadata(t *testing.T) {
	f := types.NotEvaluated("SSH-001", "policy unreadable")

	if f.Pass {
		t.Error("NotEvaluated reports Pass=true")
	}
	if f.Category != types.SSHSecurity {
		t.Errorf("Category = %q, want %q", f.Category, types.SSHSecurity)
	}
	if f.Title == "SSH-001 could not be evaluated" {
		t.Error("Title did not pick up the registered check title")
	}
}

// An unregistered ID still produces a usable finding rather than a blank one.
func TestNotEvaluatedUnknownID(t *testing.T) {
	f := types.NotEvaluated("ZZZ-999", "reason")

	if f.Pass {
		t.Error("NotEvaluated reports Pass=true")
	}
	if f.Title == "" {
		t.Error("Title is empty")
	}
}
