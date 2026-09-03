package auditor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tailscale/hujson"

	"testing"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// detailsContain reports whether any line in a finding's Details contains
// substr. Details is typed interface{} because some checks report it as a
// plain string; ACL-011 always reports []string. Used to assert on the reach
// table describeReach produces, which is the informational payload ACL-011
// exists to deliver.
func detailsContain(details interface{}, substr string) bool {
	lines, ok := details.([]string)
	if !ok {
		return false
	}
	for _, d := range lines {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}

func TestCheckAllowAll(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name     string
		policy   ACLPolicy
		rawACL   string
		wantPass bool
		wantSev  types.Severity
	}{
		{
			name:     "missing acls and grants fields - default allow all",
			policy:   ACLPolicy{},
			rawACL:   `{"tagOwners": {}}`,
			wantPass: false,
			wantSev:  types.Critical,
		},
		{
			name:     "empty acls with no grants - deny all",
			policy:   ACLPolicy{ACLs: []ACLRule{}},
			rawACL:   `{"acls": []}`,
			wantPass: false,
			wantSev:  types.Informational,
		},
		{
			name: "has grants - not flagged",
			policy: ACLPolicy{
				Grants: []Grant{{Src: []string{"*"}, Dst: []string{"*"}}},
			},
			rawACL:   `{"grants": [{"src": ["*"], "dst": ["*"]}]}`,
			wantPass: true,
		},
		{
			name: "wildcard src and dst - allow all",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}},
				},
			},
			rawACL:   `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
			wantPass: false,
			wantSev:  types.Critical,
		},
		{
			name: "specific src and dst - pass",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Action: "accept", Src: []string{"group:engineers"}, Dst: []string{"tag:server:22"}},
				},
			},
			rawACL:   `{"acls": [{"action": "accept", "src": ["group:engineers"], "dst": ["tag:server:22"]}]}`,
			wantPass: true,
		},
		{
			name: "wildcard src only - pass",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Action: "accept", Src: []string{"*"}, Dst: []string{"tag:server:22"}},
				},
			},
			rawACL:   `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:server:22"]}]}`,
			wantPass: true,
		},
		{
			name: "wildcard dst only - pass",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Action: "accept", Src: []string{"group:admin"}, Dst: []string{"*:*"}},
				},
			},
			rawACL:   `{"acls": [{"action": "accept", "src": ["group:admin"], "dst": ["*:*"]}]}`,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkAllowAll(tt.policy, newPolicyFields([]byte(tt.rawACL)))

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-001" {
				t.Errorf("ID = %q, want ACL-001", result.ID)
			}

			if !tt.wantPass && result.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSev)
			}
		})
	}
}

func TestCheckSSHNonrootMisconfig(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name      string
		policy    ACLPolicy
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no SSH rules",
			policy:   ACLPolicy{},
			wantPass: true,
		},
		{
			name: "SSH rule without autogroup:nonroot - pass",
			policy: ACLPolicy{
				SSH: []SSHRule{
					{Src: []string{"group:admins"}, Dst: []string{"tag:server"}, Users: []string{"root"}},
				},
			},
			wantPass: true,
		},
		{
			name: "SSH rule with autogroup:nonroot but autogroup:self dst - pass",
			policy: ACLPolicy{
				SSH: []SSHRule{
					{Src: []string{"*"}, Dst: []string{"autogroup:self"}, Users: []string{"autogroup:nonroot"}},
				},
			},
			wantPass: true,
		},
		{
			name: "SSH rule with autogroup:nonroot and tag dst - fail",
			policy: ACLPolicy{
				SSH: []SSHRule{
					{Src: []string{"*"}, Dst: []string{"tag:server"}, Users: []string{"autogroup:nonroot"}},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "multiple problematic SSH rules",
			policy: ACLPolicy{
				SSH: []SSHRule{
					{Src: []string{"*"}, Dst: []string{"tag:server"}, Users: []string{"autogroup:nonroot"}},
					{Src: []string{"*"}, Dst: []string{"tag:db"}, Users: []string{"autogroup:nonroot", "root"}},
				},
			},
			wantPass:  false,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkSSHNonrootMisconfig(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-002" {
				t.Errorf("ID = %q, want ACL-002", result.ID)
			}

			if !tt.wantPass {
				if result.Severity != types.Critical {
					t.Errorf("Severity = %v, want Critical", result.Severity)
				}
				if details, ok := result.Details.([]string); ok {
					if len(details) != tt.wantCount {
						t.Errorf("Details count = %d, want %d", len(details), tt.wantCount)
					}
				}
			}
		})
	}
}

func TestCheckACLTests(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name     string
		policy   ACLPolicy
		wantPass bool
		wantSev  types.Severity
	}{
		{
			name:     "no tests defined",
			policy:   ACLPolicy{},
			wantPass: false,
			wantSev:  types.Low,
		},
		{
			name: "only accept tests",
			policy: ACLPolicy{
				Tests: []ACLTest{
					{Src: "user@example.com", Accept: []string{"server:22"}},
				},
			},
			wantPass: false,
			wantSev:  types.Low,
		},
		{
			name: "only deny tests",
			policy: ACLPolicy{
				Tests: []ACLTest{
					{Src: "user@example.com", Deny: []string{"prod-db:5432"}},
				},
			},
			wantPass: false,
			wantSev:  types.Low,
		},
		{
			name: "both accept and deny tests",
			policy: ACLPolicy{
				Tests: []ACLTest{
					{Src: "user@example.com", Accept: []string{"server:22"}, Deny: []string{"prod-db:5432"}},
				},
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkACLTests(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-003" {
				t.Errorf("ID = %q, want ACL-003", result.ID)
			}

			if !tt.wantPass && result.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSev)
			}
		})
	}
}

func TestCheckAutogroupMember(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name      string
		policy    ACLPolicy
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no ACLs",
			policy:   ACLPolicy{},
			wantPass: true,
		},
		{
			name: "no autogroup:member usage",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Src: []string{"group:engineers"}, Dst: []string{"tag:server:*"}},
				},
			},
			wantPass: true,
		},
		{
			name: "autogroup:member in src",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Src: []string{"autogroup:member"}, Dst: []string{"tag:server:*"}},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkAutogroupMember(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-004" {
				t.Errorf("ID = %q, want ACL-004", result.ID)
			}
		})
	}
}

func TestCheckTagOwners(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name     string
		policy   ACLPolicy
		wantPass bool
		wantSev  types.Severity
	}{
		{
			name:     "no tag owners",
			policy:   ACLPolicy{},
			wantPass: true,
		},
		{
			name: "tag owned by admin",
			policy: ACLPolicy{
				TagOwners: map[string][]string{
					"tag:server": {"autogroup:admin"},
				},
			},
			wantPass: true,
		},
		{
			name: "tag owned by autogroup:member - dangerous",
			policy: ACLPolicy{
				TagOwners: map[string][]string{
					"tag:prod": {"autogroup:member"},
				},
			},
			wantPass: false,
			wantSev:  types.Critical,
		},
		{
			name: "tag owned by wildcard - dangerous",
			policy: ACLPolicy{
				TagOwners: map[string][]string{
					"tag:prod": {"*"},
				},
			},
			wantPass: false,
			wantSev:  types.Critical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkTagOwners(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-006" {
				t.Errorf("ID = %q, want ACL-006", result.ID)
			}

			if !tt.wantPass && result.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSev)
			}
		})
	}
}

func TestCheckDangerAll(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name      string
		policy    ACLPolicy
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no danger-all usage",
			policy:   ACLPolicy{},
			wantPass: true,
		},
		{
			name: "danger-all in ACL src",
			policy: ACLPolicy{
				ACLs: []ACLRule{
					{Src: []string{"autogroup:danger-all"}, Dst: []string{"*:*"}},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "danger-all in SSH src",
			policy: ACLPolicy{
				SSH: []SSHRule{
					{Src: []string{"autogroup:danger-all"}, Dst: []string{"tag:server"}, Users: []string{"root"}},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "danger-all in tagOwners",
			policy: ACLPolicy{
				TagOwners: map[string][]string{
					"tag:server": {"autogroup:danger-all"},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "danger-all in autoApprovers routes",
			policy: ACLPolicy{
				AutoApprovers: &AutoApprovers{
					Routes: map[string][]string{
						"10.0.0.0/8": {"autogroup:danger-all"},
					},
				},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkDangerAll(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-007" {
				t.Errorf("ID = %q, want ACL-007", result.ID)
			}

			if !tt.wantPass {
				if result.Severity != types.Critical {
					t.Errorf("Severity = %v, want Critical", result.Severity)
				}
			}
		})
	}
}

func TestCheckGroupsExist(t *testing.T) {
	a := &ACLAuditor{}

	tests := []struct {
		name     string
		policy   ACLPolicy
		wantPass bool
	}{
		{
			name:     "no groups",
			policy:   ACLPolicy{},
			wantPass: false,
		},
		{
			name: "has groups",
			policy: ACLPolicy{
				Groups: map[string][]string{
					"group:engineers": {"alice@example.com", "bob@example.com"},
				},
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkGroupsExist(tt.policy)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "ACL-008" {
				t.Errorf("ID = %q, want ACL-008", result.ID)
			}
		})
	}
}

func TestCheckAllowAllIgnoresCommentsInPolicy(t *testing.T) {
	// Regression: field presence was detected by searching the raw HuJSON for
	// `"acls"`, so a comment mentioning the key made an omitted section look
	// present and hid the default allow-all policy.
	a := &ACLAuditor{}

	hujsonWithComment := []byte(`{
		// This tailnet has no "acls" section on purpose, see the "grants" RFC.
		"tagOwners": {"tag:server": ["group:admin"]}
	}`)
	standardized, err := hujson.Standardize(hujsonWithComment)
	if err != nil {
		t.Fatalf("standardizing test policy: %v", err)
	}

	got := a.checkAllowAll(ACLPolicy{}, newPolicyFields(standardized))
	if got.Pass {
		t.Error("checkAllowAll() Pass = true, want false: the policy omits acls and grants, leaving the default allow-all in force")
	}
	if got.Severity != types.Critical {
		t.Errorf("checkAllowAll() severity = %s, want CRITICAL", got.Severity)
	}
}

func TestPolicyFieldsReportsUnparseablePolicy(t *testing.T) {
	fields := newPolicyFields([]byte(`not json`))
	if fields.parsed {
		t.Error("newPolicyFields() parsed = true for invalid JSON")
	}

	a := &ACLAuditor{}
	got := a.checkAllowAll(ACLPolicy{}, fields)
	if got.Pass {
		t.Error("checkAllowAll() Pass = true for an unparseable policy; it should not claim the rules were evaluated")
	}
}

func TestCheckTagReach(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}
	gw := dev("prod-gw", []string{"10.0.0.0/8"}, nil)
	devices := []*client.Device{web, gw}

	reusableCIKey := client.Key{ID: "k1", KeyType: client.KeyTypeAuth}
	reusableCIKey.Capabilities.Devices.Create.Reusable = true
	reusableCIKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}

	a := &ACLAuditor{}

	t.Run("mintable tag reaching wildcard fails high", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, nil)
		if f.Pass || f.Severity != types.High {
			t.Errorf("want fail HIGH, got pass=%v severity=%s", f.Pass, f.Severity)
		}
		// The reach table is the check's informational payload even on a
		// failing result: describeReach must have run and named the tag, and
		// must say the minting key is reusable specifically.
		if !detailsContain(f.Details, "tag:ci: reaches every device in the tailnet (a rule grants *:*)") {
			t.Errorf("Details does not contain a reach line naming tag:ci: %v", f.Details)
		}
		if !detailsContain(f.Details, "a reusable auth key can assign this tag") {
			t.Errorf("Details should say a reusable auth key can assign tag:ci: %v", f.Details)
		}
	})

	t.Run("broad tag no key can mint stays informational", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:monitoring": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:monitoring"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, nil)
		if !f.Pass {
			t.Error("a broad tag that no auth key can mint must not fail")
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO for a tag no key can mint", f.Severity)
		}
	})

	t.Run("mintable tag reaching a routed cidr fails", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, nil)
		if f.Pass {
			t.Error("reaching a routed subnet crosses the tailnet boundary and must fail")
		}
	})

	t.Run("narrow mintable tag passes", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, nil)
		if !f.Pass {
			t.Errorf("a tag reaching one device on one port should not fail: %+v", f.Details)
		}
	})

	t.Run("unreadable keys degrade to informational, not pass", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, nil, errors.New("403"), nil)
		if f.Pass {
			t.Error("mintability unknown must not report as a satisfied control")
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO when mintability is unknown", f.Severity)
		}
		// The fix here is the credential's read scope, not the ACL rules -
		// Remediation must point at that instead of the generic "narrow the
		// rules" advice, which would tell the user to fix the wrong thing.
		if !strings.Contains(f.Remediation, "auth_keys:read") {
			t.Errorf("Remediation = %q, want guidance to grant auth_keys:read", f.Remediation)
		}
	})

	// The subtests above establish the HIGH arm (reusable key) for the
	// wildcard condition, and structurally fail the routed-CIDR condition,
	// but none of them assert MEDIUM for a one-off key, and none reach
	// exit-node egress at all. Those are exercised below so that removing
	// the Medium/High distinction, or removing the egress crossing check,
	// is caught by a test rather than silently passing.

	t.Run("mintable tag via a one-off key reaching wildcard fails medium", func(t *testing.T) {
		oneOffKey := client.Key{ID: "k2", KeyType: client.KeyTypeAuth}
		oneOffKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{oneOffKey}, nil, nil)
		if f.Pass || f.Severity != types.Medium {
			t.Errorf("want fail MEDIUM for a one-off key, got pass=%v severity=%s", f.Pass, f.Severity)
		}
		if !detailsContain(f.Details, "tag:ci: reaches every device in the tailnet (a rule grants *:*)") {
			t.Errorf("Details does not contain a reach line naming tag:ci: %v", f.Details)
		}
		if !detailsContain(f.Details, "an auth key can assign this tag") {
			t.Errorf("Details should say an auth key can assign tag:ci: %v", f.Details)
		}
		if detailsContain(f.Details, "a reusable auth key can assign this tag") {
			t.Errorf("a one-off key must not be described as reusable: %v", f.Details)
		}
	})

	t.Run("mintable tag reaching a routed cidr via a reusable key fails high", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, nil)
		if f.Pass || f.Severity != types.High {
			t.Errorf("want fail HIGH for a routed cidr minted by a reusable key, got pass=%v severity=%s", f.Pass, f.Severity)
		}
	})

	t.Run("mintable tag reaching a routed cidr via a one-off key fails medium", func(t *testing.T) {
		oneOffKey := client.Key{ID: "k3", KeyType: client.KeyTypeAuth}
		oneOffKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{oneOffKey}, nil, nil)
		if f.Pass || f.Severity != types.Medium {
			t.Errorf("want fail MEDIUM for a routed cidr minted by a one-off key, got pass=%v severity=%s", f.Pass, f.Severity)
		}
	})

	t.Run("mintable tag reaching exit-node egress fails high", func(t *testing.T) {
		exit := dev("edge-01", []string{"0.0.0.0/0", "::/0"}, nil)
		devicesWithExit := append(append([]*client.Device{}, devices...), exit)
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"autogroup:internet:*"}}},
		}
		f := a.checkTagReach(policy, devicesWithExit, []client.Key{reusableCIKey}, nil, nil)
		if f.Pass || f.Severity != types.High {
			t.Errorf("want fail HIGH for internet egress minted by a reusable key, got pass=%v severity=%s", f.Pass, f.Severity)
		}
	})

	// Severity must never derive from a device count - only from whether reach
	// crosses a structural boundary (wildcard, routed CIDR, or exit-node
	// egress). "narrow mintable tag passes" reaches only one device, so it
	// would not catch a future `if len(r.Devices) > N { sev = High }` inserted
	// into the severity path. This reaches many devices, on specific ports,
	// with none of the three boundary crossings present, and must still pass
	// as informational regardless of how many devices that is.
	t.Run("mintable tag reaching many devices on specific ports stays informational", func(t *testing.T) {
		manyDevices := make([]*client.Device, 0, 6)
		for i := 0; i < 6; i++ {
			d := &client.Device{}
			d.Name = fmt.Sprintf("prod-%02d", i)
			d.Tags = []string{"tag:prod"}
			manyDevices = append(manyDevices, d)
		}
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
		}
		f := a.checkTagReach(policy, manyDevices, []client.Key{reusableCIKey}, nil, nil)
		if !f.Pass {
			t.Errorf("reaching many devices on a specific port is not a boundary crossing and should not fail: %+v", f.Details)
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO regardless of device count", f.Severity)
		}
	})
}

// ignoreListFor loads an ignore file naming ACL-011 items, e.g.
// "tag:monitoring" or "tag:monitoring\ntag:backup". types.IgnoreList's fields
// are unexported, so a real file is the only way to build one from this
// package - the same thing cmd/root.go does for a real run.
func ignoreListFor(t *testing.T, items ...string) *types.IgnoreList {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".tailsnitch-ignore")
	var content strings.Builder
	for _, item := range items {
		fmt.Fprintf(&content, "ACL-011:%s\n", item)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	il, err := types.LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return il
}

// TestCheckTagReachPerItemIgnore covers the wiring required beyond the
// brief: ACL-011 must consult IsItemIgnored while building its per-tag
// detail lines, and suppressing the only offending tag must not turn the
// check into a satisfied control.
func TestCheckTagReachPerItemIgnore(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}
	devices := []*client.Device{web}

	reusableCIKey := client.Key{ID: "k1", KeyType: client.KeyTypeAuth}
	reusableCIKey.Capabilities.Devices.Create.Reusable = true
	reusableCIKey.Capabilities.Devices.Create.Tags = []string{"tag:ci", "tag:monitoring"}

	a := &ACLAuditor{}

	t.Run("a suppressed tag does not appear in the reach table", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil, "tag:monitoring": nil},
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}},
				{Action: "accept", Src: []string{"tag:monitoring"}, Dst: []string{"*:*"}},
			},
		}
		il := ignoreListFor(t, "tag:monitoring")

		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, il)

		if detailsContain(f.Details, "tag:monitoring") {
			t.Errorf("a suppressed tag must not appear in the reach table: %v", f.Details)
		}
		if !detailsContain(f.Details, "tag:ci") {
			t.Errorf("an unsuppressed tag must still appear in the reach table: %v", f.Details)
		}
	})

	t.Run("suppressing the only offending tag stays failed, not passing", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:monitoring": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:monitoring"}, Dst: []string{"*:*"}}},
		}
		il := ignoreListFor(t, "tag:monitoring")

		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, il)

		if f.Pass {
			t.Error("SECURITY: suppressing the only offending tag must not flip Pass to true - " +
				"that would let an ignore file turn a real gap green")
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO once the only offender is suppressed", f.Severity)
		}
		if f.Fix != nil {
			t.Errorf("Fix = %+v, want none once the only offender is suppressed (nothing actionable remains)", f.Fix)
		}
	})

	t.Run("suppressing a tag that never offended leaves the check clean but still notes the suppression", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
		}
		il := ignoreListFor(t, "tag:ci")

		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil, il)

		if !f.Pass {
			t.Errorf("suppressing a tag that was never an offender must not change a clean result: %+v", f)
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO for a clean result", f.Severity)
		}
		// Description's "Reach computed for %d tag(s)" counts every tag the
		// policy defines, including the suppressed one, over a table that
		// omits it - Details must say so or the two contradict each other.
		if !detailsContain(f.Details, "were suppressed by the ignore file") {
			t.Errorf("Details must note that a tag was suppressed, since the count above still includes it: %v", f.Details)
		}
	})

	t.Run("unreadable keys: a suppressed tag is still noted on the manual-check list", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil, "tag:monitoring": nil},
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}},
				{Action: "accept", Src: []string{"tag:monitoring"}, Dst: []string{"*:*"}},
			},
		}
		il := ignoreListFor(t, "tag:monitoring")

		f := a.checkTagReach(policy, devices, nil, errors.New("403"), il)

		if f.Pass {
			t.Error("mintability unknown must not report as a satisfied control")
		}
		if detailsContain(f.Details, "tag:monitoring") {
			t.Errorf("the suppressed tag must not appear in the reach table: %v", f.Details)
		}
		// This list is what the person is told to check by hand. Silently
		// shrinking it because of an ignore file written for a different
		// question (boundary crossing) would leave tag:monitoring unchecked
		// by either question.
		if !detailsContain(f.Details, "MANUAL CHECK REQUIRED") || !detailsContain(f.Details, "were suppressed by the ignore file") {
			t.Errorf("the manual-check list must note that a tag was suppressed, not just drop it: %v", f.Details)
		}
	})

	t.Run("one offender suppressed, another remains: still fails on the unsuppressed one", func(t *testing.T) {
		reusableBackupKey := client.Key{ID: "k2", KeyType: client.KeyTypeAuth}
		reusableBackupKey.Capabilities.Devices.Create.Reusable = true
		reusableBackupKey.Capabilities.Devices.Create.Tags = []string{"tag:ci", "tag:backup"}

		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil, "tag:backup": nil},
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}},
				{Action: "accept", Src: []string{"tag:backup"}, Dst: []string{"*:*"}},
			},
		}
		il := ignoreListFor(t, "tag:backup")

		f := a.checkTagReach(policy, devices, []client.Key{reusableBackupKey}, nil, il)

		if f.Pass {
			t.Error("tag:ci still crosses a boundary and is not suppressed; the check must still fail")
		}
		if detailsContain(f.Details, "tag:backup") {
			t.Errorf("the suppressed tag must not appear anywhere in Details: %v", f.Details)
		}
		if !detailsContain(f.Details, "tag:ci") {
			t.Errorf("the unsuppressed offender must still be named: %v", f.Details)
		}
		// The header must not claim to list every tag over a table that
		// deliberately omits the suppressed one.
		if !detailsContain(f.Details, "Reach for every unsuppressed tag:") {
			t.Errorf("Details header must say \"unsuppressed\" once a tag was left out: %v", f.Details)
		}
	})
}

// A device inventory that came back empty without an error cannot be told
// apart from one that was never populated. Computing reach against it prints
// "reaches 0 of 0 devices" for every tag and would let the check report a
// clean sweep over an inventory it never had.
func TestCheckTagReachEmptyInventoryIsNotEvaluated(t *testing.T) {
	reusableCIKey := client.Key{ID: "k1", KeyType: client.KeyTypeAuth}
	reusableCIKey.Capabilities.Devices.Create.Reusable = true
	reusableCIKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}

	// A tag destination, not a wildcard: against a real inventory this tag
	// crosses no boundary, so with no inventory at all the check would take
	// the clean-sweep path and report a satisfied control.
	policy := ACLPolicy{
		TagOwners: map[string][]string{"tag:ci": nil},
		ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
	}

	f := (&ACLAuditor{}).checkTagReach(policy, nil, []client.Key{reusableCIKey}, nil, nil)

	if f.Pass {
		t.Error("SECURITY: an empty device inventory must not report as a satisfied control - " +
			"a passing finding is filtered from the default output and counted as a satisfied control")
	}
	if !strings.Contains(f.Title, "not evaluated") {
		t.Errorf("Title = %q, want the not-evaluated finding", f.Title)
	}
	if !strings.Contains(f.Description, "empty") {
		t.Errorf("Description = %q, want it to name the empty inventory", f.Description)
	}
	if detailsContain(f.Details, "0 of 0") {
		t.Errorf("Details prints reach figures derived from an inventory the check never had: %v", f.Details)
	}
}

// Regression: autogroup:tagged means every tagged device, so a rule with that
// source grants every tag whatever it names. Reading it as matching no tag
// made ACL-011 compute zero reach and pass on exactly the tailnet - one broad
// rule, every tagged node behind it - that this check exists to find.
func TestCheckTagReachAutogroupTaggedSource(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}

	reusableCIKey := client.Key{ID: "k1", KeyType: client.KeyTypeAuth}
	reusableCIKey.Capabilities.Devices.Create.Reusable = true
	reusableCIKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}

	policy := ACLPolicy{
		TagOwners: map[string][]string{"tag:ci": nil},
		ACLs:      []ACLRule{{Action: "accept", Src: []string{"autogroup:tagged"}, Dst: []string{"*:*"}}},
	}

	f := (&ACLAuditor{}).checkTagReach(policy, []*client.Device{web}, []client.Key{reusableCIKey}, nil, nil)

	if f.Pass {
		t.Error("SECURITY: a rule granting autogroup:tagged access to everything puts every " +
			"mintable tag on the whole tailnet; the check must not report that as clean")
	}
	if f.Severity != types.High {
		t.Errorf("Severity = %s, want HIGH: a reusable key mints tag:ci and tag:ci reaches every device", f.Severity)
	}
}

// suppressedTagsPresent exists so an ignore rule naming a tag the policy does
// not have cannot claim something was suppressed. Without its present filter
// the check tells the reader that tags are missing from a table that is in
// fact complete, which is worse than saying nothing.
func TestSuppressedTagsPresentIgnoresAbsentTags(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}

	policy := ACLPolicy{
		TagOwners: map[string][]string{"tag:ci": nil},
		ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
	}
	reaches := AllTagReach(policy, []*client.Device{web})

	// The ignore file names a tag this policy does not define. Nothing was
	// suppressed, because there was nothing there to suppress.
	il := ignoreListFor(t, "tag:absent")

	if got := suppressedTagsPresent(il, reaches); len(got) != 0 {
		t.Errorf("suppressedTagsPresent() = %v, want none: the policy has no tag:absent to suppress", got)
	}

	f := (&ACLAuditor{}).checkTagReach(policy, []*client.Device{web}, nil, nil, il)

	if detailsContain(f.Details, "were suppressed by the ignore file") {
		t.Errorf("the check claims a tag was hidden from a complete table: %v", f.Details)
	}
	if !detailsContain(f.Details, "tag:ci") {
		t.Errorf("the reach table must still list tag:ci: %v", f.Details)
	}
}
