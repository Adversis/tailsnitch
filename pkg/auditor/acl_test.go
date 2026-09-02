package auditor

import (
	"errors"
	"fmt"
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
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
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
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
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
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if f.Pass {
			t.Error("reaching a routed subnet crosses the tailnet boundary and must fail")
		}
	})

	t.Run("narrow mintable tag passes", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if !f.Pass {
			t.Errorf("a tag reaching one device on one port should not fail: %+v", f.Details)
		}
	})

	t.Run("unreadable keys degrade to informational, not pass", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, nil, errors.New("403"))
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
		f := a.checkTagReach(policy, devices, []client.Key{oneOffKey}, nil)
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
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
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
		f := a.checkTagReach(policy, devices, []client.Key{oneOffKey}, nil)
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
		f := a.checkTagReach(policy, devicesWithExit, []client.Key{reusableCIKey}, nil)
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
		f := a.checkTagReach(policy, manyDevices, []client.Key{reusableCIKey}, nil)
		if !f.Pass {
			t.Errorf("reaching many devices on a specific port is not a boundary crossing and should not fail: %+v", f.Details)
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO regardless of device count", f.Severity)
		}
	})
}
