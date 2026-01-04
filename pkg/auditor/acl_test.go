package auditor

import (
	"testing"

	"tailsnitch/pkg/types"
)

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
			result := a.checkAllowAll(tt.policy, tt.rawACL)

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
