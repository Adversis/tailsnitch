package auditor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

func TestCheckReusableKeys(t *testing.T) {
	a := &AuthAuditor{} // nil client is fine - check functions don't use it

	tests := []struct {
		name      string
		keys      []keyInfo
		wantPass  bool
		wantSev   types.Severity
		wantCount int // expected number of flagged keys
	}{
		{
			name:     "no keys",
			keys:     nil,
			wantPass: true,
		},
		{
			name: "no reusable keys",
			keys: []keyInfo{
				{ID: "key1", Reusable: false, DaysToExpiry: 30},
				{ID: "key2", Reusable: false, DaysToExpiry: 60},
			},
			wantPass: true,
		},
		{
			name: "one reusable key",
			keys: []keyInfo{
				{ID: "key1", Reusable: true, DaysToExpiry: 30},
			},
			wantPass:  false,
			wantSev:   types.High,
			wantCount: 1,
		},
		{
			name: "multiple reusable keys",
			keys: []keyInfo{
				{ID: "key1", Reusable: true, DaysToExpiry: 30},
				{ID: "key2", Reusable: false, DaysToExpiry: 60},
				{ID: "key3", Reusable: true, DaysToExpiry: 90, Tags: []string{"tag:ci"}},
			},
			wantPass:  false,
			wantSev:   types.High,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkReusableKeys(tt.keys)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "AUTH-001" {
				t.Errorf("ID = %q, want AUTH-001", result.ID)
			}

			if !tt.wantPass {
				if result.Severity != tt.wantSev {
					t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSev)
				}
				if details, ok := result.Details.([]string); ok {
					if len(details) != tt.wantCount {
						t.Errorf("Details count = %d, want %d", len(details), tt.wantCount)
					}
				}
				if result.Fix == nil {
					t.Error("Fix should not be nil for failed check")
				} else if result.Fix.Type != types.FixTypeAPI {
					t.Errorf("Fix.Type = %v, want %v", result.Fix.Type, types.FixTypeAPI)
				}
			}
		})
	}
}

func TestCheckLongExpiryKeys(t *testing.T) {
	a := &AuthAuditor{}

	tests := []struct {
		name      string
		keys      []keyInfo
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no keys",
			keys:     nil,
			wantPass: true,
		},
		{
			name: "keys within 90 days",
			keys: []keyInfo{
				{ID: "key1", DaysToExpiry: 30},
				{ID: "key2", DaysToExpiry: 90},
			},
			wantPass: true,
		},
		{
			name: "one key over 90 days",
			keys: []keyInfo{
				{ID: "key1", DaysToExpiry: 91},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "multiple keys over 90 days",
			keys: []keyInfo{
				{ID: "key1", DaysToExpiry: 100},
				{ID: "key2", DaysToExpiry: 50},
				{ID: "key3", DaysToExpiry: 180},
			},
			wantPass:  false,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkLongExpiryKeys(tt.keys)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "AUTH-002" {
				t.Errorf("ID = %q, want AUTH-002", result.ID)
			}

			if !tt.wantPass {
				if details, ok := result.Details.([]string); ok {
					if len(details) != tt.wantCount {
						t.Errorf("Details count = %d, want %d", len(details), tt.wantCount)
					}
				}
			}
		})
	}
}

func TestCheckPreauthorizedKeys(t *testing.T) {
	a := &AuthAuditor{}

	tests := []struct {
		name      string
		keys      []keyInfo
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no keys",
			keys:     nil,
			wantPass: true,
		},
		{
			name: "no preauthorized keys",
			keys: []keyInfo{
				{ID: "key1", Preauthorized: false},
			},
			wantPass: true,
		},
		{
			name: "preauthorized key",
			keys: []keyInfo{
				{ID: "key1", Preauthorized: true, DaysToExpiry: 30, Tags: []string{"tag:server"}},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkPreauthorizedKeys(tt.keys)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "AUTH-003" {
				t.Errorf("ID = %q, want AUTH-003", result.ID)
			}
		})
	}
}

func TestCheckEphemeralKeyUsage(t *testing.T) {
	a := &AuthAuditor{}

	tests := []struct {
		name      string
		keys      []keyInfo
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no keys",
			keys:     nil,
			wantPass: true,
		},
		{
			name: "ephemeral reusable key - good",
			keys: []keyInfo{
				{ID: "key1", Reusable: true, Ephemeral: true},
			},
			wantPass: true,
		},
		{
			name: "non-ephemeral reusable key - bad",
			keys: []keyInfo{
				{ID: "key1", Reusable: true, Ephemeral: false},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "non-reusable non-ephemeral - ok",
			keys: []keyInfo{
				{ID: "key1", Reusable: false, Ephemeral: false},
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.checkEphemeralKeyUsage(tt.keys)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "AUTH-004" {
				t.Errorf("ID = %q, want AUTH-004", result.ID)
			}
		})
	}
}

func TestKeyInfoDaysToExpiry(t *testing.T) {
	// Test that DaysToExpiry is calculated correctly
	now := time.Now()

	tests := []struct {
		name       string
		expires    time.Time
		wantApprox int
	}{
		{
			name:       "30 days from now",
			expires:    now.AddDate(0, 0, 30),
			wantApprox: 30,
		},
		{
			name:       "90 days from now",
			expires:    now.AddDate(0, 0, 90),
			wantApprox: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daysToExpiry := int(time.Until(tt.expires).Hours() / 24)
			// Allow 1 day tolerance for test timing
			if daysToExpiry < tt.wantApprox-1 || daysToExpiry > tt.wantApprox+1 {
				t.Errorf("DaysToExpiry = %d, want ~%d", daysToExpiry, tt.wantApprox)
			}
		})
	}
}

func TestKeyInfoLabelPrefersDescription(t *testing.T) {
	// The keys endpoint returns a description, so findings can name a key by
	// what it is for rather than by its opaque ID.
	withDesc := keyInfo{ID: "kABC123", Description: "ci-runner"}
	if got, want := withDesc.label(), "ci-runner (kABC123)"; got != want {
		t.Errorf("label() = %q, want %q", got, want)
	}

	bare := keyInfo{ID: "kABC123"}
	if got, want := bare.label(), "kABC123"; got != want {
		t.Errorf("label() = %q, want %q", got, want)
	}
}

func TestNewKeyInfoProjectsCapabilities(t *testing.T) {
	key := client.Key{
		ID:          "k1",
		KeyType:     client.KeyTypeAuth,
		Description: "ci",
		Expires:     time.Now().Add(48 * time.Hour),
	}
	key.Capabilities.Devices.Create.Reusable = true
	key.Capabilities.Devices.Create.Preauthorized = true
	key.Capabilities.Devices.Create.Tags = []string{"tag:ci"}

	got := newKeyInfo(key)
	if !got.Reusable || !got.Preauthorized || got.Ephemeral {
		t.Errorf("newKeyInfo() capabilities = %+v, want reusable and preauthorized only", got)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "tag:ci" {
		t.Errorf("newKeyInfo() tags = %v, want [tag:ci]", got.Tags)
	}
	if got.DaysToExpiry != 1 {
		t.Errorf("newKeyInfo() DaysToExpiry = %d, want 1", got.DaysToExpiry)
	}
}

func TestCheckFederationInUse(t *testing.T) {
	candidate := keyInfo{
		ID: "k1", Description: "ci-runner",
		Reusable: true, Ephemeral: false,
		Tags: []string{"tag:ci"}, DaysToExpiry: 341,
	}
	oneOff := keyInfo{ID: "k2", Reusable: false, Tags: []string{"tag:ci"}, DaysToExpiry: 7}
	untagged := keyInfo{ID: "k3", Reusable: true, DaysToExpiry: 30}
	expired := keyInfo{ID: "k4", Reusable: true, Tags: []string{"tag:old"}, DaysToExpiry: -3}
	ephemeral := keyInfo{ID: "k5", Reusable: true, Ephemeral: true, Tags: []string{"tag:ci"}, DaysToExpiry: 30}

	a := &AuthAuditor{}

	t.Run("no candidates passes", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{oneOff, untagged, expired}, nil)
		if !f.Pass {
			t.Errorf("expected pass with no migration candidates, got %+v", f.Details)
		}
	})

	t.Run("candidates and no federation fails medium", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{candidate}, nil)
		if f.Pass {
			t.Error("expected fail when a reusable tagged key has no federation")
		}
		if f.Severity != types.Medium {
			t.Errorf("Severity = %s, want MEDIUM", f.Severity)
		}
	})

	t.Run("covered tag passes", func(t *testing.T) {
		identities := []client.Key{{ID: "f1", Tags: []string{"tag:ci"}}}
		f := a.checkFederationInUse([]keyInfo{candidate}, identities)
		if !f.Pass {
			t.Errorf("expected pass when the tag is covered, got %+v", f.Details)
		}
	})

	t.Run("uncovered tag fails low", func(t *testing.T) {
		identities := []client.Key{{ID: "f1", Tags: []string{"tag:other"}}}
		f := a.checkFederationInUse([]keyInfo{candidate}, identities)
		if f.Pass {
			t.Error("expected fail when the candidate's tag is not covered")
		}
		if f.Severity != types.Low {
			t.Errorf("Severity = %s, want LOW", f.Severity)
		}
	})

	t.Run("expired key is not a candidate", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{expired}, nil)
		if !f.Pass {
			t.Error("an expired key should not be a migration candidate")
		}
	})

	t.Run("ephemeral key is not a candidate", func(t *testing.T) {
		// Reusable, tagged, unexpired - only Ephemeral can exclude this key.
		// An ephemeral CI node removes itself after inactivity, so it is not
		// the long-lived credential shape this check looks for.
		f := a.checkFederationInUse([]keyInfo{ephemeral}, nil)
		if !f.Pass {
			t.Error("an ephemeral key should not be a migration candidate")
		}
	})
}

// When GetAuthKeys succeeds but the later GetFederatedIdentities call fails,
// no AUTH-ERR finding is emitted (that only happens when GetAuthKeys itself
// fails). The not-evaluated reason for AUTH-005 must therefore name the
// actual error rather than point at a finding that was never raised.
func TestFederationFetchFailedNamesTheErrorNotAUTHERR(t *testing.T) {
	f := federationFetchFailed("AUTH-005", errors.New("connection reset by peer"))

	if f.Pass {
		t.Error("expected Pass=false for a not-evaluated finding")
	}
	if !strings.Contains(f.Description, "connection reset by peer") {
		t.Errorf("Description = %q, want it to name the actual error", f.Description)
	}
	if strings.Contains(f.Description, "AUTH-ERR") {
		t.Errorf("Description = %q, must not reference AUTH-ERR: no such finding is emitted on this path", f.Description)
	}
}

func TestSubjectBreadth(t *testing.T) {
	tests := []struct {
		subject string
		want    breadth
	}{
		{"", breadthAny},
		{"*", breadthAny},
		{"**", breadthAny},
		{"*:*", breadthAny},
		{"*/repo:ref:refs/heads/main", breadthLeadingWildcard},
		{"repo:org/*", breadthTrailingWildcard},
		{"repo:org/repo:*", breadthTrailingWildcard},
		{"repo:org/repo:ref:refs/heads/main", breadthPinned},
	}

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			if got := subjectBreadth(tt.subject); got != tt.want {
				t.Errorf("subjectBreadth(%q) = %v, want %v", tt.subject, got, tt.want)
			}
		})
	}
}

func TestCheckFederatedIdentityConfig(t *testing.T) {
	a := &AuthAuditor{}

	t.Run("no identities passes", func(t *testing.T) {
		if f := a.checkFederatedIdentityConfig(nil); !f.Pass {
			t.Error("expected pass with no federated identities")
		}
	})

	t.Run("pinned subject passes", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Issuer: "token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audience: "tailscale",
		}}
		if f := a.checkFederatedIdentityConfig(ids); !f.Pass {
			t.Errorf("expected pass for a pinned subject, got %+v", f.Details)
		}
	})

	t.Run("wildcard subject fails high", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Issuer: "token.actions.githubusercontent.com", Subject: "*"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass {
			t.Error("expected fail for a whole-subject wildcard")
		}
		if f.Severity != types.High {
			t.Errorf("Severity = %s, want HIGH", f.Severity)
		}
	})

	t.Run("unknown issuer gets the same verdict", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Issuer: "oidc.example.invalid", Subject: "*"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass || f.Severity != types.High {
			t.Error("an unknown issuer must not change the verdict")
		}
	})

	t.Run("trailing wildcard reports without failing high", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Subject: "repo:org/*", Audience: "tailscale"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Severity == types.High {
			t.Error("a trailing wildcard should not be rated HIGH")
		}
	})

	// The two cases below isolate the switch branches in
	// checkFederatedIdentityConfig from the CustomClaimRules supporting-fact
	// note: both Audience and CustomClaimRules are set here, so the only way
	// either identity is flagged at all is via the wildcard-position switch
	// itself. Without these, deleting a case arm (e.g. the
	// breadthLeadingWildcard arm) would leave every other test passing,
	// because the trailing-wildcard case above still has an empty
	// CustomClaimRules and gets flagged through the supporting-fact note
	// regardless of the switch.
	t.Run("leading wildcard is flagged by the switch alone", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Subject: "*/repo:ref:refs/heads/main",
			Audience: "tailscale", CustomClaimRules: map[string]string{"repository": "org/repo"},
		}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass {
			t.Error("expected fail for a leading-wildcard subject")
		}
		if f.Severity == types.High {
			t.Error("a leading wildcard should not be rated HIGH")
		}
	})

	t.Run("trailing wildcard is flagged by the switch alone", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Subject: "repo:org/*",
			Audience: "tailscale", CustomClaimRules: map[string]string{"repository": "org/repo"},
		}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass {
			t.Error("expected fail for a trailing-wildcard subject")
		}
		if f.Severity == types.High {
			t.Error("a trailing wildcard should not be rated HIGH")
		}
	})

	// Isolates the empty-audience supporting fact from the wildcard-subject
	// switch: subject is pinned and claim rules are set, so the audience note
	// is the only thing that can fail this check. Confirms a missing
	// audience alone reports without escalating to HIGH.
	t.Run("missing audience alone is low, not high", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Subject: "repo:org/repo:ref:refs/heads/main",
			CustomClaimRules: map[string]string{"repository": "org/repo"},
		}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass {
			t.Error("expected fail: a missing audience should still be reported")
		}
		if f.Severity != types.Low {
			t.Errorf("Severity = %s, want LOW; a missing audience alone must not escalate to HIGH", f.Severity)
		}
	})
}

func TestReachNote(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}
	devices := []*client.Device{web}
	policy := ACLPolicy{
		ACLs: []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
	}

	t.Run("unparsed policy yields no note", func(t *testing.T) {
		if got := reachNote([]string{"tag:ci"}, policy, false, devices); got != "" {
			t.Errorf("reachNote = %q, want empty when the policy did not parse", got)
		}
	})

	t.Run("no devices yields no note", func(t *testing.T) {
		if got := reachNote([]string{"tag:ci"}, policy, true, nil); got != "" {
			t.Errorf("reachNote = %q, want empty with no device inventory", got)
		}
	})

	t.Run("reach is described", func(t *testing.T) {
		got := reachNote([]string{"tag:ci"}, policy, true, devices)
		if !strings.Contains(got, "tag:ci") || !strings.Contains(got, "1 of 1") {
			t.Errorf("reachNote = %q, want it to name the tag and the count", got)
		}
	})

	// Isolates the len(tags) == 0 guard: policy parsed and devices present, so
	// only an empty tag list can make this return empty. A key with no tags
	// has nothing for reach to describe.
	t.Run("no tags yields no note", func(t *testing.T) {
		if got := reachNote(nil, policy, true, devices); got != "" {
			t.Errorf("reachNote = %q, want empty with no tags to describe", got)
		}
	})

	// A tag reaching a wildcard destination takes the other arm of the
	// switch: there is no count to print, because the rule covers every
	// device that joins later too. Printing "1 of 1" here would understate
	// it, and the arm is otherwise untested.
	t.Run("wildcard reach is named, not counted", func(t *testing.T) {
		wildcard := ACLPolicy{
			ACLs: []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		got := reachNote([]string{"tag:ci"}, wildcard, true, devices)
		if !strings.Contains(got, "tag:ci reaches every device") {
			t.Errorf("reachNote = %q, want it to say the tag reaches every device", got)
		}
		if strings.Contains(got, " of ") {
			t.Errorf("reachNote = %q, want no device count for a wildcard rule", got)
		}
	})

	// Routed reach leaves the tailnet, so the note has to name the CIDR
	// alongside the device count. Nothing else covers that clause.
	t.Run("routed reach names the cidr", func(t *testing.T) {
		gw := dev("prod-gw", []string{"10.0.0.0/8"}, nil)
		routed := ACLPolicy{
			ACLs: []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}}},
		}
		got := reachNote([]string{"tag:ci"}, routed, true, []*client.Device{web, gw})
		if !strings.Contains(got, "routes to 10.1.0.0/16") {
			t.Errorf("reachNote = %q, want it to name the routed CIDR", got)
		}
	})
}

// An entry whose subject, issuer and audience are all empty was not read, not
// configured: CreateFederatedIdentityRequest requires an issuer and a subject,
// so the API cannot have produced one. Classifying its empty subject as a
// wildcard invents a HIGH finding out of missing data and prints the
// self-evidently broken line `subject "" accepts any principal issued by .`
func TestCheckFederatedIdentityConfigUnreadableIdentity(t *testing.T) {
	a := &AuthAuditor{}

	t.Run("an all-empty identity is not evaluated, not a wildcard", func(t *testing.T) {
		f := a.checkFederatedIdentityConfig([]client.Key{{ID: "f1", KeyType: client.KeyTypeFederated}})

		if f.Pass {
			t.Error("SECURITY: an identity that could not be read must not report as a satisfied control")
		}
		if f.Severity == types.High {
			t.Error("SECURITY: missing fields are not a permissive configuration and must not be rated HIGH")
		}
		if !strings.Contains(f.Title, "not evaluated") {
			t.Errorf("Title = %q, want the not-evaluated finding", f.Title)
		}
		if strings.Contains(f.Description, "accepts any principal") {
			t.Errorf("Description = %q, want no wildcard-subject verdict on an unread identity", f.Description)
		}
		if detailsContain(f.Details, "accepts any principal") {
			t.Errorf("Details fabricates a wildcard verdict from missing data: %v", f.Details)
		}
	})

	// An unreadable entry must not swallow a real finding from a readable one.
	t.Run("a real wildcard alongside an unreadable entry still fails high", func(t *testing.T) {
		ids := []client.Key{
			{ID: "f1"},
			{ID: "f2", Issuer: "token.actions.githubusercontent.com", Subject: "*"},
		}
		f := a.checkFederatedIdentityConfig(ids)

		if f.Pass || f.Severity != types.High {
			t.Errorf("want fail HIGH on the readable wildcard, got pass=%v severity=%s", f.Pass, f.Severity)
		}
		if !detailsContain(f.Details, "could not be assessed") {
			t.Errorf("Details must still say one identity was never assessed: %v", f.Details)
		}
	})

	t.Run("a readable identity is unaffected", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Issuer: "token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audience: "tailscale",
		}}
		if f := a.checkFederatedIdentityConfig(ids); !f.Pass {
			t.Errorf("a fully pinned identity must still pass: %+v", f.Details)
		}
	})
}

func TestIdentityUnreadable(t *testing.T) {
	tests := []struct {
		name string
		id   client.Key
		want bool
	}{
		{"all three empty", client.Key{ID: "f1"}, true},
		{"whitespace only", client.Key{ID: "f1", Subject: " ", Issuer: "\t", Audience: " "}, true},
		{"subject set", client.Key{ID: "f1", Subject: "*"}, false},
		{"issuer set", client.Key{ID: "f1", Issuer: "oidc.example.invalid"}, false},
		{"audience set", client.Key{ID: "f1", Audience: "tailscale"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identityUnreadable(tt.id); got != tt.want {
				t.Errorf("identityUnreadable(%+v) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
