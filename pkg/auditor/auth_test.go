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
}

// When GetAuthKeys succeeds but the later GetFederatedIdentities call fails,
// no AUTH-ERR finding is emitted (that only happens when GetAuthKeys itself
// fails). The not-evaluated reason for AUTH-005 must therefore name the
// actual error rather than point at a finding that was never raised.
func TestFederationFetchFailedNamesTheErrorNotAUTHERR(t *testing.T) {
	f := federationFetchFailed(errors.New("connection reset by peer"))

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
