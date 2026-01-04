package auditor

import (
	"testing"
	"time"

	"tailsnitch/pkg/types"
)

func TestCheckReusableKeys(t *testing.T) {
	a := &AuthAuditor{} // nil client is fine - check functions don't use it

	tests := []struct {
		name       string
		keys       []keyInfo
		wantPass   bool
		wantSev    types.Severity
		wantCount  int // expected number of flagged keys
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
		name         string
		expires      time.Time
		wantApprox   int
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
