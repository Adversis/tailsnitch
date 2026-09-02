package types

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadIgnoreFile(t *testing.T) {
	// Create a temp ignore file
	tmpDir := t.TempDir()
	ignorePath := filepath.Join(tmpDir, ".tailsnitch-ignore")

	content := `# This is a comment
ACL-001
acl-009  # inline comment
DEV-004

# Another comment
SSH-002
`
	if err := os.WriteFile(ignorePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	il, err := LoadIgnoreFile(ignorePath)
	if err != nil {
		t.Fatalf("LoadIgnoreFile failed: %v", err)
	}

	if il.Count() != 4 {
		t.Errorf("Count() = %d, want 4", il.Count())
	}

	tests := []struct {
		id   string
		want bool
	}{
		{"ACL-001", true},
		{"acl-001", true}, // Case insensitive
		{"ACL-009", true},
		{"DEV-004", true},
		{"SSH-002", true},
		{"ACL-002", false},
		{"DEV-001", false},
	}

	for _, tt := range tests {
		if got := il.IsIgnored(tt.id); got != tt.want {
			t.Errorf("IsIgnored(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestLoadIgnoreFile_NotExist(t *testing.T) {
	il, err := LoadIgnoreFile("/nonexistent/path/.tailsnitch-ignore")
	if err != nil {
		t.Fatalf("LoadIgnoreFile should not error on missing file: %v", err)
	}

	if il.Count() != 0 {
		t.Errorf("Count() = %d, want 0 for missing file", il.Count())
	}
}

func TestFilterIgnored(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "ACL-001", Title: "Test 1"},
		{ID: "ACL-002", Title: "Test 2"},
		{ID: "DEV-004", Title: "Test 3"},
	}

	il := &IgnoreList{ids: map[string]bool{
		"ACL-001": true,
		"DEV-004": true,
	}}

	filtered, ignored := FilterIgnored(suggestions, il)

	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1", len(filtered))
	}

	if filtered[0].ID != "ACL-002" {
		t.Errorf("filtered[0].ID = %q, want ACL-002", filtered[0].ID)
	}

	want := []string{"ACL-001", "DEV-004"}
	if !slices.Equal(ignored, want) {
		t.Errorf("ignored = %v, want %v", ignored, want)
	}
}

func TestFilterIgnored_NilList(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "ACL-001", Title: "Test 1"},
	}

	filtered, ignored := FilterIgnored(suggestions, nil)

	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1 with nil ignore list", len(filtered))
	}

	if ignored != nil {
		t.Errorf("ignored = %v, want nil with nil ignore list", ignored)
	}
}

// TestPerItemIgnore is the brief's failing-test-first case for the
// CHECK-ID:item ignore format: a per-item line must not mute the whole
// check, the item is matched exactly, and the split is on the first colon
// only since the item itself contains one.
func TestPerItemIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".tailsnitch-ignore")
	content := `# comment
ACL-011:tag:monitoring   # backup agent, broad by design
ACL-011:tag:backup
AUTH-001
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	il, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("whole-id ignore still works", func(t *testing.T) {
		if !il.IsIgnored("AUTH-001") {
			t.Error("AUTH-001 should be ignored")
		}
	})

	t.Run("per-item line does not mute the whole check", func(t *testing.T) {
		if il.IsIgnored("ACL-011") {
			t.Error("a per-item line must not mute the entire check")
		}
	})

	t.Run("item is matched", func(t *testing.T) {
		if !il.IsItemIgnored("ACL-011", "tag:monitoring") {
			t.Error("tag:monitoring should be ignored for ACL-011")
		}
		if !il.IsItemIgnored("ACL-011", "tag:backup") {
			t.Error("tag:backup should be ignored for ACL-011")
		}
	})

	t.Run("other items are not ignored", func(t *testing.T) {
		if il.IsItemIgnored("ACL-011", "tag:ci") {
			t.Error("tag:ci must not be ignored")
		}
		if il.IsItemIgnored("AUTH-002", "tag:monitoring") {
			t.Error("an item is scoped to its own check")
		}
	})

	t.Run("split is on the first colon", func(t *testing.T) {
		items := il.ItemsFor("ACL-011")
		for _, item := range items {
			if !strings.HasPrefix(item, "tag:") {
				t.Errorf("item %q lost its colon; the split must be on the first colon only", item)
			}
		}
	})
}

// TestFilterIgnored_PerItem covers the wiring required beyond the brief:
// FilterIgnored must remove ignored items from a finding's Fix.Items and
// Details rather than dropping the whole finding, and it must never let a
// finding that already failed report as passing - only downgrade to
// Informational once nothing flagged remains.
func TestFilterIgnored_PerItem(t *testing.T) {
	newFinding := func() Suggestion {
		return Suggestion{
			ID:          "AUTH-001",
			Title:       "Reusable auth keys exist",
			Severity:    High,
			Pass:        false,
			Description: "Found 2 reusable auth key(s).",
			Details:     []string{"key one (expires in 10 days)", "key two (expires in 20 days)"},
			Fix: &FixInfo{
				Type: FixTypeAPI,
				Items: []FixableItem{
					{ID: "key1", Name: "key one"},
					{ID: "key2", Name: "key two"},
				},
			},
		}
	}

	t.Run("partial suppression removes only the ignored item", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true},
		}}

		filtered, ignored := FilterIgnored([]Suggestion{newFinding()}, il)
		if len(ignored) != 0 {
			t.Errorf("ignored = %v, want none (per-item rules do not mute the whole check)", ignored)
		}
		if len(filtered) != 1 {
			t.Fatalf("len(filtered) = %d, want 1 (the finding must not be dropped)", len(filtered))
		}
		f := filtered[0]

		if f.Pass {
			t.Error("Pass must stay false: one item was suppressed, not the finding")
		}
		if f.Severity != High {
			t.Errorf("Severity = %s, want unchanged HIGH when the finding is only partially suppressed", f.Severity)
		}
		if len(f.Fix.Items) != 1 || f.Fix.Items[0].ID != "key2" {
			t.Errorf("Fix.Items = %v, want only key2 remaining", f.Fix.Items)
		}
		details, ok := f.Details.([]string)
		if !ok || len(details) != 1 || details[0] != "key two (expires in 20 days)" {
			t.Errorf("Details = %v, want only key two's line remaining", f.Details)
		}
	})

	t.Run("suppressing every item does not make the check pass", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true, "key2": true},
		}}

		filtered, _ := FilterIgnored([]Suggestion{newFinding()}, il)
		if len(filtered) != 1 {
			t.Fatalf("len(filtered) = %d, want 1 (a fully-suppressed check must still be reported)", len(filtered))
		}
		f := filtered[0]

		if f.Pass {
			t.Error("SECURITY: suppressing every flagged item must not flip Pass to true - " +
				"that would let an ignore file turn a real gap green")
		}
		if f.Severity != Informational {
			t.Errorf("Severity = %s, want INFO once nothing flagged remains", f.Severity)
		}
		if len(f.Fix.Items) != 0 {
			t.Errorf("Fix.Items = %v, want none remaining", f.Fix.Items)
		}
	})

	t.Run("no per-item rules leaves the finding untouched", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"OTHER-001": {"x": true},
		}}

		filtered, _ := FilterIgnored([]Suggestion{newFinding()}, il)
		f := filtered[0]
		if len(f.Fix.Items) != 2 {
			t.Errorf("Fix.Items = %v, want both items untouched", f.Fix.Items)
		}
	})
}
