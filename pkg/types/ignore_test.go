package types

import (
	"fmt"
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

// TestLoadIgnoreFile_TrailingColon covers a line like "ACL-011:" with
// nothing after the colon. It names no item, so it must fall back to a
// whole-check ignore of the part before the colon rather than silently
// registering a rule for the literal string "ACL-011:", which can never
// match any real check ID.
func TestLoadIgnoreFile_TrailingColon(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".tailsnitch-ignore")
	if err := os.WriteFile(path, []byte("ACL-011:\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	il, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !il.IsIgnored("ACL-011") {
		t.Error("a trailing colon with no item must fall back to a whole-check ignore")
	}
	if il.Count() != 1 {
		t.Errorf("Count() = %d, want 1 (not a phantom per-item rule for the empty string)", il.Count())
	}
	if items := il.ItemsFor("ACL-011"); items != nil {
		t.Errorf("ItemsFor(\"ACL-011\") = %v, want nil - no item was ever named", items)
	}
}

// detailsContainString reports whether details (a Suggestion.Details value)
// is a []string with a line containing substr.
func detailsContainString(details interface{}, substr string) bool {
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

// TestFilterIgnored_PerItem covers the wiring required beyond the brief:
// FilterIgnored must remove ignored items from a finding's Fix.Items and
// Details rather than dropping the whole finding, it must never let a
// finding that already failed report as passing - only downgrade to
// Informational once nothing flagged remains - and any suppression, partial
// or full, must leave a trace so Description's pre-filter counts never end
// up describing a Details list that has quietly shrunk.
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

	t.Run("partial suppression removes only the ignored item and records CHECK-ID:item", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true},
		}}

		filtered, ignored := FilterIgnored([]Suggestion{newFinding()}, il)
		if !slices.Equal(ignored, []string{"AUTH-001:key1"}) {
			t.Errorf("ignored = %v, want [AUTH-001:key1] (a per-item rule is recorded, but does not mute the whole check)", ignored)
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
		if !ok || len(details) != 2 || details[0] != "key two (expires in 20 days)" {
			t.Errorf("Details = %v, want key two's line plus a suppression note", f.Details)
		}
	})

	t.Run("partial suppression does not leave Description and Details contradicting each other", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true},
		}}

		filtered, _ := FilterIgnored([]Suggestion{newFinding()}, il)
		f := filtered[0]

		// Description was computed before filtering and still says "Found 2
		// reusable auth key(s)."; Details now lists only one. Without a note
		// reconciling the two, that is self-contradictory audit output.
		if strings.Contains(fmt.Sprint(f.Description), "2") && !detailsContainString(f.Details, "1 of 2") {
			t.Errorf("Description still says 2 but Details does not explain the discrepancy: description=%q details=%v",
				f.Description, f.Details)
		}
	})

	t.Run("suppressing every item does not make the check pass, and both items are recorded", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true, "key2": true},
		}}

		filtered, ignored := FilterIgnored([]Suggestion{newFinding()}, il)
		if !slices.Equal(ignored, []string{"AUTH-001:key1", "AUTH-001:key2"}) {
			t.Errorf("ignored = %v, want [AUTH-001:key1 AUTH-001:key2]", ignored)
		}
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
		if !detailsContainString(f.Details, "2 of 2") {
			t.Errorf("Details = %v, want a note that all 2 of 2 were suppressed", f.Details)
		}
	})

	t.Run("no per-item rules leaves the finding untouched", func(t *testing.T) {
		il := &IgnoreList{items: map[string]map[string]bool{
			"OTHER-001": {"x": true},
		}}

		filtered, ignored := FilterIgnored([]Suggestion{newFinding()}, il)
		f := filtered[0]
		if len(f.Fix.Items) != 2 {
			t.Errorf("Fix.Items = %v, want both items untouched", f.Fix.Items)
		}
		if len(ignored) != 0 {
			t.Errorf("ignored = %v, want none - OTHER-001 never appears in this report", ignored)
		}
	})

	t.Run("non-[]string Details is preserved, not discarded", func(t *testing.T) {
		f := newFinding()
		f.Details = "a single freeform detail line"
		il := &IgnoreList{items: map[string]map[string]bool{
			"AUTH-001": {"key1": true},
		}}

		filtered, _ := FilterIgnored([]Suggestion{f}, il)
		details, ok := filtered[0].Details.([]string)
		if !ok || len(details) != 2 || details[0] != "a single freeform detail line" {
			t.Errorf("Details = %v, want the original string preserved plus a suppression note, not discarded", filtered[0].Details)
		}
	})

	t.Run("a check with no Fix.Items still records its per-item rules via ItemsFor", func(t *testing.T) {
		// Models ACL-011: no FixInfo.Items, so filterItemsByIgnore never
		// touches it, but the ignore file still named one of its items and
		// that must not vanish from the report's record of what applied.
		selfSuppressing := Suggestion{ID: "ACL-011", Title: "Tag reach", Pass: false}
		il := &IgnoreList{items: map[string]map[string]bool{
			"ACL-011": {"tag:monitoring": true},
		}}

		filtered, ignored := FilterIgnored([]Suggestion{selfSuppressing}, il)
		if !slices.Equal(ignored, []string{"ACL-011:tag:monitoring"}) {
			t.Errorf("ignored = %v, want [ACL-011:tag:monitoring]", ignored)
		}
		if len(filtered) != 1 || filtered[0].ID != "ACL-011" {
			t.Errorf("filtered = %v, want the ACL-011 finding kept as-is (it already applied its own suppression)", filtered)
		}
	})

	t.Run("a misaligned Details is left untouched rather than deleting the wrong line", func(t *testing.T) {
		// Simulates a hypothetical future check that emits two Details lines
		// per item. len(Details) == 4 still satisfies "at least origCount",
		// so without the Name check the code would assume the last 2 lines
		// map 1:1 to the 2 Fix.Items and delete the wrong one.
		f := Suggestion{
			ID:       "HYPO-001",
			Pass:     false,
			Severity: High,
			Details: []string{
				"Item One first line", "Item One second line",
				"Item Two first line", "Item Two second line",
			},
			Fix: &FixInfo{
				Type: FixTypeAPI,
				Items: []FixableItem{
					{ID: "id1", Name: "Item One"},
					{ID: "id2", Name: "Item Two"},
				},
			},
		}
		il := &IgnoreList{items: map[string]map[string]bool{
			"HYPO-001": {"id1": true},
		}}

		filtered, _ := FilterIgnored([]Suggestion{f}, il)
		got := filtered[0]

		if len(got.Fix.Items) != 1 || got.Fix.Items[0].ID != "id2" {
			t.Errorf("Fix.Items = %v, want only id2 remaining regardless of the Details outcome", got.Fix.Items)
		}
		details, ok := got.Details.([]string)
		if !ok {
			t.Fatalf("Details = %v, want a []string", got.Details)
		}
		for _, want := range []string{"Item One first line", "Item One second line", "Item Two first line", "Item Two second line"} {
			found := false
			for _, d := range details {
				if d == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Details = %v, want the original line %q preserved: the alignment check should have refused to guess and left Details alone", details, want)
			}
		}
	})
}
