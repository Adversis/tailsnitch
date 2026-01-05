package types

import (
	"os"
	"path/filepath"
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

	filtered := FilterIgnored(suggestions, il)

	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1", len(filtered))
	}

	if filtered[0].ID != "ACL-002" {
		t.Errorf("filtered[0].ID = %q, want ACL-002", filtered[0].ID)
	}
}

func TestFilterIgnored_NilList(t *testing.T) {
	suggestions := []Suggestion{
		{ID: "ACL-001", Title: "Test 1"},
	}

	filtered := FilterIgnored(suggestions, nil)

	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1 with nil ignore list", len(filtered))
	}
}
