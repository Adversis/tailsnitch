package auditor

import "testing"

func TestTagMatchesSource(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		src  []string
		want bool
	}{
		{"exact tag", "tag:ci", []string{"tag:ci"}, true},
		{"tag among several", "tag:ci", []string{"tag:web", "tag:ci"}, true},
		{"wildcard", "tag:ci", []string{"*"}, true},
		{"different tag", "tag:ci", []string{"tag:prod"}, false},
		{"empty src", "tag:ci", nil, false},

		// Groups and user autogroups contain USERS. A tagged device is not a
		// user, so none of these grant a tag anything. Treating them as a
		// match would inflate every reach number in the report.
		{"autogroup:member", "tag:ci", []string{"autogroup:member"}, false},
		{"autogroup:admin", "tag:ci", []string{"autogroup:admin"}, false},
		{"autogroup:self", "tag:ci", []string{"autogroup:self"}, false},
		{"named group", "tag:ci", []string{"group:eng"}, false},
		{"user email", "tag:ci", []string{"someone@example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagMatchesSource(tt.tag, tt.src); got != tt.want {
				t.Errorf("tagMatchesSource(%q, %v) = %v, want %v", tt.tag, tt.src, got, tt.want)
			}
		})
	}
}
