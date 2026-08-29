package types

import (
	"testing"
)

func TestRegistryHasNoDuplicateIDsOrSlugs(t *testing.T) {
	// A duplicate ID makes --checks select two unrelated findings and gives one
	// of them the other's title, category and SOC 2 mappings. DEV-013 was
	// assigned to both "User devices with key expiry disabled" and the device
	// posture check before this guard existed.
	seenID := make(map[string]string)
	seenSlug := make(map[string]string)

	for _, check := range DefaultRegistry.All() {
		if prev, ok := seenID[check.ID]; ok {
			t.Errorf("duplicate check ID %q used by both %q and %q", check.ID, prev, check.Title)
		}
		seenID[check.ID] = check.Title

		if prev, ok := seenSlug[check.Slug]; ok {
			t.Errorf("duplicate check slug %q used by both %q and %q", check.Slug, prev, check.Title)
		}
		seenSlug[check.Slug] = check.Title
	}
}

func TestRegistryEntriesAreWellFormed(t *testing.T) {
	for _, check := range DefaultRegistry.All() {
		if check.ID == "" || check.Title == "" || check.Slug == "" {
			t.Errorf("incomplete registry entry: %+v", check)
		}
		if check.Category == "" {
			t.Errorf("check %s has no category", check.ID)
		}
		if len(check.CCMappings) == 0 {
			t.Errorf("check %s has no SOC 2 Common Criteria mappings", check.ID)
		}
		if id, ok := DefaultRegistry.Resolve(check.Slug); !ok || id != check.ID {
			t.Errorf("slug %q for check %s does not resolve back to it", check.Slug, check.ID)
		}
	}
}
