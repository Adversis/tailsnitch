package types

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// IgnoreList holds check IDs to ignore, and items within a check to ignore.
type IgnoreList struct {
	ids   map[string]bool
	items map[string]map[string]bool // check ID -> item -> ignored
}

// DefaultIgnoreFiles returns the paths to check for ignore files, in order of priority
func DefaultIgnoreFiles() []string {
	paths := []string{
		".tailsnitch-ignore", // Current directory
	}

	// Also check home directory
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".tailsnitch-ignore"))
	}

	return paths
}

// LoadIgnoreFile loads an ignore file from the given path.
// Returns an empty IgnoreList if the file doesn't exist.
//
// Format: one rule per line, # for comments, blank lines ignored. A line
// names either a whole check ("ACL-011") or one item within it
// ("ACL-011:tag:monitoring"); the split is on the first colon only, since the
// item itself may contain colons.
func LoadIgnoreFile(path string) (*IgnoreList, error) {
	il := &IgnoreList{ids: make(map[string]bool), items: make(map[string]map[string]bool)}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return il, nil // Empty ignore list if file doesn't exist
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comment lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Handle inline comments: "ACL-001 # reason"
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// A line may name a whole check ("ACL-011") or one item within it
		// ("ACL-011:tag:monitoring"). The item can itself contain colons, so
		// the split is on the first colon only.
		if idx := strings.Index(line, ":"); idx > 0 {
			checkID := strings.ToUpper(strings.TrimSpace(line[:idx]))
			item := strings.TrimSpace(line[idx+1:])
			if item != "" {
				if il.items[checkID] == nil {
					il.items[checkID] = make(map[string]bool)
				}
				il.items[checkID][item] = true
				continue
			}
		}

		// Add to ignore list (case-insensitive for convenience)
		il.ids[strings.ToUpper(line)] = true
	}

	return il, scanner.Err()
}

// LoadIgnoreFiles tries to load ignore files from the default locations and
// returns the first one that yields any rules, with the path it came from.
func LoadIgnoreFiles() (*IgnoreList, string) {
	for _, path := range DefaultIgnoreFiles() {
		if _, err := os.Stat(path); err == nil {
			il, err := LoadIgnoreFile(path)
			if err == nil && il.Count() > 0 {
				return il, path
			}
		}
	}
	return &IgnoreList{ids: make(map[string]bool), items: make(map[string]map[string]bool)}, ""
}

// IsIgnored returns true if the check ID should be ignored in its entirety.
// A per-item rule for the check does not make this true: it mutes one item,
// not the whole check.
func (il *IgnoreList) IsIgnored(id string) bool {
	if il == nil {
		return false
	}
	return il.ids[strings.ToUpper(id)]
}

// IsItemIgnored reports whether one item within a check is ignored. What
// counts as an item is per-check: for ACL-011 it is the tag name, and for a
// check carrying a FixInfo it is the FixableItem ID. A check with no item
// notion never has entries here, so this simply returns false for it.
func (il *IgnoreList) IsItemIgnored(checkID, item string) bool {
	if il == nil {
		return false
	}
	items := il.items[strings.ToUpper(checkID)]
	if items == nil {
		return false
	}
	return items[item]
}

// ItemsFor returns the ignored items for a check, sorted, for reporting what
// was suppressed. It returns nil for a check with no per-item rules.
func (il *IgnoreList) ItemsFor(checkID string) []string {
	if il == nil {
		return nil
	}
	items := il.items[strings.ToUpper(checkID)]
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// Count returns the total number of ignore rules: whole-check ignores plus
// every per-item ignore across every check. cmd/root.go uses this to decide
// whether it is worth calling FilterIgnored at all, so a per-item-only ignore
// file must not report zero here.
func (il *IgnoreList) Count() int {
	if il == nil {
		return 0
	}
	total := len(il.ids)
	for _, items := range il.items {
		total += len(items)
	}
	return total
}

// filterItemsByIgnore removes the items ignoreList suppresses for s.ID from
// s.Fix.Items, and - where it can safely tell which Details line belongs to
// which item - from s.Details too. It never turns a failing finding into a
// passing one: suppressing every flagged item downgrades the finding to
// Informational rather than letting it disappear as a satisfied control,
// echoing NotEvaluated's rule that an unevaluated check must not read as one
// that passed.
//
// Only checks that carry FixInfo.Items are handled here, since Details for
// those checks is, by convention elsewhere in this codebase, one line per
// item (optionally preceded by fixed header lines - see DEV-015). A check
// with no item notion (no Fix, or a Fix with no Items) is returned
// unchanged; ACL-011 has no FixInfo.Items and instead consults
// IsItemIgnored directly while building its own findings.
func filterItemsByIgnore(s Suggestion, ignoreList *IgnoreList) Suggestion {
	if s.Fix == nil || len(s.Fix.Items) == 0 {
		return s
	}

	origCount := len(s.Fix.Items)
	keep := make([]bool, origCount)
	var keptItems []FixableItem
	suppressedCount := 0
	for i, item := range s.Fix.Items {
		if ignoreList.IsItemIgnored(s.ID, item.ID) {
			suppressedCount++
			continue
		}
		keep[i] = true
		keptItems = append(keptItems, item)
	}
	if suppressedCount == 0 {
		return s
	}

	newFix := *s.Fix
	newFix.Items = keptItems
	s.Fix = &newFix

	// If Details is a []string at least as long as the item list, assume its
	// last origCount entries line up 1:1 with the (pre-filter) Fix.Items -
	// true of every check in this codebase that sets both - and filter that
	// suffix the same way, leaving any leading header lines alone. A shorter
	// or differently-shaped Details is left untouched rather than guessed at.
	if details, ok := s.Details.([]string); ok && len(details) >= origCount {
		prefixLen := len(details) - origCount
		kept := append([]string{}, details[:prefixLen]...)
		for i := 0; i < origCount; i++ {
			if keep[i] {
				kept = append(kept, details[prefixLen+i])
			}
		}
		s.Details = kept
	}

	if len(keptItems) == 0 && !s.Pass {
		s.Severity = Informational
		note := fmt.Sprintf("All %d flagged item(s) were suppressed by the ignore file.", origCount)
		if details, ok := s.Details.([]string); ok {
			s.Details = append(details, note)
		} else {
			s.Details = note
		}
	}

	return s
}

// FilterIgnored returns the suggestions that are not in the ignore list, and
// the IDs of the ones it removed entirely (whole-check ignores). A finding
// with only some of its items ignored is kept, with those items removed -
// see filterItemsByIgnore.
func FilterIgnored(suggestions []Suggestion, ignoreList *IgnoreList) ([]Suggestion, []string) {
	if ignoreList == nil || ignoreList.Count() == 0 {
		return suggestions, nil
	}

	var result []Suggestion
	var ignored []string
	seen := make(map[string]bool)
	for _, s := range suggestions {
		if ignoreList.IsIgnored(s.ID) {
			if !seen[s.ID] {
				seen[s.ID] = true
				ignored = append(ignored, s.ID)
			}
			continue
		}
		result = append(result, filterItemsByIgnore(s, ignoreList))
	}
	return result, ignored
}
