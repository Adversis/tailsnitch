package types

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreList holds check IDs to ignore
type IgnoreList struct {
	ids map[string]bool
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
// Format: one check ID per line, # for comments, blank lines ignored.
func LoadIgnoreFile(path string) (*IgnoreList, error) {
	il := &IgnoreList{ids: make(map[string]bool)}

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

		// Add to ignore list (case-insensitive for convenience)
		il.ids[strings.ToUpper(line)] = true
	}

	return il, scanner.Err()
}

// LoadIgnoreFiles tries to load ignore files from default locations.
// Later files in the list override earlier ones.
func LoadIgnoreFiles() (*IgnoreList, string) {
	for _, path := range DefaultIgnoreFiles() {
		if _, err := os.Stat(path); err == nil {
			il, err := LoadIgnoreFile(path)
			if err == nil && len(il.ids) > 0 {
				return il, path
			}
		}
	}
	return &IgnoreList{ids: make(map[string]bool)}, ""
}

// IsIgnored returns true if the check ID should be ignored
func (il *IgnoreList) IsIgnored(id string) bool {
	return il.ids[strings.ToUpper(id)]
}

// Count returns the number of ignored check IDs
func (il *IgnoreList) Count() int {
	return len(il.ids)
}

// FilterIgnored returns suggestions that are not in the ignore list
func FilterIgnored(suggestions []Suggestion, ignoreList *IgnoreList) []Suggestion {
	if ignoreList == nil || ignoreList.Count() == 0 {
		return suggestions
	}

	var result []Suggestion
	for _, s := range suggestions {
		if !ignoreList.IsIgnored(s.ID) {
			result = append(result, s)
		}
	}
	return result
}
