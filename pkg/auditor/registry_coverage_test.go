package auditor

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Adversis/tailsnitch/pkg/types"
)

// checkIDLiteral matches the `ID: "XXX-001"` literals the auditors emit.
var checkIDLiteral = regexp.MustCompile(`\bID:\s+"([A-Z]+-[0-9]+)"`)

// TestEveryEmittedCheckIDIsRegistered keeps the auditors and the check registry
// from drifting apart. An unregistered ID cannot be selected with --checks and
// carries no title, category or SOC 2 mapping in reports.
func TestEveryEmittedCheckIDIsRegistered(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing sources: %v", err)
	}

	found := false
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}

		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("reading %s: %v", source, err)
		}

		for _, match := range checkIDLiteral.FindAllStringSubmatch(string(content), -1) {
			found = true
			id := match[1]
			if _, ok := types.DefaultRegistry.Resolve(id); !ok {
				t.Errorf("%s emits check ID %q, which is not in types.DefaultRegistry", source, id)
			}
		}
	}

	if !found {
		t.Fatal("no check ID literals found; the scan pattern is probably stale")
	}
}
