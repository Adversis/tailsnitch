package output

import (
	"encoding/json"
	"io"

	"github.com/Adversis/tailsnitch/pkg/types"
)

// JSON outputs the audit report as JSON
func JSON(w io.Writer, report *types.AuditReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
