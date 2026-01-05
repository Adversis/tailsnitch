package output

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"

	"github.com/Adversis/tailsnitch/pkg/types"
)

// SOC2JSON outputs the SOC2 report as JSON
func SOC2JSON(w io.Writer, report *types.SOC2Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SOC2CSV outputs the SOC2 report as CSV
func SOC2CSV(w io.Writer, report *types.SOC2Report) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{
		"resource_type",
		"resource_id",
		"resource_name",
		"check_id",
		"check_title",
		"cc_codes",
		"status",
		"details",
		"tested_at",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write each test as a row
	for _, test := range report.Tests {
		row := []string{
			test.ResourceType,
			test.ResourceID,
			test.ResourceName,
			test.CheckID,
			test.CheckTitle,
			strings.Join(test.CCCodes, ";"),
			string(test.Status),
			test.Details,
			test.TestedAt.Format("2006-01-02T15:04:05Z"),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
