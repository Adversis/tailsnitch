package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"

	"tailsnitch/pkg/types"
)

var (
	criticalColor = color.New(color.FgHiRed, color.Bold)
	highColor     = color.New(color.FgRed)
	mediumColor   = color.New(color.FgYellow)
	lowColor      = color.New(color.FgBlue)
	infoColor     = color.New(color.FgCyan)
	passColor     = color.New(color.FgGreen)
	headerColor   = color.New(color.FgWhite, color.Bold)
	dimColor      = color.New(color.Faint)
)

// PrintBanner prints the header banner immediately (before audit completes)
func PrintBanner(w io.Writer, tailnetName, version, buildID string) {
	accentColor := color.New(color.FgHiCyan, color.Bold)
	brandColor := color.New(color.FgHiMagenta)

	fmt.Fprintln(w)
	accentColor.Fprintln(w, `  ████████╗ █████╗ ██╗██╗     ███████╗███╗   ██╗██╗████████╗ ██████╗██╗  ██╗`)
	accentColor.Fprintln(w, `  ╚══██╔══╝██╔══██╗██║██║     ██╔════╝████╗  ██║██║╚══██╔══╝██╔════╝██║  ██║`)
	accentColor.Fprintln(w, `     ██║   ███████║██║██║     ███████╗██╔██╗ ██║██║   ██║   ██║     ███████║`)
	accentColor.Fprintln(w, `     ██║   ██╔══██║██║██║     ╚════██║██║╚██╗██║██║   ██║   ██║     ██╔══██║`)
	accentColor.Fprintln(w, `     ██║   ██║  ██║██║███████╗███████║██║ ╚████║██║   ██║   ╚██████╗██║  ██║`)
	accentColor.Fprintln(w, `     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝`)
	fmt.Fprintln(w)
	brandColor.Fprintf(w, "  Tailscale Security Auditor")
	dimColor.Fprintf(w, " by ")
	brandColor.Fprintf(w, "Adversis")
	fmt.Fprintln(w)

	// Version info
	versionStr := version
	if buildID != "unknown" && buildID != "" {
		versionStr = fmt.Sprintf("%s (%s)", version, buildID)
	}
	dimColor.Fprintf(w, "  Version: %s\n", versionStr)
	fmt.Fprintln(w)

	headerColor.Fprintln(w, "  ─────────────────────────────────────────────────────────────────────────")
	headerColor.Fprintf(w, "  Tailnet: %s\n", tailnetName)
	headerColor.Fprintln(w, "  ─────────────────────────────────────────────────────────────────────────")
	fmt.Fprintln(w)
	dimColor.Fprintln(w, "  Running security checks...")
	fmt.Fprintln(w)
}

// Text outputs the audit report as formatted text
func Text(w io.Writer, report *types.AuditReport, showPassing bool) error {
	// Print completion message (banner already printed)
	dimColor.Fprintf(w, "Completed at %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w)

	// Group suggestions by category
	byCategory := groupByCategory(report.Suggestions)

	// Define category order
	categoryOrder := []types.Category{
		types.AccessControl,
		types.Authentication,
		types.DeviceSecurity,
		types.NetworkExposure,
		types.SSHSecurity,
		types.LoggingAdmin,
		types.DNSConfiguration,
	}

	// Print suggestions by category
	for _, cat := range categoryOrder {
		suggestions, ok := byCategory[cat]
		if !ok || len(suggestions) == 0 {
			continue
		}

		printCategory(w, cat, suggestions, showPassing)
	}

	// Print summary
	printSummary(w, report)

	return nil
}

func printCategory(w io.Writer, cat types.Category, suggestions []types.Suggestion, showPassing bool) {
	// Sort suggestions by severity
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Severity.Order() < suggestions[j].Severity.Order()
	})

	headerColor.Fprintf(w, "━━━ %s ", strings.ToUpper(string(cat)))
	headerColor.Fprintln(w, strings.Repeat("━", 60-len(cat)))
	fmt.Fprintln(w)

	for _, s := range suggestions {
		if s.Pass && !showPassing {
			continue
		}
		printSuggestion(w, s)
	}
}

func printSuggestion(w io.Writer, s types.Suggestion) {
	// Severity label with color
	var severityLabel string
	switch s.Severity {
	case types.Critical:
		severityLabel = criticalColor.Sprintf("[CRITICAL]")
	case types.High:
		severityLabel = highColor.Sprintf("[HIGH]")
	case types.Medium:
		severityLabel = mediumColor.Sprintf("[MEDIUM]")
	case types.Low:
		severityLabel = lowColor.Sprintf("[LOW]")
	case types.Informational:
		severityLabel = infoColor.Sprintf("[INFO]")
	}

	if s.Pass {
		severityLabel = passColor.Sprintf("[PASS]")
	}

	// Print suggestion
	fmt.Fprintf(w, "%s %s: %s\n", severityLabel, s.ID, s.Title)

	// Description (indented)
	if s.Description != "" {
		for _, line := range wrapText(s.Description, 64) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	fmt.Fprintln(w)

	// Details if present
	if s.Details != nil {
		printDetails(w, s.Details)
	}

	// Remediation (if not passing)
	if !s.Pass && s.Remediation != "" {
		fmt.Fprintf(w, "  %s\n", headerColor.Sprint("Remediation:"))
		for _, line := range wrapText(s.Remediation, 64) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	// Admin URL (if fix info present)
	if s.Fix != nil && s.Fix.AdminURL != "" {
		dimColor.Fprintf(w, "  Admin: %s\n", s.Fix.AdminURL)
	}

	// Doc URL (if fix info present and different from source)
	if s.Fix != nil && s.Fix.DocURL != "" && s.Fix.DocURL != s.Source {
		dimColor.Fprintf(w, "  Docs: %s\n", s.Fix.DocURL)
	} else if s.Source != "" {
		dimColor.Fprintf(w, "  Docs: %s\n", s.Source)
	}

	fmt.Fprintln(w, strings.Repeat("─", 68))
	fmt.Fprintln(w)
}

func printDetails(w io.Writer, details interface{}) {
	switch d := details.(type) {
	case []string:
		if len(d) > 0 {
			fmt.Fprintf(w, "  %s\n", headerColor.Sprint("Affected items:"))
			for _, item := range d {
				fmt.Fprintf(w, "    • %s\n", item)
			}
			fmt.Fprintln(w)
		}
	case map[string]interface{}:
		if len(d) > 0 {
			fmt.Fprintf(w, "  %s\n", headerColor.Sprint("Details:"))
			for k, v := range d {
				fmt.Fprintf(w, "    %s: %v\n", k, v)
			}
			fmt.Fprintln(w)
		}
	case string:
		if d != "" {
			fmt.Fprintf(w, "  %s %s\n", headerColor.Sprint("Details:"), d)
			fmt.Fprintln(w)
		}
	}
}

func printSummary(w io.Writer, report *types.AuditReport) {
	headerColor.Fprintln(w, "SUMMARY")
	headerColor.Fprintln(w, strings.Repeat("━", 68))

	s := report.Summary

	// Print severity counts
	fmt.Fprint(w, "  ")
	if s.Critical > 0 {
		criticalColor.Fprintf(w, "Critical: %d  ", s.Critical)
	} else {
		fmt.Fprintf(w, "Critical: %d  ", s.Critical)
	}

	if s.High > 0 {
		highColor.Fprintf(w, "High: %d  ", s.High)
	} else {
		fmt.Fprintf(w, "High: %d  ", s.High)
	}

	if s.Medium > 0 {
		mediumColor.Fprintf(w, "Medium: %d  ", s.Medium)
	} else {
		fmt.Fprintf(w, "Medium: %d  ", s.Medium)
	}

	if s.Low > 0 {
		lowColor.Fprintf(w, "Low: %d  ", s.Low)
	} else {
		fmt.Fprintf(w, "Low: %d  ", s.Low)
	}

	if s.Info > 0 {
		infoColor.Fprintf(w, "Info: %d", s.Info)
	} else {
		fmt.Fprintf(w, "Info: %d", s.Info)
	}
	fmt.Fprintln(w)

	// Total
	totalSuggestions := s.Critical + s.High + s.Medium + s.Low + s.Info
	fmt.Fprintf(w, "  Total suggestions: %d", totalSuggestions)
	if s.Passed > 0 {
		passColor.Fprintf(w, "  (Passed: %d)", s.Passed)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}

func groupByCategory(suggestions []types.Suggestion) map[types.Category][]types.Suggestion {
	result := make(map[types.Category][]types.Suggestion)
	for _, s := range suggestions {
		result[s.Category] = append(result[s.Category], s)
	}
	return result
}

func wrapText(text string, width int) []string {
	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return lines
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)
	return lines
}
