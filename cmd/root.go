package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"tailsnitch/pkg/auditor"
	"tailsnitch/pkg/client"
	"tailsnitch/pkg/fixer"
	"tailsnitch/pkg/output"
	"tailsnitch/pkg/types"
)

// Version info - set via ldflags at build time
var (
	Version   = "dev"
	BuildID   = "unknown"
	BuildDate = "unknown"
)

var (
	jsonOutput    bool
	severity      string
	category      string
	tailnet       string
	verbose       bool
	fixMode       bool
	autoFix       bool
	dryRun        bool
	noAuditLog    bool
	checks        string
	listChecks    bool
	soc2Format    string
	tailscalePath string
	ignoreFile    string
	noIgnore      bool
)

var rootCmd = &cobra.Command{
	Use:   "tailsnitch",
	Short: "Audit Tailscale security configurations",
	Long: `A security audit tool for Tailscale configurations.

Checks your tailnet against Tailscale's best practices and recommendations.

Use --fix to enter interactive remediation mode for the items that are straightforward to fix via API.

Set TSKEY environment variable with Tailscale API key.`,
	Version: Version,
	RunE:    runAudit,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("tailsnitch %s (build: %s, date: %s)\nby Adversis.io\n", Version, BuildID, BuildDate))
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().StringVar(&severity, "severity", "", "Filter by minimum severity (critical, high, medium, low, info)")
	rootCmd.Flags().StringVar(&category, "category", "", "Filter by category")
	rootCmd.Flags().StringVar(&tailnet, "tailnet", "", "Tailnet to audit (default: from API key)")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Show passing checks too")
	rootCmd.Flags().BoolVar(&fixMode, "fix", false, "Enable fix mode with remediation actions")
	rootCmd.Flags().BoolVar(&autoFix, "auto", false, "Auto-select safe fixes (still requires confirmation)")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview fix actions without executing them")
	rootCmd.Flags().BoolVar(&noAuditLog, "no-audit-log", false, "Disable audit logging of fix actions")
	rootCmd.Flags().StringVar(&checks, "checks", "", "Run only specific checks (comma-separated IDs or slugs)")
	rootCmd.Flags().BoolVar(&listChecks, "list-checks", false, "List all available checks and exit")
	rootCmd.Flags().StringVar(&soc2Format, "soc2", "", "Export SOC2 evidence (json or csv)")
	rootCmd.Flags().StringVar(&tailscalePath, "tailscale-path", "", "Path to tailscale CLI binary (for Tailnet Lock checks)")
	rootCmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "Path to ignore file (default: .tailsnitch-ignore)")
	rootCmd.Flags().BoolVar(&noIgnore, "no-ignore", false, "Disable ignore file processing")
}

func Execute() error {
	return rootCmd.Execute()
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Handle --list-checks before anything else
	if listChecks {
		printAvailableChecks()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Parse and validate --checks flag
	var checkIDs []string
	if checks != "" {
		names := strings.Split(checks, ",")
		var err error
		checkIDs, err = types.DefaultRegistry.ResolveAll(names)
		if err != nil {
			return fmt.Errorf("invalid --checks: %w", err)
		}
	}

	// Validate flags
	if autoFix && !fixMode {
		return fmt.Errorf("--auto requires --fix flag")
	}

	if dryRun && !fixMode {
		return fmt.Errorf("--dry-run requires --fix flag")
	}

	if fixMode && jsonOutput {
		return fmt.Errorf("--fix and --json cannot be used together")
	}

	// Validate --soc2 flag
	if soc2Format != "" && soc2Format != "json" && soc2Format != "csv" {
		return fmt.Errorf("--soc2 must be 'json' or 'csv'")
	}

	if soc2Format != "" && (fixMode || jsonOutput) {
		return fmt.Errorf("--soc2 cannot be combined with --fix or --json")
	}

	// Create Tailscale client
	c, err := client.New(tailnet)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Set custom tailscale binary path if specified
	if tailscalePath != "" {
		if err := auditor.SetTailscaleBinaryPath(tailscalePath); err != nil {
			return fmt.Errorf("invalid --tailscale-path: %w", err)
		}
	}

	// Handle SOC2 export mode
	if soc2Format != "" {
		collector := auditor.NewSOC2Collector(c)
		soc2Report, err := collector.Collect(ctx)
		if err != nil {
			return fmt.Errorf("SOC2 collection failed: %w", err)
		}
		if soc2Format == "csv" {
			return output.SOC2CSV(os.Stdout, soc2Report)
		}
		return output.SOC2JSON(os.Stdout, soc2Report)
	}

	// Print banner immediately (unless JSON output)
	if !jsonOutput {
		output.PrintBanner(os.Stdout, c.Tailnet(), Version, BuildID)
	}

	// Run the audit
	a := auditor.New(c)
	report, err := a.Run(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	// Apply filters
	suggestions := report.Suggestions

	// Load and apply ignore file
	var ignoredPath string
	if !noIgnore {
		var ignoreList *types.IgnoreList
		if ignoreFile != "" {
			// User-specified ignore file
			var err error
			ignoreList, err = types.LoadIgnoreFile(ignoreFile)
			if err != nil {
				return fmt.Errorf("failed to load ignore file %s: %w", ignoreFile, err)
			}
			ignoredPath = ignoreFile
		} else {
			// Try default locations
			ignoreList, ignoredPath = types.LoadIgnoreFiles()
		}

		if ignoreList.Count() > 0 {
			suggestions = types.FilterIgnored(suggestions, ignoreList)
			if !jsonOutput {
				fmt.Printf("  Using ignore file: %s (%d rules)\n\n", ignoredPath, ignoreList.Count())
			}
		}
	}

	// Filter by severity
	if severity != "" {
		sev := parseSeverity(severity)
		if sev == "" {
			return fmt.Errorf("invalid severity: %s (use: critical, high, medium, low, info)", severity)
		}
		suggestions = types.FilterBySeverity(suggestions, sev)
	}

	// Filter by category
	if category != "" {
		cat := parseCategory(category)
		if cat == "" {
			return fmt.Errorf("invalid category: %s", category)
		}
		suggestions = types.FilterByCategory(suggestions, cat)
	}

	// Filter by specific checks
	if len(checkIDs) > 0 {
		suggestions = types.FilterByCheckIDs(suggestions, checkIDs)
	}

	// Filter out passing checks unless verbose
	if !verbose {
		suggestions = types.FilterFailed(suggestions)
	}

	report.Suggestions = suggestions
	report.CalculateSummary()

	// If fix mode, run the fixer
	if fixMode {
		// First show the summary
		if err := output.Text(os.Stdout, report, verbose); err != nil {
			return err
		}

		// Run the fixer with options
		opts := fixer.Options{
			AutoFix:  autoFix,
			DryRun:   dryRun,
			AuditLog: !noAuditLog,
		}
		f := fixer.NewWithOptions(c, report, opts)
		return f.Run(ctx)
	}

	// Output results
	if jsonOutput {
		return output.JSON(os.Stdout, report)
	}
	return output.Text(os.Stdout, report, verbose)
}

func parseSeverity(s string) types.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return types.Critical
	case "high":
		return types.High
	case "medium":
		return types.Medium
	case "low":
		return types.Low
	case "info", "informational":
		return types.Informational
	default:
		return ""
	}
}

func parseCategory(s string) types.Category {
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "access") || strings.Contains(lower, "acl"):
		return types.AccessControl
	case strings.Contains(lower, "auth") || strings.Contains(lower, "key"):
		return types.Authentication
	case strings.Contains(lower, "network") || strings.Contains(lower, "exposure"):
		return types.NetworkExposure
	case strings.Contains(lower, "ssh"):
		return types.SSHSecurity
	case strings.Contains(lower, "log") || strings.Contains(lower, "admin"):
		return types.LoggingAdmin
	case strings.Contains(lower, "device"):
		return types.DeviceSecurity
	default:
		return ""
	}
}

func printAvailableChecks() {
	checks := types.DefaultRegistry.All()

	fmt.Println("Available checks:")
	fmt.Println()

	currentCategory := types.Category("")
	for _, check := range checks {
		if check.Category != currentCategory {
			if currentCategory != "" {
				fmt.Println()
			}
			currentCategory = check.Category
			fmt.Printf("  %s:\n", currentCategory)
		}
		fmt.Printf("    %-10s  %-45s  %s\n", check.ID, check.Slug, check.Title)
	}

	fmt.Println()
	fmt.Println("Usage: --checks=ACL-001,stale-devices,tailnet-lock-not-enabled")
}
