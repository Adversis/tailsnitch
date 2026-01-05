package fixer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// AdminURLs maps suggestion prefixes to admin console URLs
var AdminURLs = map[string]string{
	"AUTH": "https://login.tailscale.com/admin/settings/keys",
	"DEV":  "https://login.tailscale.com/admin/machines",
	"ACL":  "https://login.tailscale.com/admin/acls",
	"LOG":  "https://login.tailscale.com/admin/logs",
	"SSH":  "https://login.tailscale.com/admin/acls",
	"NET":  "https://login.tailscale.com/admin/machines",
}

// Styles for output
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212"))

	linkStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Underline(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214"))
)

// Options configures the Fixer behavior
type Options struct {
	AutoFix  bool // Auto-select safe fixes
	DryRun   bool // Preview actions without executing
	AuditLog bool // Enable audit logging (default: true)
}

// Fixer orchestrates the fix process
type Fixer struct {
	client   *client.Client
	report   *types.AuditReport
	autoFix  bool
	dryRun   bool
	auditLog *AuditLog
	out      io.Writer
}

// New creates a new Fixer (legacy, use NewWithOptions for full control)
func New(c *client.Client, report *types.AuditReport, autoFix bool) *Fixer {
	return &Fixer{
		client:  c,
		report:  report,
		autoFix: autoFix,
		out:     os.Stdout,
	}
}

// NewWithOptions creates a new Fixer with full options
func NewWithOptions(c *client.Client, report *types.AuditReport, opts Options) *Fixer {
	f := &Fixer{
		client:  c,
		report:  report,
		autoFix: opts.AutoFix,
		dryRun:  opts.DryRun,
		out:     os.Stdout,
	}

	// Initialize audit log if enabled
	if opts.AuditLog {
		auditLog, err := NewAuditLog(report.Tailnet, opts.DryRun, "")
		if err != nil {
			// Log warning but continue without audit log
			fmt.Fprintf(os.Stderr, "Warning: could not create audit log: %v\n", err)
		} else {
			f.auditLog = auditLog
		}
	}

	return f
}

// Run executes the fix workflow
func (f *Fixer) Run(ctx context.Context) error {
	// Ensure audit log is closed at the end
	defer f.closeAuditLog()

	// Filter to only failed suggestions with fix info
	suggestions := types.FilterFailed(f.report.Suggestions)
	suggestions = types.FilterFixable(suggestions)

	if len(suggestions) == 0 {
		fmt.Fprintln(f.out, successStyle.Render("No fixable issues found!"))
		return nil
	}

	// Group suggestions by fix type
	apiFixable := types.FilterByFixType(suggestions, types.FixTypeAPI)
	manualFixes := types.FilterByFixType(suggestions, types.FixTypeManual)
	externalFixes := types.FilterByFixType(suggestions, types.FixTypeExternal)

	fmt.Fprintln(f.out)
	if f.dryRun {
		fmt.Fprintln(f.out, headerStyle.Render(" TAILSNITCH SECURITY FIXER (DRY RUN) "))
		fmt.Fprintln(f.out)
		fmt.Fprintln(f.out, warningStyle.Render("  DRY RUN MODE: No changes will be made. Actions will be previewed only."))
	} else {
		fmt.Fprintln(f.out, headerStyle.Render(" TAILSNITCH SECURITY FIXER "))
	}
	fmt.Fprintln(f.out)

	// Show external fixes first (just links)
	if len(externalFixes) > 0 {
		f.showExternalFixes(externalFixes)
	}

	// Show manual fixes (admin console links)
	if len(manualFixes) > 0 {
		f.showManualFixes(manualFixes)
	}

	// Interactive fix for API-fixable items
	if len(apiFixable) > 0 {
		return f.runInteractiveFix(ctx, apiFixable)
	}

	// No API-fixable items - let user know
	fmt.Fprintln(f.out, sectionStyle.Render("API-Fixable Issues:"))
	fmt.Fprintln(f.out)
	fmt.Fprintln(f.out, "  "+successStyle.Render("None")+" - all fixable issues require manual action via the links above.")
	fmt.Fprintln(f.out)

	return nil
}

func (f *Fixer) showExternalFixes(suggestions []types.Suggestion) {
	fmt.Fprintln(f.out, sectionStyle.Render("External Actions Required (configure in your IdP/external systems):"))
	fmt.Fprintln(f.out)

	for _, s := range suggestions {
		fmt.Fprintf(f.out, "  %s %s\n", warningStyle.Render("●"), s.Title)
		if s.Fix != nil {
			if s.Fix.Description != "" {
				fmt.Fprintf(f.out, "    %s\n", s.Fix.Description)
			}
			if s.Fix.DocURL != "" {
				fmt.Fprintf(f.out, "    Docs: %s\n", linkStyle.Render(s.Fix.DocURL))
			}
			if s.Fix.AdminURL != "" {
				fmt.Fprintf(f.out, "    Admin: %s\n", linkStyle.Render(s.Fix.AdminURL))
			}
		}
		fmt.Fprintln(f.out)
	}
}

// closeAuditLog closes the audit log and prints summary
func (f *Fixer) closeAuditLog() {
	if f.auditLog == nil {
		return
	}

	total, successful, failed := f.auditLog.Summary()
	logPath := f.auditLog.LogPath()

	if err := f.auditLog.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to close audit log: %v\n", err)
	}

	if total > 0 {
		fmt.Fprintln(f.out)
		fmt.Fprintln(f.out, sectionStyle.Render("Audit Log:"))
		fmt.Fprintf(f.out, "  Actions: %d total, %d successful, %d failed\n", total, successful, failed)
		fmt.Fprintf(f.out, "  Log file: %s\n", linkStyle.Render(logPath))
		fmt.Fprintln(f.out)
	}
}

// logAction logs an action to the audit log
func (f *Fixer) logAction(action, resourceType, resourceID, resourceName, details string, success bool, err error) {
	if f.auditLog != nil {
		f.auditLog.LogAction(action, resourceType, resourceID, resourceName, details, success, err)
	}
}

func (f *Fixer) showManualFixes(suggestions []types.Suggestion) {
	fmt.Fprintln(f.out, sectionStyle.Render("Manual Actions Required (configure in Tailscale admin console):"))
	fmt.Fprintln(f.out)

	for _, s := range suggestions {
		fmt.Fprintf(f.out, "  %s %s\n", warningStyle.Render("●"), s.Title)
		if s.Fix != nil {
			if s.Fix.Description != "" {
				fmt.Fprintf(f.out, "    %s\n", s.Fix.Description)
			}
			if s.Fix.AdminURL != "" {
				fmt.Fprintf(f.out, "    Admin Console: %s\n", linkStyle.Render(s.Fix.AdminURL))
			}
		}
		fmt.Fprintln(f.out)
	}
}

func (f *Fixer) runInteractiveFix(ctx context.Context, suggestions []types.Suggestion) error {
	fmt.Fprintln(f.out, sectionStyle.Render("API-Fixable Issues (can be fixed via this CLI):"))
	fmt.Fprintln(f.out)

	// Categorize suggestions by fix action type
	var keysToDelete []types.FixableItem       // AUTH-001, AUTH-002, AUTH-003
	var keysToReplace []types.FixableItem      // AUTH-004 (create ephemeral replacement)
	var devicesToDelete []types.FixableItem    // DEV-004
	var devicesToUntag []types.FixableItem     // DEV-002
	var devicesToAuthorize []types.FixableItem // DEV-005
	var aclSuggestions []types.Suggestion      // ACL-001, ACL-003, SSH-001, SSH-002

	for _, s := range suggestions {
		if s.Fix == nil || len(s.Fix.Items) == 0 {
			continue
		}

		// Auto-select if autoFix and safe
		for i := range s.Fix.Items {
			if f.autoFix && s.Fix.AutoFixSafe {
				s.Fix.Items[i].Selected = true
			}
		}

		switch s.ID {
		case "AUTH-001", "AUTH-002", "AUTH-003":
			keysToDelete = append(keysToDelete, s.Fix.Items...)
		case "AUTH-004":
			keysToReplace = append(keysToReplace, s.Fix.Items...)
		case "DEV-004":
			devicesToDelete = append(devicesToDelete, s.Fix.Items...)
		case "DEV-002":
			devicesToUntag = append(devicesToUntag, s.Fix.Items...)
		case "DEV-005":
			devicesToAuthorize = append(devicesToAuthorize, s.Fix.Items...)
		case "ACL-001", "ACL-003", "SSH-001", "SSH-002":
			aclSuggestions = append(aclSuggestions, s)
		}
	}

	// Run fixers in order of risk (lowest first)

	// 1. Delete stale devices (low risk)
	if len(devicesToDelete) > 0 {
		if err := f.runDeviceFixer(ctx, devicesToDelete); err != nil {
			return err
		}
	}

	// 2. Authorize pending devices (low risk, requires review)
	if len(devicesToAuthorize) > 0 {
		if err := f.runDeviceAuthorizeFixer(ctx, devicesToAuthorize); err != nil {
			return err
		}
	}

	// 3. Remove tags from user devices (medium risk)
	if len(devicesToUntag) > 0 {
		if err := f.runTagRemovalFixer(ctx, devicesToUntag); err != nil {
			return err
		}
	}

	// 4. Delete auth keys (medium risk)
	if len(keysToDelete) > 0 {
		if err := f.runKeyFixer(ctx, keysToDelete); err != nil {
			return err
		}
	}

	// 5. Replace non-ephemeral keys (medium risk)
	if len(keysToReplace) > 0 {
		if err := f.runKeyReplacementFixer(ctx, keysToReplace); err != nil {
			return err
		}
	}

	// 6. ACL modifications (high risk) - show info only for now
	if len(aclSuggestions) > 0 {
		f.showACLFixInfo(aclSuggestions)
	}

	return nil
}

func (f *Fixer) runKeyFixer(ctx context.Context, keys []types.FixableItem) error {
	if len(keys) == 0 {
		return nil
	}

	fmt.Fprintf(f.out, "\n  Found %d auth key(s) to review:\n\n", len(keys))

	// Run the key selection TUI
	selected, err := RunKeySelector(keys, f.autoFix)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(f.out, "  No keys selected for deletion.")
		return nil
	}

	// Confirm deletion (skip in dry-run mode)
	if f.dryRun {
		fmt.Fprintf(f.out, "\n  %s Would delete %d auth key(s):\n", warningStyle.Render("[DRY RUN]"), len(selected))
		for _, key := range selected {
			fmt.Fprintf(f.out, "    - %s (%s)\n", key.ID, key.Description)
			f.logAction("delete", "auth_key", key.ID, key.Name, key.Description, true, nil)
		}
		return nil
	}

	if !f.confirmDeletion(fmt.Sprintf("Delete %d auth key(s)?", len(selected))) {
		fmt.Fprintln(f.out, "  Cancelled.")
		return nil
	}

	// Delete the keys
	for _, key := range selected {
		fmt.Fprintf(f.out, "  Deleting key %s... ", key.ID)
		if err := f.client.DeleteKey(ctx, key.ID); err != nil {
			color.Red("FAILED: %v\n", err)
			f.logAction("delete", "auth_key", key.ID, key.Name, key.Description, false, err)
		} else {
			color.Green("OK\n")
			f.logAction("delete", "auth_key", key.ID, key.Name, key.Description, true, nil)
		}
	}

	return nil
}

func (f *Fixer) runDeviceFixer(ctx context.Context, devices []types.FixableItem) error {
	if len(devices) == 0 {
		return nil
	}

	fmt.Fprintf(f.out, "\n  Found %d device(s) to review:\n\n", len(devices))

	// Run the device selection TUI
	selected, err := RunDeviceSelector(devices, f.autoFix)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(f.out, "  No devices selected for deletion.")
		return nil
	}

	// Confirm deletion (skip in dry-run mode)
	if f.dryRun {
		fmt.Fprintf(f.out, "\n  %s Would delete %d device(s):\n", warningStyle.Render("[DRY RUN]"), len(selected))
		for _, dev := range selected {
			fmt.Fprintf(f.out, "    - %s (%s)\n", dev.Name, dev.Description)
			f.logAction("delete", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
		return nil
	}

	if !f.confirmDeletion(fmt.Sprintf("Delete %d device(s)?", len(selected))) {
		fmt.Fprintln(f.out, "  Cancelled.")
		return nil
	}

	// Delete the devices
	for _, dev := range selected {
		fmt.Fprintf(f.out, "  Deleting device %s... ", dev.Name)
		if err := f.client.DeleteDevice(ctx, dev.ID); err != nil {
			color.Red("FAILED: %v\n", err)
			f.logAction("delete", "device", dev.ID, dev.Name, dev.Description, false, err)
		} else {
			color.Green("OK\n")
			f.logAction("delete", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
	}

	return nil
}

func (f *Fixer) confirmDeletion(prompt string) bool {
	fmt.Fprintf(f.out, "\n  %s This cannot be undone. [y/N]: ", warningStyle.Render(prompt))

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))

	return response == "y" || response == "yes"
}

func (f *Fixer) confirmAction(prompt string) bool {
	fmt.Fprintf(f.out, "\n  %s [y/N]: ", warningStyle.Render(prompt))

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))

	return response == "y" || response == "yes"
}

func (f *Fixer) runDeviceAuthorizeFixer(ctx context.Context, devices []types.FixableItem) error {
	if len(devices) == 0 {
		return nil
	}

	fmt.Fprintf(f.out, "\n  Found %d pending device(s) to authorize:\n\n", len(devices))

	// Run the authorization selection TUI
	selected, err := RunAuthorizationSelector(devices, f.autoFix)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(f.out, "  No devices selected for authorization.")
		return nil
	}

	// Confirm authorization (skip in dry-run mode)
	if f.dryRun {
		fmt.Fprintf(f.out, "\n  %s Would authorize %d device(s):\n", warningStyle.Render("[DRY RUN]"), len(selected))
		for _, dev := range selected {
			fmt.Fprintf(f.out, "    - %s (%s)\n", dev.Name, dev.Description)
			f.logAction("authorize", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
		return nil
	}

	if !f.confirmAction(fmt.Sprintf("Authorize %d device(s)?", len(selected))) {
		fmt.Fprintln(f.out, "  Cancelled.")
		return nil
	}

	// Authorize the devices
	for _, dev := range selected {
		fmt.Fprintf(f.out, "  Authorizing device %s... ", dev.Name)
		if err := f.client.AuthorizeDevice(ctx, dev.ID); err != nil {
			color.Red("FAILED: %v\n", err)
			f.logAction("authorize", "device", dev.ID, dev.Name, dev.Description, false, err)
		} else {
			color.Green("OK\n")
			f.logAction("authorize", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
	}

	return nil
}

func (f *Fixer) runTagRemovalFixer(ctx context.Context, devices []types.FixableItem) error {
	if len(devices) == 0 {
		return nil
	}

	fmt.Fprintf(f.out, "\n  Found %d user device(s) with tags to remove:\n\n", len(devices))

	// Run the tag removal selection TUI
	selected, err := RunTagRemovalSelector(devices, f.autoFix)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(f.out, "  No devices selected for tag removal.")
		return nil
	}

	// Confirm tag removal (skip in dry-run mode)
	if f.dryRun {
		fmt.Fprintf(f.out, "\n  %s Would remove tags from %d device(s):\n", warningStyle.Render("[DRY RUN]"), len(selected))
		for _, dev := range selected {
			fmt.Fprintf(f.out, "    - %s (%s)\n", dev.Name, dev.Description)
			f.logAction("remove_tags", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
		return nil
	}

	if !f.confirmAction(fmt.Sprintf("Remove all tags from %d device(s)?", len(selected))) {
		fmt.Fprintln(f.out, "  Cancelled.")
		return nil
	}

	// Remove tags from the devices
	for _, dev := range selected {
		fmt.Fprintf(f.out, "  Removing tags from %s... ", dev.Name)
		if err := f.client.SetDeviceTags(ctx, dev.ID, []string{}); err != nil {
			color.Red("FAILED: %v\n", err)
			f.logAction("remove_tags", "device", dev.ID, dev.Name, dev.Description, false, err)
		} else {
			color.Green("OK\n")
			f.logAction("remove_tags", "device", dev.ID, dev.Name, dev.Description, true, nil)
		}
	}

	return nil
}

func (f *Fixer) runKeyReplacementFixer(ctx context.Context, keys []types.FixableItem) error {
	if len(keys) == 0 {
		return nil
	}

	fmt.Fprintf(f.out, "\n  Found %d non-ephemeral reusable key(s) that could be replaced with ephemeral keys:\n\n", len(keys))

	// Run the key selection TUI
	selected, err := RunKeySelector(keys, f.autoFix)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(f.out, "  No keys selected for replacement.")
		return nil
	}

	// Confirm replacement (skip in dry-run mode)
	if f.dryRun {
		fmt.Fprintf(f.out, "\n  %s Would replace %d key(s) with ephemeral versions:\n", warningStyle.Render("[DRY RUN]"), len(selected))
		for _, key := range selected {
			fmt.Fprintf(f.out, "    - %s (%s)\n", key.ID, key.Description)
			f.logAction("replace", "auth_key", key.ID, key.Name, key.Description, true, nil)
		}
		return nil
	}

	if !f.confirmAction(fmt.Sprintf("Replace %d key(s) with ephemeral versions (7-day expiry)?", len(selected))) {
		fmt.Fprintln(f.out, "  Cancelled.")
		return nil
	}

	// Replace the keys
	for _, key := range selected {
		fmt.Fprintf(f.out, "  Deleting old key %s... ", key.ID)
		if err := f.client.DeleteKey(ctx, key.ID); err != nil {
			color.Red("FAILED: %v\n", err)
			f.logAction("replace", "auth_key", key.ID, key.Name, key.Description, false, err)
			continue
		}
		color.Green("OK\n")
		f.logAction("replace", "auth_key", key.ID, key.Name, key.Description, true, nil)

		// Note: Creating a replacement key would require the original key's tags
		// For now, just inform the user they need to create a new one manually
		fmt.Fprintf(f.out, "    %s Create a new ephemeral key in admin console with the same tags.\n",
			warningStyle.Render("→"))
	}

	return nil
}

func (f *Fixer) showACLFixInfo(suggestions []types.Suggestion) {
	fmt.Fprintln(f.out, "\n"+sectionStyle.Render("ACL Modifications (manual review recommended):"))
	fmt.Fprintln(f.out)
	fmt.Fprintln(f.out, "  The following ACL changes are available but require careful review:")
	fmt.Fprintln(f.out)

	for _, s := range suggestions {
		fmt.Fprintf(f.out, "  %s %s\n", warningStyle.Render("●"), s.Title)
		if s.Fix != nil {
			fmt.Fprintf(f.out, "    %s\n", s.Fix.Description)
			if s.Fix.AdminURL != "" {
				fmt.Fprintf(f.out, "    Admin Console: %s\n", linkStyle.Render(s.Fix.AdminURL))
			}
		}
		fmt.Fprintln(f.out)
	}

	fmt.Fprintln(f.out, "  "+warningStyle.Render("Note:")+" ACL modifications can break connectivity. Use the admin console for safer editing.")
	fmt.Fprintln(f.out)
}
