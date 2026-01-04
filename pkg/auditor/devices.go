package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tailsnitch/pkg/client"
	"tailsnitch/pkg/types"
)

// httpClientWithTimeout is used for external API calls to prevent hanging
var httpClientWithTimeout = &http.Client{
	Timeout: 10 * time.Second,
}

// tailscaleBinaryPath caches the verified path to the tailscale binary
var tailscaleBinaryPath string

// tailscaleBinaryOverride is set via CLI flag --tailscale-path
var tailscaleBinaryOverride string

// SetTailscaleBinaryPath allows specifying a custom path to the tailscale binary.
// This is useful when tailscale is installed in a non-standard location.
// The path must be absolute and the file must exist.
func SetTailscaleBinaryPath(path string) error {
	if path == "" {
		return nil
	}

	// Ensure it's an absolute path
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("could not resolve path %q: %w", path, err)
		}
		path = absPath
	}

	// Verify the file exists and is not a directory
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("tailscale binary not found at %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory, not a file", path)
	}

	tailscaleBinaryOverride = path
	return nil
}

// findTailscaleBinary locates the tailscale binary using known safe paths.
// This prevents PATH hijacking attacks by checking specific directories.
// If a custom path was set via SetTailscaleBinaryPath, that is used instead.
func findTailscaleBinary() (string, error) {
	// Check user-specified override first
	if tailscaleBinaryOverride != "" {
		return tailscaleBinaryOverride, nil
	}

	// Check cached path
	if tailscaleBinaryPath != "" {
		return tailscaleBinaryPath, nil
	}

	// Known safe installation paths for tailscale binary
	knownPaths := []string{
		"/usr/bin/tailscale",
		"/usr/local/bin/tailscale",
		"/opt/homebrew/bin/tailscale",  // macOS Homebrew ARM
		"/usr/local/Cellar/tailscale",  // macOS Homebrew Intel (will be resolved)
		"/snap/bin/tailscale",          // Ubuntu Snap
		"/usr/sbin/tailscale",
	}

	for _, path := range knownPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			tailscaleBinaryPath = path
			return path, nil
		}
	}

	// Fallback: use exec.LookPath but verify it's not in current directory
	path, err := exec.LookPath("tailscale")
	if err != nil {
		return "", fmt.Errorf("tailscale binary not found in known paths or PATH (use --tailscale-path to specify)")
	}

	// Security check: ensure it's not a relative path (e.g., ./tailscale)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("could not resolve tailscale path: %w", err)
	}

	// Reject if it's in the current working directory (potential hijack)
	cwd, err := os.Getwd()
	if err == nil && filepath.Dir(absPath) == cwd {
		return "", fmt.Errorf("refusing to execute tailscale from current directory (use --tailscale-path for custom location)")
	}

	tailscaleBinaryPath = absPath
	return absPath, nil
}

// getLatestTailscaleVersion fetches the latest stable version from GitHub releases API.
// Per Tailscale docs, auto-updates take ~7 days to roll out, so we apply a grace period
// and only consider releases older than 7 days as the "expected" version.
// Returns the full version string (e.g., "v1.76.6") and parsed major/minor for comparison.
func getLatestTailscaleVersion(ctx context.Context) (versionStr string, major, minor int, ok bool) {
	// Fetch recent releases (not just latest) so we can apply grace period
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/tailscale/tailscale/releases?per_page=10", nil)
	if err != nil {
		return "", 0, 0, false
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := httpClientWithTimeout.Do(req)
	if err != nil {
		return "", 0, 0, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, 0, false
	}

	var releases []struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", 0, 0, false
	}

	versionRegex := regexp.MustCompile(`v?(\d+)\.(\d+)`)
	gracePeriod := 7 * 24 * time.Hour

	// Find the first non-prerelease that's older than the grace period
	for _, release := range releases {
		if release.Prerelease {
			continue
		}

		publishedAt, err := time.Parse(time.RFC3339, release.PublishedAt)
		if err != nil {
			continue
		}

		// Check if release is older than grace period
		if time.Since(publishedAt) >= gracePeriod {
			major, minor, ok = parseVersion(release.TagName, versionRegex)
			if ok {
				return release.TagName, major, minor, true
			}
		}
	}

	return "", 0, 0, false
}

// parseVersion extracts major and minor version numbers from a version string
func parseVersion(versionStr string, versionRegex *regexp.Regexp) (major, minor int, ok bool) {
	matches := versionRegex.FindStringSubmatch(versionStr)
	if len(matches) < 3 {
		return 0, 0, false
	}
	var err error
	major, err = strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// DeviceAuditor checks for device security issues
type DeviceAuditor struct {
	client *client.Client
}

// NewDeviceAuditor creates a new device auditor
func NewDeviceAuditor(c *client.Client) *DeviceAuditor {
	return &DeviceAuditor{client: c}
}

// Audit performs device-related security checks
func (d *DeviceAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	devices, err := d.client.GetDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	// Fetch DNS config for checks that need it (DEV-007)
	dnsConfig, _ := d.client.GetDNSConfig(ctx) // Ignore error, check will handle nil

	// DEV-001: Tagged devices with key expiry disabled
	findings = append(findings, d.checkTaggedDevicesKeyExpiry(devices))

	// DEV-002: User devices with tags
	findings = append(findings, d.checkUserDevicesWithTags(devices))

	// DEV-003: Outdated client versions
	findings = append(findings, d.checkOutdatedClients(ctx, devices))

	// DEV-004: Stale devices not seen recently
	findings = append(findings, d.checkStaleDevices(devices))

	// DEV-005: Unauthorized devices pending approval
	findings = append(findings, d.checkUnauthorizedDevices(devices))

	// DEV-006: External devices in tailnet
	findings = append(findings, d.checkExternalDevices(devices))

	// DEV-007: Sensitive information in machine names (CT log exposure)
	// Only relevant when MagicDNS is enabled (names appear in HTTPS certs)
	findings = append(findings, d.checkSensitiveMachineNames(devices, dnsConfig))

	// DEV-008: Long key expiry (default 180 days)
	findings = append(findings, d.checkLongKeyExpiry(devices))

	// DEV-009: Device approval configuration
	findings = append(findings, d.checkDeviceApproval(devices))

	// DEV-010: Tailnet Lock status
	findings = append(findings, d.checkTailnetLock(ctx))

	// DEV-011: Unique users in tailnet
	findings = append(findings, d.checkUniqueUsers(devices))

	// DEV-012: Nodes awaiting Tailnet Lock signature
	findings = append(findings, d.checkTailnetLockPending(ctx))

	return findings, nil
}

func (d *DeviceAuditor) checkTaggedDevicesKeyExpiry(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-001",
		Title:       "Tagged devices with key expiry disabled",
		Severity:    types.High,
		Category:    types.DeviceSecurity,
		Description: "Tagged devices have key expiry disabled by default, creating indefinite access if credentials are compromised.",
		Remediation: "Review key expiry settings for tagged devices in admin console. Enable expiry for sensitive infrastructure.",
		Source:      "https://tailscale.com/kb/1068/tags",
		Pass:        true,
	}

	var problematicDevices []string
	for _, dev := range devices {
		if len(dev.Tags) > 0 && dev.KeyExpiryDisabled {
			problematicDevices = append(problematicDevices, fmt.Sprintf("%s (%s) - tags: %v", dev.Name, dev.Hostname, dev.Tags))
		}
	}

	if len(problematicDevices) > 0 {
		finding.Pass = false
		finding.Details = problematicDevices
		finding.Description = fmt.Sprintf("Found %d tagged device(s) with key expiry disabled.", len(problematicDevices))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable key expiry for tagged devices",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/kb/1068/tags",
		}
	}

	return finding
}

func (d *DeviceAuditor) checkUserDevicesWithTags(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-002",
		Title:       "User devices tagged (should be servers only)",
		Severity:    types.High,
		Category:    types.DeviceSecurity,
		Description: "Tags are intended for service accounts and servers, not user devices. Tagged user devices remain on network after user removal.",
		Remediation: "Remove tags from end-user devices. Use tags only for servers and infrastructure. Check for orphaned devices from removed users.",
		Source:      "https://tailscale.com/kb/1068/tags",
		Pass:        true,
	}

	// Heuristics to identify user devices
	userDevicePatterns := []string{
		"macbook", "imac", "mac-", "mbp", "mba",
		"iphone", "ipad",
		"pixel", "samsung", "android",
		"laptop", "desktop",
		"windows", "win-",
	}

	userOSTypes := []string{
		"iOS", "macOS", "android", "windows",
	}

	var userDevicesWithTags []string
	for _, dev := range devices {
		if len(dev.Tags) == 0 {
			continue
		}

		isUserDevice := false

		// Check hostname patterns
		hostnameLower := strings.ToLower(dev.Hostname)
		for _, pattern := range userDevicePatterns {
			if strings.Contains(hostnameLower, pattern) {
				isUserDevice = true
				break
			}
		}

		// Check OS type
		if !isUserDevice {
			for _, osType := range userOSTypes {
				if strings.EqualFold(dev.OS, osType) {
					isUserDevice = true
					break
				}
			}
		}

		if isUserDevice {
			userDevicesWithTags = append(userDevicesWithTags, fmt.Sprintf("%s (%s, %s) - tags: %v", dev.Name, dev.Hostname, dev.OS, dev.Tags))
		}
	}

	if len(userDevicesWithTags) > 0 {
		finding.Pass = false
		finding.Details = userDevicesWithTags
		finding.Description = fmt.Sprintf("Found %d likely user device(s) with tags applied.", len(userDevicesWithTags))

		// Build fixable items for tag removal
		var fixableItems []types.FixableItem
		for _, dev := range devices {
			if len(dev.Tags) == 0 {
				continue
			}

			isUserDevice := false
			hostnameLower := strings.ToLower(dev.Hostname)
			for _, pattern := range userDevicePatterns {
				if strings.Contains(hostnameLower, pattern) {
					isUserDevice = true
					break
				}
			}
			if !isUserDevice {
				for _, osType := range userOSTypes {
					if strings.EqualFold(dev.OS, osType) {
						isUserDevice = true
						break
					}
				}
			}

			if isUserDevice {
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          dev.DeviceID,
					Name:        dev.Name,
					Description: fmt.Sprintf("%s (%s) - tags: %v", dev.Hostname, dev.OS, dev.Tags),
				})
			}
		}

		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Remove tags from user devices",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			Items:       fixableItems,
			AutoFixSafe: false, // User should review which devices to untag
		}
	}

	return finding
}

func (d *DeviceAuditor) checkOutdatedClients(ctx context.Context, devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-003",
		Title:       "Outdated Tailscale clients",
		Severity:    types.Medium,
		Category:    types.DeviceSecurity,
		Description: "Outdated clients may have security vulnerabilities. Customers are responsible for client updates.",
		Remediation: "Enable auto-updates in Device management. Use MDM to enforce updates. Monitor client versions.",
		Source:      "https://tailscale.com/kb/1212/shared-responsibility",
		Pass:        true,
	}

	versionRegex := regexp.MustCompile(`(\d+)\.(\d+)`)

	// Try to get the stable version from GitHub releases (with 7-day grace period for auto-update rollout)
	latestVersionStr, latestMajor, latestMinor, gotLatest := getLatestTailscaleVersion(ctx)
	if !gotLatest {
		// Fallback: find the latest version among all devices
		for _, dev := range devices {
			if dev.ClientVersion == "" {
				continue
			}
			if major, minor, ok := parseVersion(dev.ClientVersion, versionRegex); ok {
				if major > latestMajor || (major == latestMajor && minor > latestMinor) {
					latestMajor = major
					latestMinor = minor
					latestVersionStr = dev.ClientVersion
				}
			}
		}
		if latestVersionStr != "" {
			latestVersionStr = latestVersionStr + " (from tailnet)"
		}
	}

	// Check for devices significantly older than the expected version
	var outdatedDevices []string
	for _, dev := range devices {
		if dev.ClientVersion == "" {
			continue
		}

		major, minor, ok := parseVersion(dev.ClientVersion, versionRegex)
		if !ok {
			continue
		}

		// Skip devices that are at or ahead of the expected version
		if major > latestMajor || (major == latestMajor && minor >= latestMinor) {
			continue
		}

		// Flag if more than 2 minor versions behind the expected version
		if major < latestMajor || (major == latestMajor && latestMinor-minor > 2) {
			versionsBehind := latestMinor - minor
			if major < latestMajor {
				versionsBehind = latestMinor + (latestMajor-major)*100 - minor // rough estimate for major version diff
			}
			outdatedDevices = append(outdatedDevices, fmt.Sprintf("%s (%s): %s (%d minor versions behind)", dev.Name, dev.Hostname, dev.ClientVersion, versionsBehind))
		}
	}

	// Also check for clients older than v1.34 (required for network flow logs)
	var oldClientsNoFlowLogs []string
	for _, dev := range devices {
		if dev.ClientVersion == "" {
			continue
		}
		if major, minor, ok := parseVersion(dev.ClientVersion, versionRegex); ok {
			if major == 1 && minor < 34 {
				oldClientsNoFlowLogs = append(oldClientsNoFlowLogs, fmt.Sprintf("%s: %s", dev.Name, dev.ClientVersion))
			}
		}
	}

	if len(outdatedDevices) > 0 {
		finding.Pass = false
		// Note: expected version accounts for 7-day auto-update rollout period
		finding.Details = append([]string{fmt.Sprintf("Expected: %s (after 7-day auto-update rollout)", latestVersionStr)}, outdatedDevices...)
		finding.Description = fmt.Sprintf("Found %d device(s) with outdated Tailscale clients.", len(outdatedDevices))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable auto-updates in Device management settings",
			AdminURL:    "https://login.tailscale.com/admin/settings/device-management",
			DocURL:      "https://tailscale.com/kb/1212/shared-responsibility",
		}
	}

	if len(oldClientsNoFlowLogs) > 0 {
		if finding.Pass {
			finding.Pass = false
			finding.Severity = types.Medium
		}
		if finding.Details == nil {
			finding.Details = oldClientsNoFlowLogs
		}
		finding.Description += fmt.Sprintf(" Additionally, %d device(s) are running clients older than v1.34 and cannot generate network flow logs.", len(oldClientsNoFlowLogs))
	}

	return finding
}

func (d *DeviceAuditor) checkStaleDevices(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-004",
		Title:       "Stale devices not seen recently",
		Severity:    types.Medium,
		Category:    types.DeviceSecurity,
		Description: "Devices not seen in over 30 days may be unused and should be reviewed for removal.",
		Remediation: "Review and remove unused devices. Implement device lifecycle policies.",
		Source:      "https://tailscale.com/kb/1068/tags",
		Pass:        true,
	}

	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var staleDevices []string

	for _, dev := range devices {
		if dev.LastSeen == "" {
			continue
		}

		lastSeen, err := time.Parse(time.RFC3339, dev.LastSeen)
		if err != nil {
			continue
		}

		if lastSeen.Before(thirtyDaysAgo) {
			daysSince := int(time.Since(lastSeen).Hours() / 24)
			staleDevices = append(staleDevices, fmt.Sprintf("%s (%s): last seen %d days ago", dev.Name, dev.Hostname, daysSince))
		}
	}

	if len(staleDevices) > 0 {
		finding.Pass = false
		finding.Details = staleDevices
		finding.Description = fmt.Sprintf("Found %d device(s) not seen in over 30 days.", len(staleDevices))

		// Build fixable items
		var fixableItems []types.FixableItem
		for _, dev := range devices {
			if dev.LastSeen == "" {
				continue
			}
			lastSeen, err := time.Parse(time.RFC3339, dev.LastSeen)
			if err != nil {
				continue
			}
			if lastSeen.Before(thirtyDaysAgo) {
				daysSince := int(time.Since(lastSeen).Hours() / 24)
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          dev.DeviceID,
					Name:        dev.Name,
					Description: fmt.Sprintf("%s - last seen %d days ago", dev.Hostname, daysSince),
				})
			}
		}
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Remove stale devices that are no longer in use",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			Items:       fixableItems,
			AutoFixSafe: true, // Safe to remove devices not seen in 30+ days
		}
	}

	return finding
}

func (d *DeviceAuditor) checkUnauthorizedDevices(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-005",
		Title:       "Unauthorized devices pending approval",
		Severity:    types.Medium,
		Category:    types.DeviceSecurity,
		Description: "Devices pending authorization cannot access the tailnet but may indicate attempted unauthorized access.",
		Remediation: "Review and authorize legitimate devices. Investigate unknown device attempts.",
		Source:      "https://tailscale.com/kb/1099/device-authorization",
		Pass:        true,
	}

	var unauthorizedDevices []string
	for _, dev := range devices {
		if !dev.Authorized {
			unauthorizedDevices = append(unauthorizedDevices, fmt.Sprintf("%s (%s) - user: %s", dev.Name, dev.Hostname, dev.User))
		}
	}

	if len(unauthorizedDevices) > 0 {
		finding.Pass = false
		finding.Details = unauthorizedDevices
		finding.Description = fmt.Sprintf("Found %d unauthorized device(s) pending approval.", len(unauthorizedDevices))

		// Build fixable items for device authorization
		var fixableItems []types.FixableItem
		for _, dev := range devices {
			if !dev.Authorized {
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          dev.DeviceID,
					Name:        dev.Name,
					Description: fmt.Sprintf("%s - user: %s", dev.Hostname, dev.User),
				})
			}
		}

		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Authorize pending devices via API",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/kb/1099/device-authorization",
			Items:       fixableItems,
			AutoFixSafe: false, // Requires review before authorizing
		}
	}

	return finding
}

func (d *DeviceAuditor) checkExternalDevices(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-006",
		Title:       "External devices in tailnet",
		Severity:    types.Informational,
		Category:    types.DeviceSecurity,
		Description: "External devices are shared from other tailnets. Ensure these are expected.",
		Remediation: "Review external devices and verify they should have access. Remove any unexpected shared devices.",
		Source:      "https://tailscale.com/kb/1084/sharing",
		Pass:        true,
	}

	var externalDevices []string
	for _, dev := range devices {
		if dev.IsExternal {
			externalDevices = append(externalDevices, fmt.Sprintf("%s (%s) - user: %s", dev.Name, dev.Hostname, dev.User))
		}
	}

	if len(externalDevices) > 0 {
		finding.Pass = false
		finding.Details = externalDevices
		finding.Description = fmt.Sprintf("Found %d external (shared) device(s) in tailnet.", len(externalDevices))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review and manage external shared devices",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/kb/1084/sharing",
		}
	}

	return finding
}

func (d *DeviceAuditor) checkSensitiveMachineNames(devices []*client.Device, dnsConfig *client.DNSConfig) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-007",
		Title:       "Potentially sensitive machine names",
		Severity:    types.Medium,
		Category:    types.DeviceSecurity,
		Description: "Machine names are published to Certificate Transparency logs when HTTPS is enabled. Sensitive information in names is publicly exposed.",
		Remediation: "Rename devices to remove sensitive information before enabling HTTPS. Use generic names. Consider randomized tailnet DNS name.",
		Source:      "https://tailscale.com/kb/1153/enabling-https",
		Pass:        true,
	}

	// This check only applies when MagicDNS is enabled, since that's when
	// machine names appear in HTTPS certificates and CT logs
	if dnsConfig == nil || !dnsConfig.MagicDNS {
		finding.Pass = true
		finding.Description = "MagicDNS is disabled. Machine names are not exposed in HTTPS certificates or CT logs."
		finding.Details = "This check is skipped because MagicDNS is not enabled."
		return finding
	}

	// Patterns that might indicate sensitive info in machine names
	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key|cred)`),
		regexp.MustCompile(`(?i)(prod|production|staging|dev)[-_]?(db|database|mysql|postgres|mongo|redis)`),
		regexp.MustCompile(`(?i)(internal|private|confidential)`),
		regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), // IP addresses
		regexp.MustCompile(`(?i)(admin|root|superuser)`),
		regexp.MustCompile(`(?i)(api[-_]?key|access[-_]?key|auth[-_]?key)`),
		regexp.MustCompile(`(?i)(ssn|social[-_]?security|credit[-_]?card)`),
	}

	var sensitiveNames []string
	for _, dev := range devices {
		for _, pattern := range sensitivePatterns {
			if pattern.MatchString(dev.Name) || pattern.MatchString(dev.Hostname) {
				sensitiveNames = append(sensitiveNames, fmt.Sprintf("%s (%s)", dev.Name, dev.Hostname))
				break
			}
		}
	}

	if len(sensitiveNames) > 0 {
		finding.Pass = false
		finding.Details = sensitiveNames
		finding.Description = fmt.Sprintf("Found %d device(s) with potentially sensitive information in names. These may be exposed in CT logs when HTTPS certificates are requested.", len(sensitiveNames))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Rename devices to remove sensitive information",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/kb/1153/enabling-https",
		}
	}

	return finding
}

// isDevDevice returns true if the device appears to be an end-user device (laptop, phone, etc.)
// rather than a server or infrastructure device.
//
// Note: Tagged devices return false because tags are primarily used for servers/infrastructure.
// This affects DEV-008 key expiry thresholds - tagged devices use the 90-day server threshold
// while untagged user devices use the stricter 180-day threshold.
func isDevDevice(dev *client.Device) bool {
	// Tagged devices are typically servers/infrastructure, not user devices
	if len(dev.Tags) > 0 {
		return false
	}

	// Check OS type - mobile and desktop OSes are dev devices
	devOSTypes := []string{"iOS", "macOS", "android", "windows"}
	for _, osType := range devOSTypes {
		if strings.EqualFold(dev.OS, osType) {
			return true
		}
	}

	// Check hostname patterns that suggest user devices
	devPatterns := []string{
		"macbook", "imac", "mac-", "mbp", "mba",
		"iphone", "ipad",
		"pixel", "samsung", "android",
		"laptop", "desktop", "workstation",
		"windows", "win-", "win10", "win11",
	}
	hostnameLower := strings.ToLower(dev.Hostname)
	for _, pattern := range devPatterns {
		if strings.Contains(hostnameLower, pattern) {
			return true
		}
	}

	return false
}

func (d *DeviceAuditor) checkLongKeyExpiry(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-008",
		Title:       "Devices with long key expiry periods",
		Severity:    types.Low,
		Category:    types.DeviceSecurity,
		Description: "Default key expiry is 180 days. Dev devices (laptops, phones) should use shorter; servers can use up to 180 days.",
		Remediation: "Customize node key expiry: shorter for dev devices, up to 180 days for servers. Shorter periods require more frequent re-authentication.",
		Source:      "https://tailscale.com/kb/1196/security-hardening",
		Pass:        true,
	}

	const (
		devDeviceMaxDays = 90  // Dev devices should expire within
		serverMaxDays    = 180 // Servers can have up to
	)

	var devDeviceLongExpiry []string
	var serverLongExpiry []string
	now := time.Now()

	for _, dev := range devices {
		if dev.KeyExpiryDisabled {
			continue // Already flagged in DEV-001
		}

		if dev.Expires == "" {
			continue
		}

		expires, err := time.Parse(time.RFC3339, dev.Expires)
		if err != nil {
			continue
		}

		daysUntilExpiry := int(expires.Sub(now).Hours() / 24)

		if isDevDevice(dev) {
			if daysUntilExpiry > devDeviceMaxDays {
				devDeviceLongExpiry = append(devDeviceLongExpiry,
					fmt.Sprintf("%s (%s, %s): expires in %d days (recommended: ≤%d)",
						dev.Name, dev.Hostname, dev.OS, daysUntilExpiry, devDeviceMaxDays))
			}
		} else {
			if daysUntilExpiry > serverMaxDays {
				serverLongExpiry = append(serverLongExpiry,
					fmt.Sprintf("%s (%s): expires in %d days (recommended: ≤%d)",
						dev.Name, dev.Hostname, daysUntilExpiry, serverMaxDays))
			}
		}
	}

	var allLongExpiry []string
	if len(devDeviceLongExpiry) > 0 {
		allLongExpiry = append(allLongExpiry, "Dev devices (should be longer :")
		allLongExpiry = append(allLongExpiry, devDeviceLongExpiry...)
	}
	if len(serverLongExpiry) > 0 {
		if len(allLongExpiry) > 0 {
			allLongExpiry = append(allLongExpiry, "")
		}
		allLongExpiry = append(allLongExpiry, "Servers (should be longer :")
		allLongExpiry = append(allLongExpiry, serverLongExpiry...)
	}

	if len(allLongExpiry) > 0 {
		finding.Pass = false
		finding.Details = allLongExpiry

		// Dev devices with long expiry are higher severity
		if len(devDeviceLongExpiry) > 0 {
			finding.Severity = types.Medium
			finding.Description = fmt.Sprintf("Found %d dev device(s) with key expiry >%d days and %d server(s) with expiry >%d days.",
				len(devDeviceLongExpiry), devDeviceMaxDays, len(serverLongExpiry), serverMaxDays)
		} else {
			finding.Description = fmt.Sprintf("Found %d server(s) with key expiry >%d days.",
				len(serverLongExpiry), serverMaxDays)
		}

		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Adjust key expiry periods: shorter for dev devices, longer for servers",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/kb/1196/security-hardening",
		}
	}

	return finding
}

func (d *DeviceAuditor) checkDeviceApproval(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-009",
		Title:       "Device approval configuration",
		Severity:    types.Medium,
		Category:    types.DeviceSecurity,
		Description: "Device approval requires admin review before new devices can access the tailnet. This is a key security control.",
		Remediation: "Enable device approval in Device management console. Review and approve only trusted, workplace-managed devices.",
		Source:      "https://tailscale.com/kb/1099/device-authorization",
		Pass:        true,
	}

	// Count unauthorized vs authorized devices to infer if device approval is enabled
	authorized := 0
	unauthorized := 0
	for _, dev := range devices {
		if dev.Authorized {
			authorized++
		} else {
			unauthorized++
		}
	}

	// If all devices are authorized and there are many devices, device approval might not be enabled
	// This is a heuristic - we can't directly check the setting via API
	if unauthorized == 0 && authorized > 5 {
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Description = fmt.Sprintf("All %d devices are authorized. Verify device approval is enabled in admin console - if not, new devices join automatically without review.", authorized)
		finding.Details = "MANUAL CHECK REQUIRED: Verify device approval is enabled in Device management settings."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable device approval in Device management settings",
			AdminURL:    "https://login.tailscale.com/admin/settings/device-management",
			DocURL:      "https://tailscale.com/kb/1099/device-authorization",
		}
	} else if unauthorized > 0 {
		// Device approval is working - there are pending devices
		finding.Pass = true
		finding.Description = fmt.Sprintf("Device approval appears active: %d authorized, %d pending approval.", authorized, unauthorized)
	}

	return finding
}

func (d *DeviceAuditor) checkTailnetLock(ctx context.Context) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-010",
		Title:       "Tailnet Lock not enabled",
		Severity:    types.High,
		Category:    types.DeviceSecurity,
		Description: "Tailnet Lock (network lock) prevents attackers from adding devices even with stolen auth keys. Requires cryptographic signing from trusted nodes.",
		Remediation: "Enable Tailnet Lock to require device signing. Run: tailscale lock init",
		Source:      "https://tailscale.com/kb/1226/tailnet-lock",
		Pass:        true,
	}

	// Find tailscale binary using secure path resolution
	tsBinary, err := findTailscaleBinary()
	if err != nil {
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Description = "Cannot check Tailnet Lock status: " + err.Error()
		finding.Details = []string{
			"The tailscale CLI binary could not be located securely.",
			"",
			"NOTE: This check runs on the LOCAL machine and may not reflect",
			"the status of the tailnet being audited via --tailnet flag.",
			"",
			"To check Tailnet Lock status manually:",
			"  1. Install Tailscale CLI: https://tailscale.com/download",
			"  2. Run: tailscale lock status",
			"",
			"See: https://tailscale.com/kb/1226/tailnet-lock",
		}
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeExternal,
			Description: "Install tailscale CLI and run 'tailscale lock init'",
			DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
		}
		return finding
	}

	// Try to run tailscale lock status
	cmd := exec.CommandContext(ctx, tsBinary, "lock", "status")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if it's a "command not found" error
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			finding.Pass = false
			finding.Severity = types.Informational
			finding.Description = "Cannot check Tailnet Lock status: tailscale CLI not found."
			finding.Details = []string{
				"The tailscale CLI binary was not found in PATH.",
				"",
				"To check Tailnet Lock status manually:",
				"  1. Install Tailscale CLI: https://tailscale.com/download",
				"  2. Run: tailscale lock status",
				"",
				"To enable Tailnet Lock:",
				"  1. Ensure tailscale CLI is installed on a trusted node",
				"  2. Run: tailscale lock init",
				"  3. Add signing keys from other trusted nodes",
				"",
				"See: https://tailscale.com/kb/1226/tailnet-lock",
			}
			finding.Fix = &types.FixInfo{
				Type:        types.FixTypeExternal,
				Description: "Install tailscale CLI and run 'tailscale lock init'",
				DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
			}
			return finding
		}

		// Check for exit status indicating lock is not enabled
		outputStr := string(output)

		// "tailscale lock status" returns exit code 1 with specific message when not enabled
		if strings.Contains(outputStr, "disabled") ||
			strings.Contains(outputStr, "not enabled") ||
			strings.Contains(outputStr, "Tailnet lock is NOT enabled") {
			finding.Pass = false
			finding.Description = "Tailnet Lock is not enabled. Attackers with stolen auth keys can add unauthorized devices."
			finding.Details = []string{
				"Tailnet Lock prevents unauthorized device additions even if auth keys are compromised.",
				"",
				"Current status: DISABLED",
				"",
				"To enable Tailnet Lock:",
				"  1. On a trusted node, run: tailscale lock init",
				"  2. This generates a signing key for that node",
				"  3. Add signing keys from additional trusted nodes: tailscale lock add <nodekey>",
				"  4. Once enabled, new devices require signatures from existing trusted nodes",
				"",
				"WARNING: Enabling Tailnet Lock is a significant security change.",
				"Ensure you understand the key rotation and recovery procedures.",
			}
			finding.Fix = &types.FixInfo{
				Type:        types.FixTypeExternal,
				Description: "Enable Tailnet Lock by running 'tailscale lock init' on a trusted node",
				DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
			}
			return finding
		}

		// Other errors - connection issues, permission denied, etc.
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Description = "Cannot determine Tailnet Lock status due to an error."
		finding.Details = []string{
			fmt.Sprintf("Error running 'tailscale lock status': %v", err),
			fmt.Sprintf("Output: %s", strings.TrimSpace(outputStr)),
			"",
			"Possible causes:",
			"  - Tailscale daemon not running (start with: sudo tailscaled)",
			"  - Insufficient permissions (try running as root/admin)",
			"  - Network connectivity issues",
			"",
			"To check manually, run: tailscale lock status",
		}
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeExternal,
			Description: "Verify tailscale daemon is running and check 'tailscale lock status'",
			DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
		}
		return finding
	}

	// Command succeeded - parse output
	outputStr := string(output)

	// Check if lock is enabled
	if strings.Contains(outputStr, "enabled") ||
		strings.Contains(outputStr, "Tailnet lock is enabled") {
		finding.Pass = true
		finding.Description = "Tailnet Lock is enabled (local check). Devices require cryptographic signing from trusted nodes."

		// Extract some useful info if available
		var details []string
		details = append(details, "Status: ENABLED (checked via local tailscale CLI)")
		details = append(details, "")
		details = append(details, "NOTE: This check runs on the LOCAL machine. If auditing a remote")
		details = append(details, "tailnet via --tailnet, verify lock status on that tailnet directly.")

		// Try to extract key count or other info
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "key") || strings.Contains(line, "signing") {
				details = append(details, line)
			}
		}

		if len(details) > 1 {
			finding.Details = details
		}
		return finding
	}

	// Output doesn't clearly indicate enabled/disabled - report what we got
	finding.Pass = false
	finding.Severity = types.Informational
	finding.Description = "Tailnet Lock status unclear. Manual verification recommended."
	finding.Details = []string{
		"Output from 'tailscale lock status':",
		strings.TrimSpace(outputStr),
		"",
		"Please verify Tailnet Lock status manually.",
		"To enable: tailscale lock init",
	}
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeExternal,
		Description: "Verify Tailnet Lock status and enable if needed",
		DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
	}

	return finding
}

func (d *DeviceAuditor) checkUniqueUsers(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-011",
		Title:       "Unique users in tailnet",
		Severity:    types.Informational,
		Category:    types.DeviceSecurity,
		Description: "Summary of unique users who own devices in the tailnet. Review user list for unexpected or departed users.",
		Remediation: "Periodically audit the user list. Remove access for departed employees. Verify external users should have access.",
		Source:      "https://tailscale.com/kb/1184/deprovisioning",
		Pass:        true,
	}

	// Count devices per user
	userDevices := make(map[string][]string)
	for _, dev := range devices {
		if dev.User == "" {
			continue
		}
		userDevices[dev.User] = append(userDevices[dev.User], dev.Name)
	}

	// Find users with many devices (potential concern)
	const manyDevicesThreshold = 10
	var usersWithManyDevices []string

	var userSummary []string
	for user, devList := range userDevices {
		userSummary = append(userSummary, fmt.Sprintf("%s: %d device(s)", user, len(devList)))
		if len(devList) > manyDevicesThreshold {
			usersWithManyDevices = append(usersWithManyDevices, fmt.Sprintf("%s: %d devices", user, len(devList)))
		}
	}

	finding.Description = fmt.Sprintf("Found %d unique user(s) owning devices in the tailnet.", len(userDevices))
	finding.Details = userSummary

	if len(usersWithManyDevices) > 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("Found %d unique user(s). %d user(s) own more than %d devices - verify this is expected.",
			len(userDevices), len(usersWithManyDevices), manyDevicesThreshold)
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review users with many devices",
			AdminURL:    "https://login.tailscale.com/admin/users",
			DocURL:      "https://tailscale.com/kb/1184/deprovisioning",
		}
	}

	return finding
}

func (d *DeviceAuditor) checkTailnetLockPending(ctx context.Context) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-012",
		Title:       "Nodes awaiting Tailnet Lock signature",
		Severity:    types.High,
		Category:    types.DeviceSecurity,
		Description: "With Tailnet Lock enabled, new nodes require signatures from trusted signing keys before they can connect.",
		Remediation: "Review pending nodes and sign legitimate ones. Investigate unexpected signing requests.",
		Source:      "https://tailscale.com/kb/1226/tailnet-lock",
		Pass:        true,
	}

	// Find tailscale binary using secure path resolution
	tsBinary, err := findTailscaleBinary()
	if err != nil {
		// Can't find binary, skip this check
		finding.Pass = true
		finding.Description = "Tailnet Lock pending check skipped (CLI unavailable)."
		finding.Details = []string{
			"This check only applies when Tailnet Lock is enabled.",
			"NOTE: This check runs on the LOCAL machine.",
		}
		return finding
	}

	// Try to run tailscale lock status for detailed info
	cmd := exec.CommandContext(ctx, tsBinary, "lock", "status")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// If lock is not enabled or command fails, skip this check
		finding.Pass = true
		finding.Description = "Tailnet Lock status check skipped (lock not enabled or CLI unavailable)."
		finding.Details = "This check only applies when Tailnet Lock is enabled."
		return finding
	}

	outputStr := string(output)

	// Check if there are pending signatures
	if strings.Contains(outputStr, "awaiting") ||
		strings.Contains(outputStr, "pending") ||
		strings.Contains(outputStr, "needs signature") {

		finding.Pass = false
		finding.Description = "There are nodes awaiting Tailnet Lock signatures. Review and sign legitimate nodes."

		// Extract relevant lines
		var pendingLines []string
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "await") || strings.Contains(line, "pending") || strings.Contains(line, "needs") {
				pendingLines = append(pendingLines, line)
			}
		}

		if len(pendingLines) > 0 {
			finding.Details = pendingLines
		} else {
			finding.Details = []string{
				"Nodes are awaiting signatures.",
				"Run 'tailscale lock status' for details.",
				"Sign with: tailscale lock sign <nodekey>",
			}
		}

		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeExternal,
			Description: "Review pending nodes with 'tailscale lock status' and sign legitimate ones",
			DocURL:      "https://tailscale.com/kb/1226/tailnet-lock",
		}
		return finding
	}

	// Check if lock is enabled but no pending nodes
	if strings.Contains(outputStr, "enabled") {
		finding.Pass = true
		finding.Description = "Tailnet Lock is enabled with no nodes awaiting signatures (local check)."
		finding.Details = "NOTE: This check runs on the LOCAL machine. If auditing a remote tailnet, verify directly."
		return finding
	}

	// Lock not enabled - skip this check
	finding.Pass = true
	finding.Description = "Tailnet Lock is not enabled. Enable it to require device signing."
	finding.Details = []string{
		"This check only reports pending signatures when Tailnet Lock is active.",
		"NOTE: This check runs on the LOCAL machine.",
	}
	return finding
}
