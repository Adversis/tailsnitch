package types

import (
	"fmt"
	"regexp"
	"strings"
)

// CheckInfo contains metadata about a security check
type CheckInfo struct {
	ID         string
	Slug       string
	Title      string
	Category   Category
	CCMappings []string // SOC 2 Common Criteria mappings
}

// CheckRegistry maps check IDs and slugs to check metadata
type CheckRegistry struct {
	checks []CheckInfo
	byID   map[string]*CheckInfo
	bySlug map[string]*CheckInfo
}

// slugify converts a title to a URL-friendly slug
func slugify(s string) string {
	// Remove parenthetical suffixes like "(Access Rules)"
	if idx := strings.Index(s, "("); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}

	s = strings.ToLower(s)

	// Replace special characters with spaces
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "'", "")

	// Replace non-alphanumeric with hyphens
	re := regexp.MustCompile(`[^a-z0-9]+`)
	s = re.ReplaceAllString(s, "-")

	// Trim leading/trailing hyphens
	s = strings.Trim(s, "-")

	return s
}

// NewCheckRegistry creates and initializes the check registry
func NewCheckRegistry() *CheckRegistry {
	checks := []CheckInfo{
		// ACL checks - CC6.1 (Logical Access), CC6.2 (Access Control)
		{ID: "ACL-001", Title: "Default 'allow all' policy active", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-002", Title: "SSH autogroup:nonroot misconfiguration", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-003", Title: "No ACL tests defined", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-004", Title: "autogroup:member grants access to external users", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-005", Title: "AutoApprovers bypass administrative route approval", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-006", Title: "tagOwners grants tag privileges too broadly", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-007", Title: "autogroup:danger-all grants access to everyone", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-008", Title: "No groups defined in ACL policy", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-009", Title: "Using legacy ACLs instead of grants", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "ACL-010", Title: "Taildrop file sharing configuration", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2", "C1.1"}},

		// Auth checks - CC6.1 (Logical Access), CC6.2 (Access Control), CC6.3 (Access Removal)
		{ID: "AUTH-001", Title: "Reusable auth keys exist", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2", "CC6.3"}},
		{ID: "AUTH-002", Title: "Auth keys with long expiry period", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2", "CC6.3"}},
		{ID: "AUTH-003", Title: "Pre-authorized auth keys bypass device approval", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "AUTH-004", Title: "Non-ephemeral keys may be used for CI/CD", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2", "CC6.3"}},

		// Device checks - CC6.1 (Logical Access), CC6.3 (Access Removal), CC7.1 (System Operations)
		{ID: "DEV-001", Title: "Tagged devices with key expiry disabled", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "DEV-002", Title: "User devices tagged", Category: DeviceSecurity, CCMappings: []string{"CC6.1"}},
		{ID: "DEV-003", Title: "Outdated Tailscale clients", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC7.1"}},
		{ID: "DEV-004", Title: "Stale devices not seen recently", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "DEV-005", Title: "Unauthorized devices pending approval", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "DEV-006", Title: "External devices in tailnet", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "DEV-007", Title: "Potentially sensitive machine names", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "C1.1"}},
		{ID: "DEV-008", Title: "Devices with long key expiry periods", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "DEV-009", Title: "Device approval configuration", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "DEV-010", Title: "Tailnet Lock not enabled", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC7.1"}},
		{ID: "DEV-011", Title: "Unique users in tailnet", Category: DeviceSecurity, CCMappings: []string{"CC6.1"}},
		{ID: "DEV-012", Title: "Nodes awaiting Tailnet Lock signature", Category: DeviceSecurity, CCMappings: []string{"CC6.1", "CC7.1"}},
		{ID: "DEV-013", Title: "Device posture configuration", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC7.1"}},

		// Network checks - CC6.6 (Boundary Protection), CC6.7 (Transmission Protection)
		{ID: "NET-001", Title: "Funnel exposes services to public internet", Category: NetworkExposure, CCMappings: []string{"CC6.6", "CC6.7"}},
		{ID: "NET-002", Title: "Exit node access configuration", Category: NetworkExposure, CCMappings: []string{"CC6.6", "CC6.7"}},
		{ID: "NET-003", Title: "Subnet routes expose trust boundary", Category: NetworkExposure, CCMappings: []string{"CC6.6", "CC6.7"}},
		{ID: "NET-004", Title: "HTTPS certificates publish names to CT logs", Category: NetworkExposure, CCMappings: []string{"CC6.6", "C1.1"}},
		{ID: "NET-005", Title: "Exit nodes can see all internet traffic", Category: NetworkExposure, CCMappings: []string{"CC6.6", "CC6.7", "C1.1"}},
		{ID: "NET-006", Title: "Tailscale Serve exposes services on tailnet", Category: NetworkExposure, CCMappings: []string{"CC6.6"}},
		{ID: "NET-007", Title: "App connectors provide SaaS access", Category: NetworkExposure, CCMappings: []string{"CC6.6", "CC6.7"}},

		// SSH checks - CC6.1 (Logical Access), CC6.6 (Boundary), CC7.2 (Monitoring)
		{ID: "SSH-001", Title: "SSH session recording not enforced", Category: SSHSecurity, CCMappings: []string{"CC6.1", "CC7.2"}},
		{ID: "SSH-002", Title: "High-risk SSH access without check mode", Category: SSHSecurity, CCMappings: []string{"CC6.1", "CC6.6", "CC7.2"}},
		{ID: "SSH-003", Title: "Session recorder UI may be exposed", Category: SSHSecurity, CCMappings: []string{"CC6.6", "CC7.2"}},
		{ID: "SSH-004", Title: "Tailscale SSH configuration", Category: SSHSecurity, CCMappings: []string{"CC6.1", "CC6.6"}},

		// Logging/Admin checks - CC7.1 (System Operations), CC7.2 (Monitoring), CC7.3 (Evaluation)
		{ID: "LOG-001", Title: "Network flow logs configuration", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.2"}},
		{ID: "LOG-002", Title: "Log streaming for long-term retention", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.2", "CC7.3"}},
		{ID: "LOG-003", Title: "Audit log limitations", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.2"}},
		{ID: "LOG-004", Title: "Failed login monitoring via IdP", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.2"}},
		{ID: "LOG-005", Title: "Webhook secrets never expire", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "LOG-006", Title: "OAuth clients persist after user removal", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "LOG-007", Title: "SCIM API keys never expire", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.3"}},
		{ID: "LOG-008", Title: "Passkey-authenticated backup admin", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "LOG-009", Title: "MFA enforcement in identity provider", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.2"}},
		{ID: "LOG-010", Title: "DNS rebinding attack protection", Category: LoggingAdmin, CCMappings: []string{"CC6.6", "CC7.1"}},
		{ID: "LOG-011", Title: "Security contact email configuration", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.3"}},
		{ID: "LOG-012", Title: "Webhooks for critical events", Category: LoggingAdmin, CCMappings: []string{"CC7.1", "CC7.2"}},
		{ID: "USER-001", Title: "Review user roles and ownership", Category: LoggingAdmin, CCMappings: []string{"CC6.1", "CC6.2", "CC6.3"}},

		// DNS checks - CC6.6 (Boundary Protection)
		{ID: "DNS-001", Title: "MagicDNS configuration", Category: DNSConfiguration, CCMappings: []string{"CC6.6"}},
	}

	// Generate slugs and build lookup maps
	r := &CheckRegistry{
		checks: checks,
		byID:   make(map[string]*CheckInfo),
		bySlug: make(map[string]*CheckInfo),
	}

	for i := range r.checks {
		check := &r.checks[i]
		check.Slug = slugify(check.Title)
		r.byID[strings.ToUpper(check.ID)] = check
		r.bySlug[check.Slug] = check
	}

	return r
}

// All returns all registered checks
func (r *CheckRegistry) All() []CheckInfo {
	return r.checks
}

// Resolve converts a check name (ID or slug) to the canonical check ID.
// Returns the ID and true if found, or empty string and false if not found.
func (r *CheckRegistry) Resolve(name string) (string, bool) {
	// Try as ID first (case-insensitive)
	if check, ok := r.byID[strings.ToUpper(name)]; ok {
		return check.ID, true
	}

	// Try as slug (lowercase)
	if check, ok := r.bySlug[strings.ToLower(name)]; ok {
		return check.ID, true
	}

	return "", false
}

// ResolveAll converts a list of check names (IDs or slugs) to canonical IDs.
// Returns an error if any name is not recognized.
func (r *CheckRegistry) ResolveAll(names []string) ([]string, error) {
	var ids []string
	var unknown []string

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		id, ok := r.Resolve(name)
		if !ok {
			unknown = append(unknown, name)
		} else {
			ids = append(ids, id)
		}
	}

	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown check(s): %s", strings.Join(unknown, ", "))
	}

	return ids, nil
}

// DefaultRegistry is the global check registry instance
var DefaultRegistry = NewCheckRegistry()
