package auditor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// LoggingAuditor checks for logging and administrative issues
type LoggingAuditor struct {
	client *client.Client
}

// NewLoggingAuditor creates a new logging auditor
func NewLoggingAuditor(c *client.Client) *LoggingAuditor {
	return &LoggingAuditor{client: c}
}

// Audit performs logging and admin security checks.
//
// tc carries tailnet-wide state shared with the other auditors. When nil, it is
// fetched here so an individual auditor can be run on its own.
func (l *LoggingAuditor) Audit(ctx context.Context, tc *TailnetContext) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	if tc == nil {
		tc = FetchTailnetContext(ctx, l.client)
	}

	// LOG-001: Network flow logs
	findings = append(findings, l.checkNetworkFlowLogs(tc))

	// LOG-002: Log streaming
	findings = append(findings, l.checkLogStreaming(tc))

	// LOG-003: Audit log retention
	findings = append(findings, l.checkAuditLogRetention())

	// LOG-004: Failed login monitoring
	findings = append(findings, l.checkFailedLoginMonitoring())

	// LOG-005: Webhook configuration (manual check)
	findings = append(findings, l.checkWebhookConfiguration(tc))

	// LOG-006: OAuth client review (manual check)
	findings = append(findings, l.checkOAuthClients(tc))

	// LOG-007: SCIM configuration (manual check)
	findings = append(findings, l.checkSCIMConfiguration())

	// LOG-008: Passkey admin backup
	findings = append(findings, l.checkPasskeyAdmin())

	// LOG-009: MFA in identity provider
	findings = append(findings, l.checkMFAConfiguration())

	// LOG-010: DNS rebinding protection
	findings = append(findings, l.checkDNSRebindingProtection())

	// LOG-011: Security contact configuration
	findings = append(findings, l.checkSecurityContact(tc))

	// LOG-012: Webhook events configuration
	findings = append(findings, l.checkWebhookEvents(tc))

	// USER-001: User roles and ownership review
	findings = append(findings, l.checkUserRoles(tc))

	// DEV-014: Device posture configuration
	findings = append(findings, l.checkDevicePosture(tc))

	return findings, nil
}

// unavailable renders the guidance shown when a resource could not be read,
// so a missing scope is never reported as a passing control.
func unavailable(what string, err error) []string {
	return []string{
		fmt.Sprintf("Could not read %s: %v", what, err),
		"MANUAL CHECK REQUIRED: verify this setting in the admin console.",
	}
}

func (l *LoggingAuditor) checkNetworkFlowLogs(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-001",
		Title:       "Network flow logs configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Network flow logs record connections between devices. They are disabled by default and available on Premium and Enterprise plans.",
		Remediation: "Enable network flow logs in the admin console. Add log streaming for retention beyond 30 days.",
		Source:      "https://tailscale.com/kb/1219/network-flow-logs",
		Pass:        true,
	}

	settings := tc.settings()
	if settings == nil {
		finding.Pass = false
		finding.Description = "Could not determine whether network flow logs are enabled."
		finding.Details = unavailable("tailnet settings (needs the logs:network:read scope)", tc.SettingsErr)
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Check network flow logs in the admin console",
			AdminURL:    "https://login.tailscale.com/admin/logs/network",
			DocURL:      "https://tailscale.com/kb/1219/network-flow-logs",
		}
		return finding
	}

	if !settings.NetworkFlowLoggingOn {
		finding.Pass = false
		finding.Description = "Network flow logs are disabled. Connections between devices are not recorded, leaving no audit trail of tailnet traffic."
		finding.Details = "Confirmed via the Tailscale API (networkFlowLoggingOn is false)."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable network flow logs in the admin console",
			AdminURL:    "https://login.tailscale.com/admin/logs/network",
			DocURL:      "https://tailscale.com/kb/1219/network-flow-logs",
		}
		return finding
	}

	finding.Description = "Network flow logs are enabled."
	finding.Details = "Confirmed via the Tailscale API (networkFlowLoggingOn is true)."
	return finding
}

func (l *LoggingAuditor) checkLogStreaming(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-002",
		Title:       "Log streaming for long-term retention",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Tailscale retains configuration audit logs for 90 days and network flow logs for 30 days. Log streaming to a SIEM or object store is required to keep them longer.",
		Remediation: "Configure log streaming for configuration audit logs and network flow logs if your retention requirements exceed those windows.",
		Source:      "https://tailscale.com/kb/1203/audit-logging",
		Pass:        true,
	}

	if tc == nil || tc.LogstreamErr != nil {
		var err error
		if tc != nil {
			err = tc.LogstreamErr
		}
		finding.Pass = false
		finding.Description = "Could not determine whether log streaming is configured."
		finding.Details = unavailable("log stream configuration (needs the log_streaming:read scope)", err)
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Check log streaming in the admin console",
			AdminURL:    "https://login.tailscale.com/admin/logs",
			DocURL:      "https://tailscale.com/kb/1203/audit-logging",
		}
		return finding
	}

	var missing []string
	if !tc.ConfigLogstream {
		missing = append(missing, "configuration audit logs (90-day retention without streaming)")
	}
	if !tc.NetworkLogstream {
		missing = append(missing, "network flow logs (30-day retention without streaming)")
	}

	if len(missing) == 0 {
		finding.Description = "Log streaming is configured for both configuration audit logs and network flow logs."
		return finding
	}

	finding.Pass = false
	finding.Description = fmt.Sprintf("Log streaming is not configured for %d of 2 log types. Those logs are kept only for Tailscale's default retention window.", len(missing))
	finding.Details = append([]string{"No streaming destination for:"}, missing...)
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Configure log streaming in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/logs",
		DocURL:      "https://tailscale.com/kb/1203/audit-logging",
	}
	return finding
}
func (l *LoggingAuditor) checkAuditLogRetention() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-003",
		Title:       "Audit log limitations",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Configuration audit logs have several limitations: 90-day retention, no read-only action logging, no Tailscale support action logging.",
		Remediation: "Maintain separate records of support interactions. For read access logging, implement monitoring at identity provider level.",
		Source:      "https://tailscale.com/kb/1203/audit-logging",
		Pass:        true, // Informational
		Details:     "Audit logs are always enabled. Connection denials and failed logins are NOT logged by Tailscale.",
	}
}

func (l *LoggingAuditor) checkFailedLoginMonitoring() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-004",
		Title:       "Failed login monitoring via IdP",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Failed authentication attempts must be monitored through your identity provider, not Tailscale. This is an FYI - Tailscale cannot detect this.",
		Remediation: "Ensure identity provider has comprehensive authentication logging with alerts for failed attempts.",
		Source:      "https://tailscale.com/kb/1203/audit-logging",
		Pass:        true, // Informational - external system
		Details:     "FYI: Tailscale does not log failed authentication attempts. Configure monitoring in your IdP.",
	}
}

func (l *LoggingAuditor) checkWebhookConfiguration(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-005",
		Title:       "Webhook secrets never expire",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Webhook endpoint secrets have no automatic expiration. If one leaks, anyone can send forged events to that endpoint until it is rotated.",
		Remediation: "Rotate webhook secrets on a schedule and store them in a secrets manager.",
		Source:      "https://tailscale.com/kb/1213/webhooks",
		Pass:        true,
	}

	if tc == nil || tc.WebhooksErr != nil {
		var err error
		if tc != nil {
			err = tc.WebhooksErr
		}
		finding.Pass = false
		finding.Description = "Could not enumerate webhook endpoints."
		finding.Details = unavailable("webhooks (needs the webhooks:read scope)", err)
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review webhook endpoints in the admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/webhooks",
			DocURL:      "https://tailscale.com/kb/1213/webhooks",
		}
		return finding
	}

	if len(tc.Webhooks) == 0 {
		finding.Description = "No webhook endpoints are configured, so there are no webhook secrets to rotate."
		return finding
	}

	// Endpoints are reported with their age so a rotation schedule can be
	// judged against something concrete. LastModified moves on secret rotation.
	const staleAfter = 365 * 24 * time.Hour
	var stale []string
	details := make([]string, 0, len(tc.Webhooks)+2)
	details = append(details, fmt.Sprintf("%d webhook endpoint(s) configured:", len(tc.Webhooks)))

	for _, hook := range tc.Webhooks {
		age := "unknown age"
		if !hook.LastModified.IsZero() {
			days := int(time.Since(hook.LastModified).Hours() / 24)
			age = fmt.Sprintf("last modified %d days ago", days)
			if time.Since(hook.LastModified) > staleAfter {
				stale = append(stale, fmt.Sprintf("%s (%s)", hook.EndpointURL, age))
			}
		}
		details = append(details, fmt.Sprintf("  - %s (%s, created by %s)", hook.EndpointURL, age, hook.CreatorLoginName))
	}

	if len(stale) > 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("%d of %d webhook endpoint(s) have not been modified in over a year, so their secrets are at least that old.", len(stale), len(tc.Webhooks))
		details = append(details, "", "Not modified in over a year:")
		details = append(details, stale...)
	} else {
		finding.Description = fmt.Sprintf("%d webhook endpoint(s) configured. Secrets never expire on their own, so confirm they are on a rotation schedule.", len(tc.Webhooks))
	}

	finding.Details = details
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Rotate webhook secrets in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/settings/webhooks",
		DocURL:      "https://tailscale.com/kb/1213/webhooks",
	}
	return finding
}
func (l *LoggingAuditor) checkOAuthClients(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-006",
		Title:       "OAuth clients persist after user removal",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "OAuth clients keep working after the user who created them loses tailnet access, leaving a standing credential behind a departed account.",
		Remediation: "Review OAuth clients on the Trust credentials page and add OAuth client review to your offboarding checklist.",
		Source:      "https://tailscale.com/kb/1215/oauth-clients",
		Pass:        true,
	}

	if tc == nil || tc.OAuthErr != nil {
		var err error
		if tc != nil {
			err = tc.OAuthErr
		}
		finding.Pass = false
		finding.Description = "Could not enumerate OAuth clients."
		finding.Details = unavailable("OAuth clients (needs the oauth_keys:read scope)", err)
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review OAuth clients in the admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/oauth",
			DocURL:      "https://tailscale.com/kb/1215/oauth-clients",
		}
		return finding
	}

	if len(tc.OAuthClients) == 0 {
		finding.Description = "No OAuth clients are configured."
		return finding
	}

	// A client whose owning user is gone or suspended is the case this check
	// exists for: the credential outlives the account that created it.
	activeLogins, usersReadable := tc.activeUserLogins()
	usersByID := make(map[string]client.User, len(tc.Users))
	for _, user := range tc.Users {
		usersByID[user.ID] = user
	}

	var orphaned []string
	details := make([]string, 0, len(tc.OAuthClients)+3)
	details = append(details, fmt.Sprintf("%d OAuth client(s) configured:", len(tc.OAuthClients)))

	for _, oc := range tc.OAuthClients {
		owner := "owned by the tailnet"
		if oc.UserID != "" {
			if user, ok := usersByID[oc.UserID]; ok {
				owner = fmt.Sprintf("created by %s (%s)", user.LoginName, user.Status)
				if usersReadable && !activeLogins[user.LoginName] {
					orphaned = append(orphaned, fmt.Sprintf("%s - %s is %s", describeKey(oc), user.LoginName, user.Status))
				}
			} else {
				owner = fmt.Sprintf("created by user %s", oc.UserID)
				if usersReadable {
					orphaned = append(orphaned, fmt.Sprintf("%s - creating user %s is no longer in the tailnet", describeKey(oc), oc.UserID))
				}
			}
		}
		scopes := "no scopes"
		if len(oc.Scopes) > 0 {
			scopes = strings.Join(oc.Scopes, ", ")
		}
		details = append(details, fmt.Sprintf("  - %s (%s, scopes: %s)", describeKey(oc), owner, scopes))
	}

	if len(orphaned) > 0 {
		finding.Pass = false
		finding.Severity = types.High
		finding.Description = fmt.Sprintf("Found %d OAuth client(s) whose creating user no longer has tailnet access. These credentials still work.", len(orphaned))
		details = append(details, "", "Clients belonging to departed or suspended users:")
		details = append(details, orphaned...)
	} else if !usersReadable {
		finding.Pass = false
		finding.Description = fmt.Sprintf("Found %d OAuth client(s), but the user list could not be read to check whether their creators still have access.", len(tc.OAuthClients))
		details = append(details, "", "Grant the users:read scope to cross-reference client owners automatically.")
	} else {
		finding.Description = fmt.Sprintf("Found %d OAuth client(s); every creating user still has tailnet access.", len(tc.OAuthClients))
	}

	finding.Details = details
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Review OAuth clients in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/settings/oauth",
		DocURL:      "https://tailscale.com/kb/1215/oauth-clients",
	}
	return finding
}

// describeKey names a credential by its description, falling back to its ID.
func describeKey(key client.Key) string {
	if key.Description != "" {
		return fmt.Sprintf("%s (%s)", key.Description, key.ID)
	}
	return key.ID
}
func (l *LoggingAuditor) checkSCIMConfiguration() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-007",
		Title:       "SCIM API keys never expire",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "SCIM API keys have no automatic expiration, increasing exposure window if compromised. SCIM-suspended users retain access until key expiry.",
		Remediation: "Implement manual rotation schedule for SCIM keys. Manually remove suspended users if immediate revocation required.",
		Source:      "https://tailscale.com/kb/1252/key-secret-management",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: If using SCIM, implement key rotation schedule and verify user suspension handling.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review and rotate SCIM keys in admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/scim",
			DocURL:      "https://tailscale.com/kb/1252/key-secret-management",
		},
	}
}

func (l *LoggingAuditor) checkPasskeyAdmin() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-008",
		Title:       "Passkey-authenticated backup admin",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "If SSO identity provider fails, all users may be locked out without a passkey-authenticated admin account.",
		Remediation: "Create a passkey-authenticated admin account with Owner or Admin role. Test passkey login periodically. Document recovery procedures.",
		Source:      "https://tailscale.com/kb/1341/tailnet-passkey-admin",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Verify passkey-authenticated backup admin exists for IdP failure recovery.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Configure passkey admin in user management",
			AdminURL:    "https://login.tailscale.com/admin/settings/user-management",
			DocURL:      "https://tailscale.com/kb/1341/tailnet-passkey-admin",
		},
	}
}

func (l *LoggingAuditor) checkMFAConfiguration() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-009",
		Title:       "MFA enforcement in identity provider",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Tailscale doesn't handle authentication directly - MFA must be configured in your identity provider. This is an FYI - Tailscale cannot detect or enforce this.",
		Remediation: "Enable MFA in your identity provider. Use hardware security keys (FIDO2/WebAuthn) where possible for phishing resistance.",
		Source:      "https://tailscale.com/kb/1075/multifactor-auth",
		Pass:        true, // Informational - external system
		Details:     "FYI: MFA must be configured in your IdP (Okta, Azure AD, Google, etc.), not in Tailscale.",
	}
}

func (l *LoggingAuditor) checkDNSRebindingProtection() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-010",
		Title:       "DNS rebinding attack protection",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "HTTP services on the tailnet may be vulnerable to DNS rebinding attacks if they don't validate Host headers. This is an FYI - configure on your application servers.",
		Remediation: "Configure all HTTP services to validate Host headers against an allowlist. Only accept requests with expected Host values.",
		Source:      "https://tailscale.com/kb/1196/security-hardening",
		Pass:        true, // Informational - host-level configuration
		Details:     "FYI: DNS rebinding protection must be configured on each HTTP service, not in Tailscale.",
	}
}

func (l *LoggingAuditor) checkSecurityContact(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-011",
		Title:       "Security contact email configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "The security contact is where Tailscale sends security notifications and bulletins for your tailnet.",
		Remediation: "Set a security contact in Contact preferences. Prefer a group address (for example security@example.com) so coverage does not depend on one person.",
		Source:      "https://tailscale.com/kb/1196/security-hardening",
		Pass:        true,
	}

	fix := &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Set the security contact in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/settings/general",
		DocURL:      "https://tailscale.com/kb/1196/security-hardening",
	}

	if tc == nil || tc.ContactsErr != nil {
		var err error
		if tc != nil {
			err = tc.ContactsErr
		}
		finding.Pass = false
		finding.Description = "Could not read the tailnet's contact preferences."
		finding.Details = unavailable("contacts (needs the account_settings:read scope)", err)
		finding.Fix = fix
		return finding
	}

	security := tc.Contacts.Security
	switch {
	case security.Email == "":
		finding.Pass = false
		finding.Severity = types.Medium
		finding.Description = "No security contact email is set. Security bulletins for this tailnet have no dedicated recipient."
		finding.Fix = fix
	case security.NeedsVerification:
		finding.Pass = false
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("The security contact %s is not verified, so notifications fall back to %s.", security.Email, security.FallbackEmail)
		finding.Details = "Confirm the verification email to activate the contact."
		finding.Fix = fix
	default:
		finding.Description = fmt.Sprintf("Security contact is set and verified: %s", security.Email)
		if !strings.Contains(security.Email, "security") && !strings.Contains(security.Email, "-team") {
			finding.Details = "Consider a group address so security bulletins are not routed to a single individual."
		}
	}

	return finding
}

// criticalWebhookEvents are the events worth alerting on for security
// monitoring, each with a short reason.
var criticalWebhookEvents = []struct {
	Event  client.WebhookSubscriptionType
	Reason string
}{
	{client.WebhookNodeCreated, "New device added to the tailnet"},
	{client.WebhookNodeDeleted, "Device removed from the tailnet"},
	{client.WebhookNodeApproved, "Pending device approved"},
	{client.WebhookNodeNeedsApproval, "Device is waiting on approval"},
	{client.WebhookPolicyUpdate, "Tailnet policy file changed"},
	{client.WebhookUserCreated, "New user added"},
	{client.WebhookUserDeleted, "User removed"},
	{client.WebhookUserSuspended, "User suspended"},
	{client.WebhookUserRoleUpdated, "User permissions changed"},
}

func (l *LoggingAuditor) checkWebhookEvents(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "LOG-012",
		Title:       "Webhooks for critical events",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Webhooks notify external systems about tailnet events such as device additions, policy changes and user role changes.",
		Remediation: "Subscribe a webhook to the tailnet management events and route them to your SIEM or alerting system.",
		Source:      "https://tailscale.com/kb/1213/webhooks",
		Pass:        true,
	}

	fix := &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Configure webhook subscriptions in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/settings/webhooks",
		DocURL:      "https://tailscale.com/kb/1213/webhooks",
	}

	if tc == nil || tc.WebhooksErr != nil {
		var err error
		if tc != nil {
			err = tc.WebhooksErr
		}
		finding.Pass = false
		finding.Description = "Could not enumerate webhook subscriptions."
		finding.Details = unavailable("webhooks (needs the webhooks:read scope)", err)
		finding.Fix = fix
		return finding
	}

	// The category subscription implies every event in its group, including
	// ones Tailscale adds later, so treat it as covering them all.
	subscribed := make(map[client.WebhookSubscriptionType]bool)
	category := false
	for _, hook := range tc.Webhooks {
		for _, sub := range hook.Subscriptions {
			subscribed[sub] = true
			if sub == client.WebhookCategoryTailnetManagement {
				category = true
			}
		}
	}

	if len(tc.Webhooks) == 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Description = "No webhooks are configured, so no tailnet events reach an external system."
		finding.Details = describeCriticalEvents()
		finding.Fix = fix
		return finding
	}

	if category {
		finding.Description = fmt.Sprintf("%d webhook endpoint(s) subscribe to the tailnet management event category, which covers all critical events.", len(tc.Webhooks))
		return finding
	}

	var missing []string
	for _, want := range criticalWebhookEvents {
		if !subscribed[want.Event] {
			missing = append(missing, fmt.Sprintf("  - %s: %s", want.Event, want.Reason))
		}
	}

	if len(missing) == 0 {
		finding.Description = fmt.Sprintf("%d webhook endpoint(s) cover all critical tailnet events.", len(tc.Webhooks))
		return finding
	}

	finding.Pass = false
	finding.Severity = types.Low
	finding.Description = fmt.Sprintf("Webhooks are configured but %d critical event type(s) have no subscription.", len(missing))
	finding.Details = append([]string{"Unsubscribed events:"}, missing...)
	finding.Fix = fix
	return finding
}

func describeCriticalEvents() []string {
	details := []string{"Recommended events to subscribe to:"}
	for _, want := range criticalWebhookEvents {
		details = append(details, fmt.Sprintf("  - %s: %s", want.Event, want.Reason))
	}
	return details
}

func (l *LoggingAuditor) checkUserRoles(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "USER-001",
		Title:       "Review user roles and ownership",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "User roles control who can administer the tailnet. Regular review keeps privilege from accumulating.",
		Remediation: "Apply least privilege: most users should be Members, and helpdesk or network duties should use the IT Admin and Network Admin roles rather than full Admin.",
		Source:      "https://tailscale.com/docs/reference/user-roles",
		Pass:        true,
	}

	fix := &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Review user roles in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/users",
		DocURL:      "https://tailscale.com/docs/reference/user-roles",
	}

	if tc == nil || tc.UsersErr != nil {
		var err error
		if tc != nil {
			err = tc.UsersErr
		}
		finding.Pass = false
		finding.Description = "Could not enumerate tailnet users."
		finding.Details = unavailable("users (needs the users:read scope)", err)
		finding.Fix = fix
		return finding
	}

	byRole := make(map[client.UserRole][]string)
	var suspended, needApproval, external []string
	for _, user := range tc.Users {
		byRole[user.Role] = append(byRole[user.Role], user.LoginName)
		switch user.Status {
		case client.UserStatusSuspended:
			suspended = append(suspended, user.LoginName)
		case client.UserStatusNeedsApproval:
			needApproval = append(needApproval, user.LoginName)
		}
		if user.Type == client.UserTypeShared {
			external = append(external, user.LoginName)
		}
	}

	details := []string{fmt.Sprintf("%d user(s) in the tailnet:", len(tc.Users))}
	roles := make([]string, 0, len(byRole))
	for role := range byRole {
		roles = append(roles, string(role))
	}
	sort.Strings(roles)
	for _, role := range roles {
		logins := byRole[client.UserRole(role)]
		sort.Strings(logins)
		details = append(details, fmt.Sprintf("  - %s: %d (%s)", role, len(logins), strings.Join(logins, ", ")))
	}

	privileged := len(byRole[client.UserRoleOwner]) + len(byRole[client.UserRoleAdmin])
	var concerns []string
	if privileged > maxPrivilegedUsers {
		concerns = append(concerns, fmt.Sprintf("%d users hold Owner or Admin, more than the %d this check treats as a reasonable ceiling", privileged, maxPrivilegedUsers))
	}
	if len(suspended) > 0 {
		concerns = append(concerns, fmt.Sprintf("%d suspended user(s) still present: %s", len(suspended), strings.Join(suspended, ", ")))
	}
	if len(needApproval) > 0 {
		concerns = append(concerns, fmt.Sprintf("%d user(s) awaiting approval: %s", len(needApproval), strings.Join(needApproval, ", ")))
	}
	if len(external) > 0 {
		concerns = append(concerns, fmt.Sprintf("%d external (shared) user(s): %s", len(external), strings.Join(external, ", ")))
	}

	if len(concerns) > 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("Found %d user(s), %d with Owner or Admin. Review the items below.", len(tc.Users), privileged)
		details = append(details, "")
		details = append(details, "Worth reviewing:")
		for _, concern := range concerns {
			details = append(details, "  - "+concern)
		}
		finding.Fix = fix
	} else {
		finding.Description = fmt.Sprintf("Found %d user(s), %d with Owner or Admin.", len(tc.Users), privileged)
	}

	finding.Details = details
	return finding
}

// maxPrivilegedUsers is the number of Owner plus Admin accounts above which
// this check asks for a review.
const maxPrivilegedUsers = 3

func (l *LoggingAuditor) checkDevicePosture(tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DEV-014",
		Title:       "Device posture configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Device posture integrations (Intune, Jamf, CrowdStrike, Kolide) let policy restrict access based on device health and compliance.",
		Remediation: "If your plan includes it, connect your MDM or EDR and reference posture attributes from the tailnet policy file to keep non-compliant devices out.",
		Source:      "https://tailscale.com/kb/1288/device-posture",
		Pass:        true,
	}

	fix := &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Configure device posture integrations in the admin console",
		AdminURL:    "https://login.tailscale.com/admin/settings/integrations",
		DocURL:      "https://tailscale.com/kb/1288/device-posture",
	}

	if tc == nil || tc.PostureErr != nil {
		var err error
		if tc != nil {
			err = tc.PostureErr
		}
		finding.Pass = false
		finding.Description = "Could not enumerate device posture integrations."
		finding.Details = unavailable("posture integrations (needs the devices:posture_attributes:read scope)", err)
		finding.Fix = fix
		return finding
	}

	details := []string{}
	if settings := tc.settings(); settings != nil {
		if settings.PostureIdentityCollectionOn {
			details = append(details, "Device identity collection is enabled (serial numbers are collected for posture).")
		} else {
			details = append(details, "Device identity collection is disabled, so posture integrations cannot match devices by serial number.")
		}
	}

	if len(tc.PostureIntegrations) == 0 {
		finding.Pass = false
		finding.Description = "No device posture integrations are configured. Access is not conditioned on device health or compliance."
		finding.Details = append(details, "", "Supported providers: Intune, Jamf, CrowdStrike Falcon, Kolide, and custom attributes set via the API.")
		finding.Fix = fix
		return finding
	}

	providers := make([]string, 0, len(tc.PostureIntegrations))
	for _, integration := range tc.PostureIntegrations {
		providers = append(providers, string(integration.Provider))
	}
	sort.Strings(providers)

	finding.Description = fmt.Sprintf("%d device posture integration(s) configured: %s.", len(tc.PostureIntegrations), strings.Join(providers, ", "))
	finding.Details = append(details, "", "Confirm the tailnet policy file references posture attributes; an integration alone does not restrict access.")
	return finding
}
