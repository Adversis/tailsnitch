package auditor

import (
	"context"

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

// Audit performs logging and admin security checks
func (l *LoggingAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// LOG-001: Network flow logs (manual check)
	findings = append(findings, l.checkNetworkFlowLogs())

	// LOG-002: Log streaming (manual check)
	findings = append(findings, l.checkLogStreaming())

	// LOG-003: Audit log retention
	findings = append(findings, l.checkAuditLogRetention())

	// LOG-004: Failed login monitoring
	findings = append(findings, l.checkFailedLoginMonitoring())

	// LOG-005: Webhook configuration (manual check)
	findings = append(findings, l.checkWebhookConfiguration())

	// LOG-006: OAuth client review (manual check)
	findings = append(findings, l.checkOAuthClients())

	// LOG-007: SCIM configuration (manual check)
	findings = append(findings, l.checkSCIMConfiguration())

	// LOG-008: Passkey admin backup
	findings = append(findings, l.checkPasskeyAdmin())

	// LOG-009: MFA in identity provider
	findings = append(findings, l.checkMFAConfiguration())

	// LOG-010: DNS rebinding protection
	findings = append(findings, l.checkDNSRebindingProtection())

	// LOG-011: Security contact configuration
	findings = append(findings, l.checkSecurityContact())

	// LOG-012: Webhook events configuration
	findings = append(findings, l.checkWebhookEvents())

	// USER-001: User roles and ownership review
	findings = append(findings, l.checkUserRoles())

	// DEV-013: Device posture configuration
	findings = append(findings, l.checkDevicePosture())

	return findings, nil
}

func (l *LoggingAuditor) checkNetworkFlowLogs() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-001",
		Title:       "Network flow logs configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Network flow logs are disabled by default and only available for Premium/Enterprise plans.",
		Remediation: "Navigate to admin console > Network flow logs > Start logging. Enable log streaming for retention beyond 30 days.",
		Source:      "https://tailscale.com/kb/1219/network-flow-logs",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Verify network flow logs are enabled in admin console.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable network flow logs in admin console",
			AdminURL:    "https://login.tailscale.com/admin/logs/network",
			DocURL:      "https://tailscale.com/kb/1219/network-flow-logs",
		},
	}
}

func (l *LoggingAuditor) checkLogStreaming() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-002",
		Title:       "Log streaming for long-term retention",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Configuration audit logs are retained for 90 days, network flow logs for 30 days. Log streaming required for longer retention.",
		Remediation: "Configure log streaming to SIEM or S3 for compliance requirements exceeding retention limits.",
		Source:      "https://tailscale.com/kb/1203/audit-logging",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Verify log streaming is configured if retention >30/90 days is required.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Configure log streaming in admin console",
			AdminURL:    "https://login.tailscale.com/admin/logs",
			DocURL:      "https://tailscale.com/kb/1203/audit-logging",
		},
	}
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

func (l *LoggingAuditor) checkWebhookConfiguration() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-005",
		Title:       "Webhook secrets never expire",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Webhook endpoint secrets have no automatic expiration. If compromised, anyone can send fake events.",
		Remediation: "Implement periodic manual rotation schedule for webhook secrets. Store secrets securely.",
		Source:      "https://tailscale.com/kb/1213/webhooks",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Review webhook configurations and implement rotation schedule.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review and rotate webhook secrets in admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/webhooks",
			DocURL:      "https://tailscale.com/kb/1213/webhooks",
		},
	}
}

func (l *LoggingAuditor) checkOAuthClients() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-006",
		Title:       "OAuth clients persist after user removal",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "OAuth clients continue functioning after creating user loses tailnet access, creating persistent access vectors.",
		Remediation: "Review all OAuth clients in Trust credentials page. Identify clients created by former employees. Add OAuth client review to offboarding checklist.",
		Source:      "https://tailscale.com/kb/1215/oauth-clients",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Review OAuth clients in admin console and verify creators still have access.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review OAuth clients in admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/oauth",
			DocURL:      "https://tailscale.com/kb/1215/oauth-clients",
		},
	}
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

func (l *LoggingAuditor) checkSecurityContact() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-011",
		Title:       "Security contact email configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "A security contact email ensures your team receives important security notifications and bulletins from Tailscale.",
		Remediation: "Set a security contact email in Contact preferences. Use a group email (e.g., security@example.com) for multi-person coverage. Subscribe to the security RSS feed.",
		Source:      "https://tailscale.com/kb/1196/security-hardening",
		Pass:        false, // Manual check required
		Details:     "MANUAL CHECK REQUIRED: Verify security contact email is configured in admin console Contact preferences.",
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Configure security contact in admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/general",
			DocURL:      "https://tailscale.com/kb/1196/security-hardening",
		},
	}
}

func (l *LoggingAuditor) checkWebhookEvents() types.Suggestion {
	return types.Suggestion{
		ID:          "LOG-012",
		Title:       "Webhooks for critical events",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Webhooks can notify external systems about critical tailnet events (device additions, ACL changes, user changes). Enable webhooks for security monitoring.",
		Remediation: "Configure webhooks for critical event types: nodeCreated, nodeDeleted, nodeApproved, aclUpdated, userCreated, userDeleted. Integrate with your SIEM or alerting system.",
		Source:      "https://tailscale.com/kb/1213/webhooks",
		Pass:        false, // Manual check required
		Details: []string{
			"MANUAL CHECK REQUIRED: Verify webhooks are configured for critical events.",
			"",
			"Recommended webhook events to enable:",
			"  - nodeCreated: New device added to tailnet",
			"  - nodeDeleted: Device removed from tailnet",
			"  - nodeApproved: Pending device approved",
			"  - nodeKeyExpiringInOneDay: Key expiry warning",
			"  - aclUpdated: ACL policy changed",
			"  - userCreated: New user added",
			"  - userDeleted: User removed",
			"  - userRoleUpdated: User permissions changed",
		},
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Configure webhooks for critical events in admin console",
			AdminURL:    "https://login.tailscale.com/admin/settings/webhooks",
			DocURL:      "https://tailscale.com/kb/1213/webhooks",
		},
	}
}

func (l *LoggingAuditor) checkUserRoles() types.Suggestion {
	return types.Suggestion{
		ID:          "USER-001",
		Title:       "Review user roles and ownership",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "User roles (Owner, Admin, Member, IT Admin, Network Admin, Auditor, Billing Admin) control access to tailnet administration. Regular review prevents privilege creep.",
		Remediation: "Audit user roles periodically. Apply least privilege - most users should be Members. Review Owners (cannot be removed) and Admins (full control). Use IT Admin for helpdesk roles.",
		Source:      "https://tailscale.com/kb/1352/roles",
		Pass:        false, // Manual check required
		Details: []string{
			"MANUAL CHECK REQUIRED: Review user roles in admin console.",
			"",
			"Role hierarchy (highest to lowest privilege):",
			"  - Owner: Full control, cannot be removed, irrevocable",
			"  - Admin: Full control, can manage users/ACLs/devices",
			"  - IT Admin: Device management only",
			"  - Network Admin: ACL and network settings",
			"  - Auditor: Read-only access to logs and settings",
			"  - Billing Admin: Billing and subscription only",
			"  - Member: Regular user, no admin access",
			"",
			"Security recommendations:",
			"  - Minimize Owner accounts (ideally 1-2)",
			"  - Review Admin accounts quarterly",
			"  - Use specific roles (IT Admin, Network Admin) instead of full Admin",
		},
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review and adjust user roles in admin console",
			AdminURL:    "https://login.tailscale.com/admin/users",
			DocURL:      "https://tailscale.com/kb/1352/roles",
		},
	}
}

func (l *LoggingAuditor) checkDevicePosture() types.Suggestion {
	return types.Suggestion{
		ID:          "DEV-013",
		Title:       "Device posture configuration",
		Severity:    types.Informational,
		Category:    types.LoggingAdmin,
		Description: "Device posture integrations (Intune, Jamf, CrowdStrike, etc.) can restrict tailnet access based on device health and compliance status. Enterprise feature.",
		Remediation: "If available on your plan, configure device posture integration with your MDM/EDR. Define posture attributes in nodeAttrs to restrict non-compliant devices.",
		Source:      "https://tailscale.com/kb/1288/device-posture",
		Pass:        false, // Manual check required
		Details: []string{
			"MANUAL CHECK REQUIRED: Review device posture configuration if available on your plan.",
			"",
			"Device posture integrations:",
			"  - Intune: Microsoft endpoint management",
			"  - Jamf: Apple device management",
			"  - CrowdStrike Falcon: EDR posture",
			"  - Kolide: Cross-platform device health",
			"  - Custom: Define posture attributes via API",
			"",
			"To use device posture:",
			"  1. Configure integration in Settings > Integrations",
			"  2. Define posture requirements in ACL nodeAttrs",
			"  3. Non-compliant devices can be restricted from accessing resources",
			"",
			"Note: Device posture is an Enterprise feature.",
		},
		Fix: &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Configure device posture in admin console (Enterprise feature)",
			AdminURL:    "https://login.tailscale.com/admin/settings/integrations",
			DocURL:      "https://tailscale.com/kb/1288/device-posture",
		},
	}
}
