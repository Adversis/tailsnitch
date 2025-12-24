package auditor

import (
	"context"
	"fmt"
	"strings"

	"tailsnitch/pkg/client"
	"tailsnitch/pkg/types"
)

// SSHAuditor checks for SSH and device security issues
type SSHAuditor struct {
	client *client.Client
}

// NewSSHAuditor creates a new SSH auditor
func NewSSHAuditor(c *client.Client) *SSHAuditor {
	return &SSHAuditor{client: c}
}

// Audit performs SSH security checks
func (s *SSHAuditor) Audit(ctx context.Context, policy ACLPolicy) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// SSH-001: Check session recording enforcement
	findings = append(findings, s.checkSessionRecording(policy))

	// SSH-002: Check for root access without check mode
	findings = append(findings, s.checkRootAccessSecurity(policy))

	// SSH-003: Check recorder UI exposure
	findings = append(findings, s.checkRecorderUIExposure(policy))

	// SSH-004: Check for SSH rules overall
	findings = append(findings, s.checkSSHRulesExist(policy))

	return findings, nil
}

func (s *SSHAuditor) checkSessionRecording(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "SSH-001",
		Title:       "SSH session recording not enforced",
		Severity:    types.Informational,
		Category:    types.SSHSecurity,
		Description: "Session recording without enforceRecorder:true allows SSH sessions when recorders are unreachable.",
		Remediation: "Set enforceRecorder:true for compliance-critical SSH rules. Deploy multiple recorders for failover.",
		Source:      "https://tailscale.com/kb/1246/tailscale-ssh-session-recording",
		Pass:        true,
	}

	var rulesWithRecording []string
	var rulesNotEnforced []string

	for i, rule := range policy.SSH {
		if len(rule.Recorder) > 0 {
			rulesWithRecording = append(rulesWithRecording, fmt.Sprintf("SSH Rule %d", i+1))
			if !rule.EnforceRecorder {
				rulesNotEnforced = append(rulesNotEnforced, fmt.Sprintf("SSH Rule %d: recorder=%v but enforceRecorder=false", i+1, rule.Recorder))
			}
		}
	}

	if len(rulesNotEnforced) > 0 {
		finding.Pass = false
		finding.Details = rulesNotEnforced
		finding.Description = fmt.Sprintf("Found %d SSH rule(s) with recording but without enforceRecorder:true. Sessions can bypass recording if recorders are unavailable.", len(rulesNotEnforced))

		// Build fixable items for enabling enforceRecorder
		var fixableItems []types.FixableItem
		for i, rule := range policy.SSH {
			if len(rule.Recorder) > 0 && !rule.EnforceRecorder {
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          fmt.Sprintf("ssh-rule-%d", i),
					Name:        fmt.Sprintf("SSH Rule %d", i+1),
					Description: fmt.Sprintf("recorder=%v, dst=%v", rule.Recorder, rule.Dst),
				})
			}
		}

		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Add "enforceRecorder": true to SSH rules. Example:
  {"action": "accept", "src": ["group:dev"], "dst": ["tag:server"],
   "users": ["autogroup:nonroot"], "recorder": ["tag:recorder"],
   "enforceRecorder": true}`,
			AdminURL: "https://login.tailscale.com/admin/acls",
			DocURL:   "https://tailscale.com/kb/1246/tailscale-ssh-session-recording",
		}
	} else if len(rulesWithRecording) == 0 && len(policy.SSH) > 0 {
		finding.Pass = false
		finding.Description = "No SSH rules have session recording configured. Consider enabling recording for compliance and security."
	}

	return finding
}

// hasCheckMode returns true if the SSH rule requires re-authentication via check mode
func hasCheckMode(rule SSHRule) bool {
	// Check mode is enabled if:
	// 1. action is "check", OR
	// 2. checkPeriod is set (even with action: accept)
	return rule.Action == "check" || rule.CheckPeriod != ""
}

// isSensitiveDestination returns true if any destination looks like a sensitive/production target
func isSensitiveDestination(destinations []string) bool {
	sensitivePatterns := []string{
		"prod", "production", "prd",
		"sensitive", "critical", "secure",
		"database", "db", "mysql", "postgres", "mongo", "redis",
		"vault", "secret", "key",
		"payment", "billing", "finance",
		"pci", "hipaa", "sox",
	}

	for _, dst := range destinations {
		dstLower := strings.ToLower(dst)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(dstLower, pattern) {
				return true
			}
		}
	}
	return false
}

// isBroadSource returns true if source grants wide access
func isBroadSource(sources []string) bool {
	broadPatterns := []string{
		"*",
		"autogroup:member",
		"autogroup:tagged",
	}

	for _, src := range sources {
		for _, pattern := range broadPatterns {
			if src == pattern {
				return true
			}
		}
	}
	return false
}

// isBroadDestination returns true if destination grants access to many devices
func isBroadDestination(destinations []string) bool {
	broadPatterns := []string{
		"*",
		"autogroup:tagged", // all tagged devices
	}

	for _, dst := range destinations {
		for _, pattern := range broadPatterns {
			if dst == pattern {
				return true
			}
		}
	}
	return false
}

func (s *SSHAuditor) checkRootAccessSecurity(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "SSH-002",
		Title:       "High-risk SSH access without check mode",
		Severity:    types.Medium,
		Category:    types.SSHSecurity,
		Description: "SSH check mode requires re-authentication through your IdP before connecting, adding an extra security layer for sensitive access.",
		Remediation: "Use check mode (action: check or checkPeriod) for: root access, production servers, sensitive infrastructure, and rules with broad source access.",
		Source:      "https://tailscale.com/kb/1193/tailscale-ssh",
		Pass:        true,
	}

	type riskyRule struct {
		index   int
		reasons []string
		rule    SSHRule
	}

	var riskyRules []riskyRule

	for i, rule := range policy.SSH {
		// Skip rules that already have check mode
		if hasCheckMode(rule) {
			continue
		}

		// Skip non-accept rules (deny, etc.)
		if rule.Action != "accept" {
			continue
		}

		var reasons []string

		// Check 1: Root access
		for _, user := range rule.Users {
			if user == "root" {
				reasons = append(reasons, "root user access")
				break
			}
		}

		// Check 2: Sensitive destinations
		if isSensitiveDestination(rule.Dst) {
			reasons = append(reasons, "sensitive destination tags")
		}

		// Check 3: Broad source access to any destination
		if isBroadSource(rule.Src) {
			reasons = append(reasons, "broad source access ("+strings.Join(rule.Src, ", ")+")")
		}

		// Check 4: Broad destination access (e.g., all tagged devices)
		if isBroadDestination(rule.Dst) {
			reasons = append(reasons, "broad destination access ("+strings.Join(rule.Dst, ", ")+")")
		}

		if len(reasons) > 0 {
			riskyRules = append(riskyRules, riskyRule{
				index:   i,
				reasons: reasons,
				rule:    rule,
			})
		}
	}

	if len(riskyRules) > 0 {
		finding.Pass = false

		// Determine severity based on what's found
		hasRoot := false
		hasSensitive := false
		hasBroadDst := false
		for _, r := range riskyRules {
			for _, reason := range r.reasons {
				if strings.Contains(reason, "root") {
					hasRoot = true
				}
				if strings.Contains(reason, "sensitive") {
					hasSensitive = true
				}
				if strings.Contains(reason, "broad destination") {
					hasBroadDst = true
				}
			}
		}

		if hasRoot || hasSensitive || hasBroadDst {
			finding.Severity = types.High
		}

		// Build details
		var details []string
		for _, r := range riskyRules {
			details = append(details, fmt.Sprintf("SSH Rule %d: %s (src=%v, dst=%v, users=%v)",
				r.index+1, strings.Join(r.reasons, ", "), r.rule.Src, r.rule.Dst, r.rule.Users))
		}
		finding.Details = details
		finding.Description = fmt.Sprintf("Found %d SSH rule(s) allowing high-risk access without check mode re-authentication.", len(riskyRules))

		// Build fixable items
		var fixableItems []types.FixableItem
		for _, r := range riskyRules {
			fixableItems = append(fixableItems, types.FixableItem{
				ID:          fmt.Sprintf("ssh-rule-%d", r.index),
				Name:        fmt.Sprintf("SSH Rule %d", r.index+1),
				Description: strings.Join(r.reasons, ", "),
			})
		}

		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Add check mode for high-risk SSH access. Options:

  1. Use "action": "check" (requires re-auth, default 12h period):
     {"action": "check", "src": ["group:admin"], "dst": ["tag:prod"], "users": ["root"]}

  2. Add "checkPeriod" to existing accept rules:
     {"action": "accept", "src": ["group:dev"], "dst": ["tag:prod"],
      "users": ["deploy"], "checkPeriod": "1h"}

  3. For maximum security, use "checkPeriod": "always" (note: may break automation)`,
			AdminURL: "https://login.tailscale.com/admin/acls",
			DocURL:   "https://tailscale.com/kb/1193/tailscale-ssh",
		}
	}

	return finding
}

func (s *SSHAuditor) checkRecorderUIExposure(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "SSH-003",
		Title:       "Session recorder UI may be exposed",
		Severity:    types.Medium,
		Category:    types.SSHSecurity,
		Description: "If the recorder container web UI is enabled, it exposes recorded SSH sessions to anyone with network access.",
		Remediation: "If using recorder --ui flag, verify ACL restricts port 443 access on recorder node to authorized users only.",
		Source:      "https://tailscale.com/kb/1246/tailscale-ssh-session-recording",
		Pass:        true,
	}

	// Check if any recorders are configured
	var recorderNodes []string
	for _, rule := range policy.SSH {
		for _, recorder := range rule.Recorder {
			if !contains(recorderNodes, recorder) {
				recorderNodes = append(recorderNodes, recorder)
			}
		}
	}

	if len(recorderNodes) > 0 {
		finding.Pass = false
		finding.Severity = types.Informational // Can't determine if UI is actually enabled
		finding.Details = recorderNodes
		finding.Description = fmt.Sprintf("Found %d session recorder node(s). If --ui flag is enabled, verify ACLs restrict access to port 443.", len(recorderNodes))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Add ACL rules to restrict access to recorder UI (port 443)",
			AdminURL:    "https://login.tailscale.com/admin/acls",
			DocURL:      "https://tailscale.com/kb/1246/tailscale-ssh-session-recording",
		}
	}

	return finding
}

func (s *SSHAuditor) checkSSHRulesExist(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "SSH-004",
		Title:       "Tailscale SSH configuration",
		Severity:    types.Informational,
		Category:    types.SSHSecurity,
		Description: "Tailscale SSH rules define who can SSH to which devices and as which users.",
		Remediation: "Review SSH rules regularly. Use check mode for sensitive access. Implement session recording for compliance.",
		Source:      "https://tailscale.com/kb/1193/tailscale-ssh",
		Pass:        true,
	}

	if len(policy.SSH) == 0 {
		finding.Description = "No Tailscale SSH rules are configured. SSH access is managed outside of Tailscale."
		return finding
	}

	var rulesSummary []string
	for i, rule := range policy.SSH {
		rulesSummary = append(rulesSummary, fmt.Sprintf("Rule %d: %s - src=%v dst=%v users=%v", i+1, rule.Action, rule.Src, rule.Dst, rule.Users))
	}

	finding.Pass = false // Just informational, listing rules
	finding.Details = rulesSummary
	finding.Description = fmt.Sprintf("Found %d Tailscale SSH rule(s). Review access patterns and security controls.", len(policy.SSH))
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Review and modify SSH rules in ACL policy",
		AdminURL:    "https://login.tailscale.com/admin/acls",
		DocURL:      "https://tailscale.com/kb/1193/tailscale-ssh",
	}

	return finding
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
