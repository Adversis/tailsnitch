package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// ACLAuditor checks for access control misconfigurations
type ACLAuditor struct {
	client *client.Client
}

// NewACLAuditor creates a new ACL auditor
func NewACLAuditor(c *client.Client) *ACLAuditor {
	return &ACLAuditor{client: c}
}

// ACLPolicy represents the parsed ACL policy for auditing
type ACLPolicy struct {
	ACLs          []ACLRule           `json:"acls"`
	Grants        []Grant             `json:"grants"`
	Groups        map[string][]string `json:"groups"`
	TagOwners     map[string][]string `json:"tagOwners"`
	Hosts         map[string]string   `json:"hosts"`
	Tests         []ACLTest           `json:"tests"`
	SSH           []SSHRule           `json:"ssh"`
	NodeAttrs     []NodeAttr          `json:"nodeAttrs"`
	AutoApprovers *AutoApprovers      `json:"autoApprovers"`
}

// Grant represents a grant-based access rule (newer format)
type Grant struct {
	Src []string  `json:"src"`
	Dst []string  `json:"dst"`
	IP  []string  `json:"ip"`
	App *GrantApp `json:"app"`
}

// GrantApp represents app-specific grant permissions
type GrantApp struct {
	Tailscale map[string][]GrantCapability `json:"tailscale.com/cap"`
}

// GrantCapability represents a capability in a grant
type GrantCapability struct {
	Impersonate *GrantImpersonate `json:"impersonate,omitempty"`
}

// GrantImpersonate represents impersonation settings
type GrantImpersonate struct {
	Groups []string `json:"groups,omitempty"`
}

type ACLRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Proto  string   `json:"proto"`
}

type ACLTest struct {
	Src    string   `json:"src"`
	Accept []string `json:"accept"`
	Deny   []string `json:"deny"`
}

type SSHRule struct {
	Action          string   `json:"action"`
	Src             []string `json:"src"`
	Dst             []string `json:"dst"`
	Users           []string `json:"users"`
	CheckPeriod     string   `json:"checkPeriod"`
	Recorder        []string `json:"recorder"`
	EnforceRecorder bool     `json:"enforceRecorder"`
}

type NodeAttr struct {
	Target []string `json:"target"`
	Attr   []string `json:"attr"`
}

type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"`
	ExitNode []string            `json:"exitNode"`
}

// Audit performs ACL-related security checks
func (a *ACLAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// Get ACL in HuJSON format for raw content
	aclHuJSON, err := a.client.GetACLHuJSON(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACL: %w", err)
	}

	// Parse the ACL - first standardize HuJSON (with comments) to JSON
	var policy ACLPolicy
	standardizedACL, err := hujson.Standardize([]byte(aclHuJSON.ACL))
	if err != nil {
		findings = append(findings, types.Suggestion{
			ID:          "ACL-ERR",
			Title:       "ACL parsing warning",
			Severity:    types.Low,
			Category:    types.AccessControl,
			Description: fmt.Sprintf("Could not standardize HuJSON ACL: %v. Some checks may be incomplete.", err),
			Pass:        true,
		})
	} else if err := json.Unmarshal(standardizedACL, &policy); err != nil {
		findings = append(findings, types.Suggestion{
			ID:          "ACL-ERR",
			Title:       "ACL parsing warning",
			Severity:    types.Low,
			Category:    types.AccessControl,
			Description: fmt.Sprintf("Could not parse ACL JSON: %v. Some checks may be incomplete.", err),
			Pass:        true,
		})
	}

	// ACL-001: Check for default "allow all" policy
	findings = append(findings, a.checkAllowAll(policy, aclHuJSON.ACL))

	// ACL-002: Check for SSH autogroup:nonroot misconfiguration
	findings = append(findings, a.checkSSHNonrootMisconfig(policy))

	// ACL-003: Check for ACL tests
	findings = append(findings, a.checkACLTests(policy))

	// ACL-004: Check for autogroup:member usage
	findings = append(findings, a.checkAutogroupMember(policy))

	// ACL-005: Check auto-approvers configuration
	findings = append(findings, a.checkAutoApprovers(policy))

	// ACL-006: Check tagOwners misconfiguration
	findings = append(findings, a.checkTagOwners(policy))

	// ACL-007: Check for autogroup:danger-all usage
	findings = append(findings, a.checkDangerAll(policy))

	// ACL-008: Check if groups are defined
	findings = append(findings, a.checkGroupsExist(policy))

	// ACL-009: Check grants usage (newer format)
	findings = append(findings, a.checkGrantsUsage(policy, aclHuJSON.ACL))

	// ACL-010: Check Taildrop configuration
	findings = append(findings, a.checkTaildropConfig(policy))

	return findings, nil
}

func (a *ACLAuditor) checkAllowAll(policy ACLPolicy, rawACL string) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-001",
		Title:       "Default 'allow all' policy active (Access Rules)",
		Severity:    types.Critical,
		Category:    types.AccessControl,
		Description: "Your ACL policy may contain overly permissive rules allowing all traffic between devices.",
		Remediation: "Define explicit ACL rules following least privilege principle. Remove rules with src: [\"*\"] or dst: [\"*:*\"]. See https://tailscale.com/kb/1192/acl-samples for examples.",
		Source:      "https://tailscale.com/kb/1192/acl-samples",
		Pass:        true,
	}

	// Check if "acls" or "grants" field is present in the raw ACL
	// Omitting both fields entirely = default "allow all" (CRITICAL)
	// Empty array {"acls": []} with no grants = "deny all" (nothing works, possibly intentional)
	// Using grants = valid access control (don't flag as "denies all")
	hasACLsField := strings.Contains(rawACL, `"acls"`)
	hasGrantsField := strings.Contains(rawACL, `"grants"`)
	hasGrants := len(policy.Grants) > 0

	if !hasACLsField && !hasGrantsField {
		// No "acls" or "grants" field = Tailscale applies default allow-all
		finding.Pass = false
		finding.Description = "Your ACL policy omits both 'acls' and 'grants' fields. Tailscale applies a default 'allow all' policy, granting all devices full access to each other."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Add an 'acls' or 'grants' section with explicit rules to restrict access",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/kb/1192/acl-samples",
		}
		return finding
	}

	if len(policy.ACLs) == 0 && !hasGrants {
		// Empty acls array with no grants = deny all (nothing works)
		// This is secure but may be unintentional - flag as informational
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Title = "ACL policy denies all traffic (Access Rules)"
		finding.Description = "Your ACL policy has an empty 'acls' array and no grants. This denies all traffic between devices. If intentional, this is the most restrictive policy."
		finding.Remediation = "If this is unintentional, add ACL rules or grants to allow required traffic."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Add ACL rules or grants to allow required traffic between devices",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/kb/1192/acl-samples",
		}
		return finding
	}

	// Check for wildcard rules
	var wildcardRules []string
	for i, rule := range policy.ACLs {
		hasWildcardSrc := false
		hasWildcardDst := false

		for _, src := range rule.Src {
			if src == "*" {
				hasWildcardSrc = true
				break
			}
		}

		for _, dst := range rule.Dst {
			if dst == "*:*" || dst == "*" {
				hasWildcardDst = true
				break
			}
		}

		if hasWildcardSrc && hasWildcardDst {
			wildcardRules = append(wildcardRules, fmt.Sprintf("Rule %d: src=%v dst=%v", i+1, rule.Src, rule.Dst))
		}
	}

	if len(wildcardRules) > 0 {
		finding.Pass = false
		finding.Details = wildcardRules
		finding.Description = fmt.Sprintf("Found %d ACL rule(s) with wildcard sources and destinations allowing unrestricted access.", len(wildcardRules))

		// Build fixable items for each wildcard rule
		var fixableItems []types.FixableItem
		for i, rule := range policy.ACLs {
			hasWildcardSrc := false
			hasWildcardDst := false
			for _, src := range rule.Src {
				if src == "*" {
					hasWildcardSrc = true
					break
				}
			}
			for _, dst := range rule.Dst {
				if dst == "*:*" || dst == "*" {
					hasWildcardDst = true
					break
				}
			}
			if hasWildcardSrc && hasWildcardDst {
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          fmt.Sprintf("rule-%d", i),
					Name:        fmt.Sprintf("ACL Rule %d", i+1),
					Description: fmt.Sprintf("src=%v dst=%v", rule.Src, rule.Dst),
				})
			}
		}

		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Replace wildcard rules with specific ACLs. Example - replace:
  {"action": "accept", "src": ["*"], "dst": ["*:*"]}
With specific rules like:
  {"action": "accept", "src": ["group:employees"], "dst": ["tag:server:22,443"]}`,
			AdminURL: "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:   "https://tailscale.com/kb/1192/acl-samples",
			Items:    fixableItems,
		}
	}

	return finding
}

func (a *ACLAuditor) checkSSHNonrootMisconfig(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-002",
		Title:       "SSH autogroup:nonroot misconfiguration (Tailscale SSH)",
		Severity:    types.Critical,
		Category:    types.AccessControl,
		Description: "SSH rules with autogroup:nonroot users and tagged destinations allow anyone matching src to SSH as ANY non-root user.",
		Remediation: "Replace autogroup:nonroot with explicit usernames when targeting tagged devices. Only use autogroup:nonroot with autogroup:self destinations.",
		Source:      "https://tailscale.com/kb/1193/tailscale-ssh",
		Pass:        true,
	}

	var problematicRules []string
	for i, rule := range policy.SSH {
		hasNonroot := false
		hasTagDst := false

		for _, user := range rule.Users {
			if user == "autogroup:nonroot" {
				hasNonroot = true
				break
			}
		}

		for _, dst := range rule.Dst {
			if strings.HasPrefix(dst, "tag:") {
				hasTagDst = true
				break
			}
		}

		if hasNonroot && hasTagDst {
			problematicRules = append(problematicRules, fmt.Sprintf("SSH Rule %d: dst=%v users=%v", i+1, rule.Dst, rule.Users))
		}
	}

	if len(problematicRules) > 0 {
		finding.Pass = false
		finding.Details = problematicRules
		finding.Description = fmt.Sprintf("Found %d SSH rule(s) with autogroup:nonroot targeting tagged devices. This allows SSH as any non-root user.", len(problematicRules))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Update SSH rules to use explicit usernames instead of autogroup:nonroot",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/ssh",
			DocURL:      "https://tailscale.com/kb/1193/tailscale-ssh",
		}
	}

	return finding
}

func (a *ACLAuditor) checkACLTests(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-003",
		Title:       "No ACL tests defined (Tests)",
		Severity:    types.Low,
		Category:    types.AccessControl,
		Description: "ACL tests help validate access controls and prevent accidental permission changes.",
		Remediation: "Add a 'tests' section to your ACL policy with both 'accept' and 'deny' assertions. Tests are validated when policies update.",
		Source:      "https://tailscale.com/kb/1196/security-hardening",
		Pass:        true,
	}

	if len(policy.Tests) == 0 {
		finding.Pass = false
		finding.Description = "No ACL tests are defined. Without tests, policy changes could accidentally revoke permissions or expose systems."
		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Add a "tests" section to your ACL. Example:
  "tests": [
    {"src": "user@example.com", "accept": ["server:22"]},
    {"src": "user@example.com", "deny": ["prod-db:5432"]}
  ]`,
			AdminURL: "https://login.tailscale.com/admin/acls/visual/tests",
			DocURL:   "https://tailscale.com/kb/1196/security-hardening",
		}
		return finding
	}

	// Check if tests include both accept and deny assertions
	hasAccept := false
	hasDeny := false
	for _, test := range policy.Tests {
		if len(test.Accept) > 0 {
			hasAccept = true
		}
		if len(test.Deny) > 0 {
			hasDeny = true
		}
	}

	if !hasAccept || !hasDeny {
		finding.Pass = false
		finding.Severity = types.Low
		var missing []string
		if !hasAccept {
			missing = append(missing, "accept assertions")
		}
		if !hasDeny {
			missing = append(missing, "deny assertions")
		}
		finding.Description = fmt.Sprintf("ACL tests exist but are missing %s. Include both accept and deny tests for comprehensive coverage.", strings.Join(missing, " and "))
		finding.Details = fmt.Sprintf("%d tests defined", len(policy.Tests))
	}

	return finding
}

func (a *ACLAuditor) checkAutogroupMember(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-004",
		Title:       "autogroup:member grants access to external users (Access Rules)",
		Severity:    types.Medium,
		Category:    types.AccessControl,
		Description: "Using autogroup:member in ACLs also grants access to external invited users with shared devices.",
		Remediation: "Review all rules using autogroup:member. List externally shared devices and verify external users should have that access.",
		Source:      "https://tailscale.com/kb/1337/policy-syntax",
		Pass:        true,
	}

	var rulesWithMember []string
	for i, rule := range policy.ACLs {
		for _, src := range rule.Src {
			if src == "autogroup:member" {
				rulesWithMember = append(rulesWithMember, fmt.Sprintf("ACL Rule %d: src includes autogroup:member", i+1))
				break
			}
		}
	}

	if len(rulesWithMember) > 0 {
		finding.Pass = false
		finding.Details = rulesWithMember
		finding.Description = fmt.Sprintf("Found %d ACL rule(s) using autogroup:member. This includes external invited users if destination devices are shared with them.", len(rulesWithMember))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review ACL rules using autogroup:member and consider using specific groups",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/kb/1337/policy-syntax",
		}
	}

	return finding
}

func (a *ACLAuditor) checkAutoApprovers(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-005",
		Title:       "AutoApprovers bypass administrative route approval (Auto Approvers)",
		Severity:    types.Medium,
		Category:    types.AccessControl,
		Description: "AutoApprovers can automatically approve subnet routes and exit nodes without admin intervention.",
		Remediation: "Review autoApprovers.routes and autoApprovers.exitNode. Use specific tags rather than broad groups. Ensure unauthorized users cannot auto-approve sensitive routes.",
		Source:      "https://tailscale.com/kb/1337/policy-syntax",
		Pass:        true,
	}

	if policy.AutoApprovers == nil {
		return finding
	}

	var issues []string

	// Check for broadly configured auto-approvers
	for route, approvers := range policy.AutoApprovers.Routes {
		for _, approver := range approvers {
			if approver == "*" || approver == "autogroup:member" {
				issues = append(issues, fmt.Sprintf("Route %s: broad approver '%s'", route, approver))
			}
		}
	}

	for _, approver := range policy.AutoApprovers.ExitNode {
		if approver == "*" || approver == "autogroup:member" {
			issues = append(issues, fmt.Sprintf("ExitNode: broad approver '%s'", approver))
		}
	}

	// Even if not broadly configured, note that auto-approvers exist
	if len(issues) == 0 && (len(policy.AutoApprovers.Routes) > 0 || len(policy.AutoApprovers.ExitNode) > 0) {
		finding.Severity = types.Low
		finding.Pass = false
		finding.Description = "AutoApprovers are configured. While not broadly permissive, ensure this aligns with your security model."
		var details []string
		for route, approvers := range policy.AutoApprovers.Routes {
			details = append(details, fmt.Sprintf("Route %s: %v", route, approvers))
		}
		if len(policy.AutoApprovers.ExitNode) > 0 {
			details = append(details, fmt.Sprintf("ExitNode: %v", policy.AutoApprovers.ExitNode))
		}
		finding.Details = details
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review autoApprovers configuration in ACL policy",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/auto-approvers",
			DocURL:      "https://tailscale.com/kb/1337/policy-syntax",
		}
		return finding
	}

	if len(issues) > 0 {
		finding.Pass = false
		finding.Details = issues
		finding.Description = fmt.Sprintf("Found %d overly permissive auto-approver configuration(s).", len(issues))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Restrict autoApprovers to specific tags instead of broad groups",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/auto-approvers",
			DocURL:      "https://tailscale.com/kb/1337/policy-syntax",
		}
	}

	return finding
}

func (a *ACLAuditor) checkTagOwners(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-006",
		Title:       "tagOwners grants tag privileges too broadly (Tag Owners)",
		Severity:    types.Critical,
		Category:    types.AccessControl,
		Description: "tagOwners controls who can apply tags to devices. Overly permissive settings allow privilege escalation.",
		Remediation: "Restrict tagOwners to autogroup:admin or specific security groups. Never use autogroup:member for production tags.",
		Source:      "https://tailscale.com/kb/1068/tags",
		Pass:        true,
	}

	var issues []string
	for tag, owners := range policy.TagOwners {
		for _, owner := range owners {
			// Check for overly broad tag ownership
			if owner == "autogroup:member" || owner == "*" {
				issues = append(issues, fmt.Sprintf("%s: owned by '%s' - any member can tag devices and gain tag-based ACL access", tag, owner))
			}
		}
	}

	if len(issues) > 0 {
		finding.Pass = false
		finding.Details = issues
		finding.Description = fmt.Sprintf("Found %d tag(s) with overly permissive ownership. Any tailnet member can apply these tags to gain elevated access.", len(issues))
		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Restrict tagOwners to admins. Example - replace:
  "tagOwners": {"tag:prod": ["autogroup:member"]}
With:
  "tagOwners": {"tag:prod": ["autogroup:admin"]}`,
			AdminURL: "https://login.tailscale.com/admin/acls/visual/tag-owners",
			DocURL:   "https://tailscale.com/kb/1068/tags",
		}
	}

	return finding
}

func (a *ACLAuditor) checkDangerAll(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-007",
		Title:       "autogroup:danger-all grants access to everyone (Access Rules)",
		Severity:    types.Critical,
		Category:    types.AccessControl,
		Description: "autogroup:danger-all matches ALL users and devices including external users, shared nodes, and tagged devices. This is the most permissive autogroup.",
		Remediation: "Replace autogroup:danger-all with specific groups, tags, or autogroup:member. Only use danger-all if you truly need to grant access to external/shared users.",
		Source:      "https://tailscale.com/kb/1337/policy-syntax",
		Pass:        true,
	}

	const dangerAll = "autogroup:danger-all"
	var issues []string

	// Check ACL rules
	for i, rule := range policy.ACLs {
		for _, src := range rule.Src {
			if src == dangerAll {
				issues = append(issues, fmt.Sprintf("ACL Rule %d: src includes %s", i+1, dangerAll))
			}
		}
		for _, dst := range rule.Dst {
			if strings.HasPrefix(dst, dangerAll) {
				issues = append(issues, fmt.Sprintf("ACL Rule %d: dst includes %s", i+1, dst))
			}
		}
	}

	// Check SSH rules
	for i, rule := range policy.SSH {
		for _, src := range rule.Src {
			if src == dangerAll {
				issues = append(issues, fmt.Sprintf("SSH Rule %d: src includes %s", i+1, dangerAll))
			}
		}
		for _, dst := range rule.Dst {
			if dst == dangerAll {
				issues = append(issues, fmt.Sprintf("SSH Rule %d: dst includes %s", i+1, dangerAll))
			}
		}
	}

	// Check tagOwners
	for tag, owners := range policy.TagOwners {
		for _, owner := range owners {
			if owner == dangerAll {
				issues = append(issues, fmt.Sprintf("tagOwners %s: owned by %s", tag, dangerAll))
			}
		}
	}

	// Check autoApprovers
	if policy.AutoApprovers != nil {
		for route, approvers := range policy.AutoApprovers.Routes {
			for _, approver := range approvers {
				if approver == dangerAll {
					issues = append(issues, fmt.Sprintf("autoApprovers route %s: approved by %s", route, dangerAll))
				}
			}
		}
		for _, approver := range policy.AutoApprovers.ExitNode {
			if approver == dangerAll {
				issues = append(issues, fmt.Sprintf("autoApprovers exitNode: approved by %s", dangerAll))
			}
		}
	}

	if len(issues) > 0 {
		finding.Pass = false
		finding.Details = issues
		finding.Description = fmt.Sprintf("Found %d use(s) of autogroup:danger-all. This grants access to ALL users including external/shared users - more permissive than autogroup:member.", len(issues))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Replace autogroup:danger-all with more restrictive groups or autogroup:member",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/kb/1337/policy-syntax",
		}
	}

	return finding
}

func (a *ACLAuditor) checkGroupsExist(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-008",
		Title:       "No groups defined in ACL policy (Groups)",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "Groups allow logical organization of users for ACL rules, making policy management easier and less error-prone.",
		Remediation: "Define groups in your ACL policy to organize users logically. Example: \"groups\": {\"group:engineers\": [\"user@example.com\"]}",
		Source:      "https://tailscale.com/kb/1337/policy-syntax",
		Pass:        true,
	}

	if len(policy.Groups) == 0 {
		finding.Pass = false
		finding.Description = "No groups are defined in the ACL policy. Using groups makes ACL management easier and reduces the risk of misconfiguration when user membership changes."
		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: `Add a "groups" section to organize users. Example:
  "groups": {
    "group:engineers": ["alice@example.com", "bob@example.com"],
    "group:admins": ["admin@example.com"]
  }`,
			AdminURL: "https://login.tailscale.com/admin/acls/visual/groups",
			DocURL:   "https://tailscale.com/kb/1337/policy-syntax",
		}
	} else {
		finding.Description = fmt.Sprintf("%d group(s) defined for logical user organization.", len(policy.Groups))
		finding.Details = func() []string {
			var groups []string
			for name, members := range policy.Groups {
				groups = append(groups, fmt.Sprintf("%s: %d member(s)", name, len(members)))
			}
			return groups
		}()
	}

	return finding
}

func (a *ACLAuditor) checkGrantsUsage(policy ACLPolicy, rawACL string) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-009",
		Title:       "Using legacy ACLs instead of grants (Access Rules)",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "Grants are a newer, more flexible format for access control that supports app-level permissions and better composability.",
		Remediation: "Consider migrating from legacy ACLs to grants for new policies. Grants support additional capabilities like app connectors.",
		Source:      "https://tailscale.com/kb/1324/grants",
		Pass:        true,
	}

	hasGrants := len(policy.Grants) > 0 || strings.Contains(rawACL, `"grants"`)
	hasLegacyACLs := len(policy.ACLs) > 0

	if !hasGrants && hasLegacyACLs {
		// Pass=true since using legacy ACLs isn't a security issue, just informational
		finding.Description = "Policy uses legacy ACL format only. The grants format offers more flexibility and is recommended for new configurations."
		finding.Details = fmt.Sprintf("Using %d legacy ACL rule(s), 0 grants", len(policy.ACLs))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Consider using grants for new access rules. Legacy ACLs continue to work but grants offer more features.",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/kb/1324/grants",
		}
	} else if hasGrants {
		finding.Description = "Policy uses the grants format for access control."
		if hasLegacyACLs {
			finding.Details = fmt.Sprintf("%d grant(s) and %d legacy ACL rule(s) defined", len(policy.Grants), len(policy.ACLs))
		} else {
			finding.Details = fmt.Sprintf("%d grant(s) defined", len(policy.Grants))
		}
	}

	return finding
}

func (a *ACLAuditor) checkTaildropConfig(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-010",
		Title:       "Taildrop file sharing configuration (Node Attributes)",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "Taildrop allows direct file transfer between tailnet devices.",
		Remediation: "If Taildrop poses a data exfiltration risk, disable it via nodeAttrs.",
		Source:      "https://tailscale.com/kb/1106/taildrop",
		Pass:        true, // Informational only - default Taildrop enabled is not a misconfiguration
	}

	var taildropConfigs []string
	taildropDisabled := false

	for _, attr := range policy.NodeAttrs {
		for _, a := range attr.Attr {
			lowerAttr := strings.ToLower(a)
			if strings.Contains(lowerAttr, "taildrop") {
				if strings.Contains(lowerAttr, "false") || strings.Contains(a, "!") {
					taildropDisabled = true
					taildropConfigs = append(taildropConfigs, fmt.Sprintf("Taildrop disabled for: %v", attr.Target))
				} else {
					taildropConfigs = append(taildropConfigs, fmt.Sprintf("Taildrop enabled for: %v", attr.Target))
				}
			}
		}
	}

	if len(taildropConfigs) == 0 {
		// No explicit config means Taildrop uses default (enabled for all) - this is normal
		finding.Description = "Taildrop uses default configuration (enabled for all devices)."
		finding.Details = "Default: Taildrop enabled for all devices"
	} else {
		finding.Details = taildropConfigs
		if taildropDisabled {
			finding.Description = "Taildrop has been explicitly configured with restrictions."
		} else {
			finding.Description = "Taildrop is explicitly configured."
		}
	}

	return finding
}
