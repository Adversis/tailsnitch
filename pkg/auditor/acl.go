package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

// Audit performs ACL-related security checks. devices and devErr are the
// tailnet's device inventory, pre-fetched once in Auditor.Run and shared with
// the Auth auditor; ACL-011 consumes them to compute tag reach.
func (a *ACLAuditor) Audit(ctx context.Context, devices []*client.Device, devErr error, ignoreList *types.IgnoreList) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// Get ACL in HuJSON format for raw content
	aclHuJSON, err := a.client.GetACLHuJSON(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACL: %w", err)
	}

	// Parse the ACL - first standardize HuJSON (with comments) to JSON
	var policy ACLPolicy
	var fields policyFields
	var parseErr error
	standardizedACL, err := hujson.Standardize([]byte(aclHuJSON.HuJSON))
	if err != nil {
		parseErr = fmt.Errorf("could not standardize HuJSON ACL: %w", err)
	} else if err := json.Unmarshal(standardizedACL, &policy); err != nil {
		parseErr = fmt.Errorf("could not parse ACL JSON: %w", err)
	} else {
		fields = newPolicyFields(standardizedACL)
	}

	// A policy that did not parse leaves every check below with a zero-valued
	// document to read, which they would report as a clean result. Say the
	// checks did not run instead.
	if parseErr != nil {
		findings = append(findings, types.Suggestion{
			ID:          "ACL-ERR",
			Title:       "ACL policy could not be parsed",
			Severity:    types.Medium,
			Category:    types.AccessControl,
			Description: fmt.Sprintf("%v. The access rule checks were not evaluated.", parseErr),
			Remediation: "Correct the tailnet policy file syntax, then re-run the audit.",
			Pass:        false,
		})

		// ACL-001 reports the unparsed policy in its own terms.
		findings = append(findings, a.checkAllowAll(policy, fields))
		for _, id := range aclPolicyChecks {
			findings = append(findings, types.NotEvaluated(id,
				"The tailnet policy file could not be parsed. See ACL-ERR for the parse error."))
		}
		return findings, nil
	}

	// ACL-001: Check for default "allow all" policy
	findings = append(findings, a.checkAllowAll(policy, fields))

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
	findings = append(findings, a.checkGrantsUsage(policy, fields))

	// ACL-010: Check Taildrop configuration
	findings = append(findings, a.checkTaildropConfig(policy))

	// ACL-011: Tag reach. This needs both the device inventory and the auth
	// keys that can mint tags; if the device inventory itself could not be
	// read, none of the reach it would report can be trusted.
	keys, keysErr := a.client.GetAuthKeys(ctx)
	if devErr != nil {
		findings = append(findings, types.NotEvaluated("ACL-011",
			fmt.Sprintf("The device inventory could not be read: %v", devErr)))
	} else {
		findings = append(findings, a.checkTagReach(policy, devices, keys, keysErr, ignoreList))
	}

	return findings, nil
}

// aclPolicyChecks are the access rule checks that read the parsed policy
// document. ACL-001 is absent because it reports an unparsed policy itself.
var aclPolicyChecks = []string{
	"ACL-002", "ACL-003", "ACL-004", "ACL-005", "ACL-006",
	"ACL-007", "ACL-008", "ACL-009", "ACL-010", "ACL-011",
}

// policyFields records which top-level keys the tailnet policy file defines.
//
// Presence has to be read from the parsed document rather than by searching the
// raw HuJSON: comments are part of that text, so a policy remarking that it has
// "no \"acls\" section" would defeat a substring test for the key.
type policyFields struct {
	present map[string]bool
	parsed  bool
}

func newPolicyFields(standardizedACL []byte) policyFields {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(standardizedACL, &raw); err != nil {
		return policyFields{}
	}

	present := make(map[string]bool, len(raw))
	for key := range raw {
		present[key] = true
	}
	return policyFields{present: present, parsed: true}
}

// has reports whether the policy defines the given top-level key. It reports
// false when the policy could not be parsed, so callers should check parsed
// before drawing a conclusion from an absent key.
func (f policyFields) has(key string) bool { return f.present[key] }

func (a *ACLAuditor) checkAllowAll(policy ACLPolicy, fields policyFields) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-001",
		Title:       "Default 'allow all' policy active (Access Rules)",
		Severity:    types.Critical,
		Category:    types.AccessControl,
		Description: "Your ACL policy may contain overly permissive rules allowing all traffic between devices.",
		Remediation: "Define explicit ACL rules following least privilege principle. Remove rules with src: [\"*\"] or dst: [\"*:*\"]. See https://tailscale.com/docs/reference/examples/acls for examples.",
		Source:      "https://tailscale.com/docs/reference/examples/acls",
		Pass:        true,
	}

	// Omitting both "acls" and "grants" leaves Tailscale's default allow-all
	// policy in force. An empty "acls" with no grants denies everything, which
	// is secure but often unintentional. A policy using grants is neither.
	if !fields.parsed {
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Description = "The tailnet policy file could not be parsed, so its access rules were not evaluated."
		finding.Details = "See ACL-ERR for the parse error."
		return finding
	}

	hasACLsField := fields.has("acls")
	hasGrantsField := fields.has("grants")
	hasGrants := len(policy.Grants) > 0

	if !hasACLsField && !hasGrantsField {
		// No "acls" or "grants" field = Tailscale applies default allow-all
		finding.Pass = false
		finding.Description = "Your ACL policy omits both 'acls' and 'grants' fields. Tailscale applies a default 'allow all' policy, granting all devices full access to each other."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Add an 'acls' or 'grants' section with explicit rules to restrict access",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/docs/reference/examples/acls",
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
			DocURL:      "https://tailscale.com/docs/reference/examples/acls",
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
			DocURL:   "https://tailscale.com/docs/reference/examples/acls",
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
		Source:      "https://tailscale.com/docs/features/tailscale-ssh",
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
			DocURL:      "https://tailscale.com/docs/features/tailscale-ssh",
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
		Source:      "https://tailscale.com/docs/reference/best-practices/security",
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
			DocURL:   "https://tailscale.com/docs/reference/best-practices/security",
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
		Source:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
			DocURL:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
		Source:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
			DocURL:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
			DocURL:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
		Source:      "https://tailscale.com/docs/features/tags",
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
			DocURL:   "https://tailscale.com/docs/features/tags",
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
		Source:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
			DocURL:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
		Source:      "https://tailscale.com/docs/reference/syntax/policy-file",
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
			DocURL:   "https://tailscale.com/docs/reference/syntax/policy-file",
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

func (a *ACLAuditor) checkGrantsUsage(policy ACLPolicy, fields policyFields) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-009",
		Title:       "Using legacy ACLs instead of grants (Access Rules)",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "Grants are a newer, more flexible format for access control that supports app-level permissions and better composability.",
		Remediation: "Consider migrating from legacy ACLs to grants for new policies. Grants support additional capabilities like app connectors.",
		Source:      "https://tailscale.com/docs/features/access-control/grants",
		Pass:        true,
	}

	hasGrants := len(policy.Grants) > 0 || fields.has("grants")
	hasLegacyACLs := len(policy.ACLs) > 0

	if !hasGrants && hasLegacyACLs {
		// Pass=true since using legacy ACLs isn't a security issue, just informational
		finding.Description = "Policy uses legacy ACL format only. The grants format offers more flexibility and is recommended for new configurations."
		finding.Details = fmt.Sprintf("Using %d legacy ACL rule(s), 0 grants", len(policy.ACLs))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Consider using grants for new access rules. Legacy ACLs continue to work but grants offer more features.",
			AdminURL:    "https://login.tailscale.com/admin/acls/visual/general-access-rules",
			DocURL:      "https://tailscale.com/docs/features/access-control/grants",
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
		Source:      "https://tailscale.com/docs/features/taildrop",
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

// mintableTags returns the tags any live auth key can assign to a new node.
func mintableTags(keys []client.Key) map[string]bool {
	tags := make(map[string]bool)
	for _, key := range keys {
		if !key.Expires.IsZero() && time.Until(key.Expires) < 0 {
			continue
		}
		for _, tag := range key.Capabilities.Devices.Create.Tags {
			tags[tag] = true
		}
	}
	return tags
}

// reusablyMintableTags returns the tags a reusable auth key can assign. A
// reusable key keeps working after it leaks, which is a property of the
// credential rather than a judgement about the environment, so it may raise
// severity.
func reusablyMintableTags(keys []client.Key) map[string]bool {
	tags := make(map[string]bool)
	for _, key := range keys {
		if !key.Capabilities.Devices.Create.Reusable {
			continue
		}
		if !key.Expires.IsZero() && time.Until(key.Expires) < 0 {
			continue
		}
		for _, tag := range key.Capabilities.Devices.Create.Tags {
			tags[tag] = true
		}
	}
	return tags
}

// describeReach renders one tag's reach as report lines.
func describeReach(r Reach, mintable, reusable bool) []string {
	var lines []string
	switch {
	case r.Wildcard:
		lines = append(lines, fmt.Sprintf("%s: reaches every device in the tailnet (a rule grants *:*)", r.Tag))
	default:
		allPortsCount := 0
		for _, d := range r.Devices {
			if d.AllPorts {
				allPortsCount++
			}
		}
		lines = append(lines, fmt.Sprintf("%s: reaches %d of %d devices, %d of them on all ports",
			r.Tag, len(r.Devices), r.TotalDevices, allPortsCount))
	}
	for _, routed := range r.Routed {
		lines = append(lines, fmt.Sprintf("    routes to %s via %s", routed.CIDR, routed.Router.Name))
	}
	for _, e := range r.Egress {
		lines = append(lines, fmt.Sprintf("    egress to the internet via exit node %s", e.Name))
	}
	for _, u := range r.Unresolved {
		lines = append(lines, fmt.Sprintf("    unresolved destination, not counted: %s", u))
	}
	if mintable {
		how := "an auth key"
		if reusable {
			how = "a reusable auth key"
		}
		lines = append(lines, fmt.Sprintf("    %s can assign this tag", how))
	}
	return lines
}

// checkTagReach reports what every tag in the policy can reach, and fails
// only when a tag an auth key can actually mint crosses a trust boundary: it
// reaches every device, a routed subnet, or internet egress. A tag's device
// count never sets severity - the tool has no way to know whether reaching
// 47 devices is correct for that tag or catastrophic. Reusability of the
// minting key is a structural property of the credential and may raise
// severity from Medium to High.
func (a *ACLAuditor) checkTagReach(policy ACLPolicy, devices []*client.Device, keys []client.Key, keysErr error, ignoreList *types.IgnoreList) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-011",
		Title:       "Tag reach",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "What a tag can reach is what a node carrying that tag can reach. A tag an auth key can assign is reachable by anyone holding that key.",
		Remediation: "Narrow the rules that name this tag as a source, or replace the auth key that assigns it with a trust credential so there is no key to steal.",
		Source:      "https://tailscale.com/docs/features/tags",
		Pass:        true,
	}

	reaches := AllTagReach(policy, devices)
	if len(reaches) == 0 {
		finding.Description = "The policy defines no tags."
		return finding
	}

	mintable := mintableTags(keys)
	reusable := reusablyMintableTags(keys)

	var details []string
	var offenders []string
	var suppressedOffenders []string
	worst := types.Informational

	for _, r := range reaches {
		isMintable := keysErr == nil && mintable[r.Tag]
		isReusable := keysErr == nil && reusable[r.Tag]

		// A tag named in the ignore file is left out of the reach table
		// entirely, whether or not it turns out to be an offender below.
		tagIgnored := ignoreList.IsItemIgnored("ACL-011", r.Tag)
		if !tagIgnored {
			details = append(details, describeReach(r, isMintable, isReusable)...)
		}

		if !isMintable {
			continue
		}
		crossings := []string{}
		if r.Wildcard {
			crossings = append(crossings, "reaches every device")
		}
		if len(r.Routed) > 0 {
			crossings = append(crossings, "routes past the tailnet edge")
		}
		if len(r.Egress) > 0 {
			crossings = append(crossings, "carries internet egress")
		}
		if len(crossings) == 0 {
			continue
		}
		entry := fmt.Sprintf("%s: %s", r.Tag, strings.Join(crossings, ", "))
		if tagIgnored {
			// Suppressed: does not count toward severity or Pass. It is
			// still tracked separately (not silently dropped) so the "every
			// offender suppressed" case below can be told apart from a
			// tailnet that genuinely has nothing crossing a boundary.
			suppressedOffenders = append(suppressedOffenders, entry)
			continue
		}
		offenders = append(offenders, entry)
		sev := types.Medium
		if isReusable {
			sev = types.High
		}
		if sev.Order() < worst.Order() {
			worst = sev
		}
	}

	if keysErr != nil {
		finding.Pass = false
		finding.Description = "Tag reach was computed, but the auth keys could not be read, so it is unknown which tags a key can assign."
		finding.Remediation = "Grant the credential the auth_keys:read scope, then re-run the audit to determine which tags an auth key can assign."
		finding.Details = append([]string{
			fmt.Sprintf("Could not read auth keys: %v", keysErr),
			"MANUAL CHECK REQUIRED: confirm which of these tags an auth key can assign.",
		}, details...)
		return finding
	}

	if len(offenders) == 0 && len(suppressedOffenders) == 0 {
		finding.Details = details
		finding.Description = fmt.Sprintf("Reach computed for %d tag(s). No tag that an auth key can assign crosses a trust boundary.", len(reaches))
		return finding
	}

	if len(offenders) == 0 {
		// Every tag that crossed a boundary was suppressed by the ignore
		// file. Suppressing the last offender must not read as a satisfied
		// control: the finding stays, at Informational severity and with
		// Pass still false, as evidence that something was suppressed
		// rather than disappearing into a clean result.
		finding.Pass = false
		finding.Severity = types.Informational
		finding.Description = fmt.Sprintf(
			"%d tag(s) that an auth key can assign crossed a trust boundary; all were suppressed by the ignore file.",
			len(suppressedOffenders))
		suppressedNote := []string{fmt.Sprintf("%d tag(s) crossing a boundary were suppressed by the ignore file.", len(suppressedOffenders))}
		if len(details) > 0 {
			suppressedNote = append(append(suppressedNote, "", "Reach for every unsuppressed tag:"), details...)
		}
		finding.Details = suppressedNote
		return finding
	}

	finding.Pass = false
	finding.Severity = worst
	finding.Description = fmt.Sprintf("%d tag(s) that an auth key can assign cross a trust boundary.", len(offenders))
	boundaryLines := append([]string{"Tags crossing a boundary:"}, offenders...)
	if len(suppressedOffenders) > 0 {
		boundaryLines = append(boundaryLines, fmt.Sprintf("(%d additional tag(s) crossing a boundary suppressed by the ignore file)", len(suppressedOffenders)))
	}
	finding.Details = append(append(boundaryLines, "", "Reach for every tag:"), details...)
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Narrow these tags' rules, or replace the auth key that assigns them",
		AdminURL:    "https://login.tailscale.com/admin/acls",
		DocURL:      "https://tailscale.com/docs/features/tags",
	}
	return finding
}
