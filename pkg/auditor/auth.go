package auditor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// AuthAuditor checks for authentication and key management issues
type AuthAuditor struct {
	client *client.Client

	// policy, policyParsed and devices are set by Audit from its parameters so
	// the check* methods can annotate a flagged key with what its tags reach.
	// policyParsed being false, or devices being empty, means reach could not
	// be computed and no annotation is added - see reachNote.
	policy       ACLPolicy
	policyParsed bool
	devices      []*client.Device
}

// authKeyChecks are the checks that read the tailnet's machine auth keys.
var authKeyChecks = []string{"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006"}

// NewAuthAuditor creates a new auth auditor
func NewAuthAuditor(c *client.Client) *AuthAuditor {
	return &AuthAuditor{client: c}
}

// keyInfo holds parsed auth key information for auditing
type keyInfo struct {
	ID            string
	Description   string
	Reusable      bool
	Preauthorized bool
	Ephemeral     bool
	Tags          []string
	DaysToExpiry  int
	Created       time.Time
	Expires       time.Time
}

// newKeyInfo projects an API key into the fields the auth checks care about.
func newKeyInfo(key client.Key) keyInfo {
	info := keyInfo{
		ID:            key.ID,
		Description:   key.Description,
		Created:       key.Created,
		Expires:       key.Expires,
		Reusable:      key.Capabilities.Devices.Create.Reusable,
		Preauthorized: key.Capabilities.Devices.Create.Preauthorized,
		Ephemeral:     key.Capabilities.Devices.Create.Ephemeral,
		Tags:          key.Capabilities.Devices.Create.Tags,
	}
	if !key.Expires.IsZero() {
		info.DaysToExpiry = int(time.Until(key.Expires).Hours() / 24)
	}
	return info
}

// label returns a human-readable identifier for a key, preferring its
// description over the opaque key ID.
func (k keyInfo) label() string {
	if k.Description != "" {
		return fmt.Sprintf("%s (%s)", k.Description, k.ID)
	}
	return k.ID
}

// reachNote describes what a key's tags reach, for readers deciding whether a
// flagged key matters. It returns an empty string when reach could not be
// computed, so a figure is never printed that was not derived from real data.
func reachNote(tags []string, policy ACLPolicy, policyParsed bool, devices []*client.Device) string {
	if !policyParsed || len(devices) == 0 || len(tags) == 0 {
		return ""
	}
	var parts []string
	for _, tag := range tags {
		r := ComputeReach(tag, policy, devices)
		switch {
		case r.Wildcard:
			parts = append(parts, fmt.Sprintf("%s reaches every device", tag))
		default:
			part := fmt.Sprintf("%s reaches %d of %d devices", tag, len(r.Devices), r.TotalDevices)
			if len(r.Routed) > 0 {
				part += fmt.Sprintf(" and routes to %s", r.Routed[0].CIDR)
			}
			parts = append(parts, part)
		}
	}
	return "Reach: " + strings.Join(parts, "; ") + " (see ACL-011)"
}

// Audit performs authentication-related security checks. policy and
// policyParsed are the tailnet's pre-fetched ACL policy, and devices is the
// tailnet's device inventory; both are shared from Auditor.Run and stored on
// the auditor so the auth-key findings can be annotated with device reach.
func (a *AuthAuditor) Audit(ctx context.Context, policy ACLPolicy, policyParsed bool, devices []*client.Device) ([]types.Suggestion, error) {
	a.policy = policy
	a.policyParsed = policyParsed
	a.devices = devices

	var findings []types.Suggestion

	// Get the tailnet's machine auth keys. The keys endpoint also returns API
	// access tokens, OAuth clients and federated identities, which have no
	// device-creation capabilities; GetAuthKeys filters those out.
	apiKeys, err := a.client.GetAuthKeys(ctx)
	if err != nil {
		// Auth keys might not be accessible with all credentials. Report the
		// checks as not evaluated rather than passing: they did not run, and a
		// passing finding would be filtered out of the default output and
		// counted as a satisfied control.
		findings = append(findings, types.Suggestion{
			ID:          "AUTH-ERR",
			Title:       "Could not retrieve auth keys",
			Severity:    types.Medium,
			Category:    types.Authentication,
			Description: fmt.Sprintf("Unable to retrieve auth keys: %v. The auth key checks were not evaluated.", err),
			Remediation: "Grant the credential the auth_keys:read scope, then re-run the audit.",
			Pass:        false,
		})
		for _, id := range authKeyChecks {
			findings = append(findings, types.NotEvaluated(id,
				"The tailnet's auth keys could not be read. See AUTH-ERR for the error."))
		}
		return findings, nil
	}

	keys := make([]keyInfo, 0, len(apiKeys))
	for _, key := range apiKeys {
		keys = append(keys, newKeyInfo(key))
	}

	// AUTH-001: Check for reusable auth keys
	findings = append(findings, a.checkReusableKeys(keys))

	// AUTH-002: Check for auth keys with long expiry
	findings = append(findings, a.checkLongExpiryKeys(keys))

	// AUTH-003: Check for pre-authorized auth keys
	findings = append(findings, a.checkPreauthorizedKeys(keys))

	// AUTH-004: Informational - ephemeral key usage
	findings = append(findings, a.checkEphemeralKeyUsage(keys))

	// AUTH-005 and AUTH-006: workload identity federation not in use, and
	// federated identity subject breadth. Federated identities come from the
	// same keys endpoint as auth keys, so a fetch failure here is reported as
	// not-evaluated for both checks, same as an auth key read failure.
	identities, idErr := a.client.GetFederatedIdentities(ctx)
	if idErr != nil {
		findings = append(findings, federationFetchFailed("AUTH-005", idErr))
		findings = append(findings, federationFetchFailed("AUTH-006", idErr))
	} else {
		findings = append(findings, a.checkFederationInUse(keys, identities))
		findings = append(findings, a.checkFederatedIdentityConfig(identities))
	}

	return findings, nil
}

func (a *AuthAuditor) checkReusableKeys(keys []keyInfo) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-001",
		Title:       "Reusable auth keys exist",
		Severity:    types.High,
		Category:    types.Authentication,
		Description: "Reusable auth keys are dangerous if stolen - they allow unlimited unauthorized device additions until expiry.",
		Remediation: "Store reusable keys in a secrets manager. Prefer one-off keys for single device provisioning. Review and delete unnecessary reusable keys.",
		Source:      "https://tailscale.com/docs/features/access-control/auth-keys",
		Pass:        true,
	}

	var reusableKeys []string
	var fixableItems []types.FixableItem
	for _, key := range keys {
		if key.Reusable {
			desc := fmt.Sprintf("Reusable, expires in %d days", key.DaysToExpiry)
			if len(key.Tags) > 0 {
				desc += fmt.Sprintf(", tags: %v", key.Tags)
			}
			line := fmt.Sprintf("%s (expires in %d days)", key.label(), key.DaysToExpiry)
			if note := reachNote(key.Tags, a.policy, a.policyParsed, a.devices); note != "" {
				line += " — " + note
			}
			reusableKeys = append(reusableKeys, line)
			fixableItems = append(fixableItems, types.FixableItem{
				ID:          key.ID,
				Name:        key.label(),
				Description: desc,
			})
		}
	}

	if len(reusableKeys) > 0 {
		finding.Pass = false
		finding.Details = reusableKeys
		finding.Description = fmt.Sprintf("Found %d reusable auth key(s). These can be reused to add multiple devices if compromised.", len(reusableKeys))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Delete reusable auth keys that are no longer needed",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			Items:       fixableItems,
			AutoFixSafe: false, // Reusable keys may be in active CI/CD use
		}
	}

	return finding
}

func (a *AuthAuditor) checkLongExpiryKeys(keys []keyInfo) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-002",
		Title:       "Auth keys with long expiry period",
		Severity:    types.High,
		Category:    types.Authentication,
		Description: "Auth keys valid for more than 90 days widen the window in which a leaked key can be used.",
		Remediation: "Set a shorter expirySeconds when creating auth keys. 90 days is the API default, not a ceiling: keys created through the API can outlive it, so a long-lived key is a deliberate choice worth revisiting.",
		Source:      "https://tailscale.com/docs/features/access-control/auth-keys",
		Pass:        true,
	}

	var longExpiryKeys []string
	var fixableItems []types.FixableItem
	for _, key := range keys {
		if key.DaysToExpiry > 90 {
			line := fmt.Sprintf("%s: %d days until expiry", key.label(), key.DaysToExpiry)
			if note := reachNote(key.Tags, a.policy, a.policyParsed, a.devices); note != "" {
				line += " — " + note
			}
			longExpiryKeys = append(longExpiryKeys, line)
			fixableItems = append(fixableItems, types.FixableItem{
				ID:          key.ID,
				Name:        key.label(),
				Description: fmt.Sprintf("Expires in %d days", key.DaysToExpiry),
			})
		}
	}

	if len(longExpiryKeys) > 0 {
		finding.Pass = false
		finding.Details = longExpiryKeys
		finding.Description = fmt.Sprintf("Found %d auth key(s) with more than 90 days until expiry.", len(longExpiryKeys))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Delete long-expiry keys and recreate with shorter expiry",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			Items:       fixableItems,
			AutoFixSafe: false, // Long-expiry keys may be intentional
		}
	}

	return finding
}

func (a *AuthAuditor) checkPreauthorizedKeys(keys []keyInfo) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-003",
		Title:       "Pre-authorized auth keys bypass device approval",
		Severity:    types.High,
		Category:    types.Authentication,
		Description: "Pre-authorized keys allow devices to join without admin approval, bypassing device approval controls.",
		Remediation: "Restrict pre-authorized keys to essential automation use cases. Use webhooks to alert on new device additions.",
		Source:      "https://tailscale.com/docs/features/access-control/auth-keys",
		Pass:        true,
	}

	var preauthorizedKeys []string
	for _, key := range keys {
		if key.Preauthorized {
			tagInfo := ""
			if len(key.Tags) > 0 {
				tagInfo = fmt.Sprintf(", tags: %v", key.Tags)
			}
			line := fmt.Sprintf("%s (expires in %d days%s)", key.label(), key.DaysToExpiry, tagInfo)
			if note := reachNote(key.Tags, a.policy, a.policyParsed, a.devices); note != "" {
				line += " — " + note
			}
			preauthorizedKeys = append(preauthorizedKeys, line)
		}
	}

	if len(preauthorizedKeys) > 0 {
		finding.Pass = false
		finding.Details = preauthorizedKeys
		finding.Description = fmt.Sprintf("Found %d pre-authorized auth key(s). These bypass device approval workflow.", len(preauthorizedKeys))

		// Build fixable items
		var fixableItems []types.FixableItem
		for _, key := range keys {
			if key.Preauthorized {
				desc := fmt.Sprintf("Pre-authorized, expires in %d days", key.DaysToExpiry)
				if len(key.Tags) > 0 {
					desc += fmt.Sprintf(", tags: %v", key.Tags)
				}
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          key.ID,
					Name:        key.label(),
					Description: desc,
				})
			}
		}
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Delete pre-authorized auth keys that are no longer needed",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			Items:       fixableItems,
			AutoFixSafe: false, // Pre-authorized keys may be in active use
		}
	}

	return finding
}

func (a *AuthAuditor) checkEphemeralKeyUsage(keys []keyInfo) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-004",
		Title:       "Non-ephemeral keys may be used for CI/CD",
		Severity:    types.Medium,
		Category:    types.Authentication,
		Description: "For CI/CD and temporary workloads, ephemeral keys are recommended as nodes are auto-removed after inactivity.",
		Remediation: "Use ephemeral keys for CI/CD pipelines. Add `tailscale logout` to scripts for immediate removal. Use --state=mem: flag.",
		Source:      "https://tailscale.com/docs/features/ephemeral-nodes",
		Pass:        true,
	}

	// Count reusable non-ephemeral keys (likely used for automation)
	var nonEphemeralReusable []string
	for _, key := range keys {
		if key.Reusable && !key.Ephemeral {
			nonEphemeralReusable = append(nonEphemeralReusable, fmt.Sprintf("%s: reusable but not ephemeral", key.label()))
		}
	}

	if len(nonEphemeralReusable) > 0 {
		finding.Pass = false
		finding.Details = nonEphemeralReusable
		finding.Description = fmt.Sprintf("Found %d reusable non-ephemeral key(s). If used for CI/CD, consider ephemeral keys instead.", len(nonEphemeralReusable))

		// Replacing a key is a manual step. The API can create the new key, but
		// it returns the secret only once, and whatever provisions devices with
		// the old key has to be updated with the new one before the old one is
		// deleted. Deleting first breaks the caller that depends on it.
		finding.Fix = &types.FixInfo{
			Type: types.FixTypeManual,
			Description: "Create an ephemeral replacement key, update the CI/CD secret that " +
				"holds the current key, then delete the old key.",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			DocURL:      "https://tailscale.com/docs/features/ephemeral-nodes",
			AutoFixSafe: false,
		}
	}

	return finding
}

// isMigrationCandidate reports whether a key is the kind of long-lived workload
// credential that workload identity federation replaces: reusable, not
// ephemeral, carrying tags, and still valid.
func (k keyInfo) isMigrationCandidate() bool {
	return k.Reusable && !k.Ephemeral && len(k.Tags) > 0 && k.DaysToExpiry >= 0
}

// federationFetchFailed builds the not-evaluated finding for a failure to
// read the tailnet's federated identities, for either AUTH-005 or AUTH-006 -
// both depend on the same fetch. Unlike the auth-keys read failure above, no
// AUTH-ERR finding is emitted on this path, so the reason must carry the
// error itself rather than point at a finding that was never raised.
func federationFetchFailed(id string, err error) types.Suggestion {
	return types.NotEvaluated(id,
		fmt.Sprintf("The tailnet's federated identities could not be read: %v", err))
}

func (a *AuthAuditor) checkFederationInUse(keys []keyInfo, identities []client.Key) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-005",
		Title:       "Workload identity federation not in use",
		Severity:    types.Medium,
		Category:    types.Authentication,
		Description: "Workload identity federation lets a CI job prove its cloud identity with a short-lived OIDC token, so there is no long-lived key to store or leak.",
		Remediation: "Create a trust credential for each CI workload and remove the static auth key it replaces. Pin the subject to a specific workload rather than a wildcard.",
		Source:      "https://tailscale.com/docs/features/workload-identity-federation",
		Pass:        true,
	}

	covered := make(map[string]bool)
	for _, id := range identities {
		for _, tag := range id.Tags {
			covered[tag] = true
		}
	}

	var details []string
	uncovered := false
	for _, key := range keys {
		if !key.isMigrationCandidate() {
			continue
		}
		var missing []string
		for _, tag := range key.Tags {
			if !covered[tag] {
				missing = append(missing, tag)
			}
		}
		if len(missing) == 0 {
			continue
		}
		uncovered = true
		details = append(details, fmt.Sprintf("%s: reusable, expires in %d days, mints %v with no trust credential",
			key.label(), key.DaysToExpiry, missing))
	}

	if !uncovered {
		return finding
	}

	finding.Pass = false
	finding.Details = details
	if len(identities) == 0 {
		finding.Description = fmt.Sprintf("Found %d reusable auth key(s) provisioning tagged workloads, and no trust credentials at all. A key like this is what an attacker reads out of a secret store and reuses to enroll nodes.", len(details))
	} else {
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("Trust credentials exist, but %d reusable auth key(s) still mint tags that none of them cover.", len(details))
	}
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Create a trust credential for these workloads, then delete the static key",
		AdminURL:    "https://login.tailscale.com/admin/settings/keys",
		DocURL:      "https://tailscale.com/docs/features/workload-identity-federation",
		AutoFixSafe: false,
	}
	return finding
}

// breadth classifies how much a federated identity subject admits.
type breadth int

const (
	breadthPinned breadth = iota
	breadthTrailingWildcard
	breadthLeadingWildcard
	breadthAny
)

// issuerHints map a recognized issuer host to remediation wording. They shape
// the message only. The verdict is issuer-agnostic so that a provider changing
// its subject grammar cannot silently invalidate a check.
var issuerHints = map[string]string{
	"token.actions.githubusercontent.com": "Pin the subject to one repository and ref, for example repo:ORG/REPO:ref:refs/heads/main.",
	"accounts.google.com":                 "Pin the subject to the service account that runs the workload.",
	"sts.amazonaws.com":                   "Pin the subject to the specific role the workload assumes.",
}

// subjectBreadth classifies a subject by where its wildcard sits. A subject
// that is nothing but wildcards (and the separators around them) admits every
// principal the issuer vouches for.
func subjectBreadth(subject string) breadth {
	s := strings.TrimSpace(subject)
	if strings.Trim(s, "*:/ ") == "" {
		return breadthAny
	}
	if !strings.Contains(s, "*") {
		return breadthPinned
	}
	if strings.HasPrefix(s, "*") {
		return breadthLeadingWildcard
	}
	return breadthTrailingWildcard
}

// checkFederatedIdentityConfig audits the configuration quality of trust
// credentials that are already in use (AUTH-005 covers whether they exist at
// all). A subject that is nothing but a wildcard lets any principal the
// issuer will vouch for mint the credential's tags - a boundary crossing, so
// it fails high regardless of issuer. A wildcard confined to one end of the
// subject is narrower and reported without escalating severity; the same
// goes for an empty audience or absent claim rules, which are supporting
// facts rather than verdicts on their own.
func (a *AuthAuditor) checkFederatedIdentityConfig(identities []client.Key) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-006",
		Title:       "Federated identity subject admits unintended principals",
		Severity:    types.High,
		Category:    types.Authentication,
		Description: "A trust credential's subject decides which workloads can mint its tags. A wildcard subject widens that to everything the issuer will vouch for.",
		Remediation: "Pin each subject to one workload. Set an audience so a token minted for another relying party cannot be replayed, and add claim rules to tighten further.",
		Source:      "https://tailscale.com/docs/features/workload-identity-federation",
		Pass:        true,
	}

	var wideOpen, narrower, notes []string
	for _, id := range identities {
		label := id.ID
		if id.Description != "" {
			label = fmt.Sprintf("%s (%s)", id.Description, id.ID)
		}
		b := subjectBreadth(id.Subject)
		switch b {
		case breadthAny:
			hint := "Pin the subject to a single workload."
			if h, ok := issuerHints[id.Issuer]; ok {
				hint = h
			}
			wideOpen = append(wideOpen, fmt.Sprintf("%s: subject %q accepts any principal issued by %s. %s",
				label, id.Subject, id.Issuer, hint))
		case breadthLeadingWildcard, breadthTrailingWildcard:
			narrower = append(narrower, fmt.Sprintf("%s: subject %q contains a wildcard", label, id.Subject))
		}

		// Supporting facts. Neither sets severity on its own; an empty audience
		// alongside a wildcard subject is the pairing that matters.
		if strings.TrimSpace(id.Audience) == "" {
			notes = append(notes, fmt.Sprintf("%s: no audience set, so a token minted for another relying party is not rejected", label))
		}
		if len(id.CustomClaimRules) == 0 && b != breadthPinned {
			notes = append(notes, fmt.Sprintf("%s: wildcard subject with no claim rules to tighten it", label))
		}
	}

	if len(wideOpen) > 0 {
		finding.Pass = false
		finding.Details = append(append(wideOpen, narrower...), notes...)
		finding.Description = fmt.Sprintf("Found %d trust credential(s) whose subject accepts any principal the issuer vouches for.", len(wideOpen))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Narrow each subject to a single workload",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			DocURL:      "https://tailscale.com/docs/features/workload-identity-federation",
		}
		return finding
	}

	if len(narrower) > 0 || len(notes) > 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Details = append(narrower, notes...)
		finding.Description = "Trust credentials are in use. These carry a wildcard subject or no audience, which may be intended but is worth confirming."
		return finding
	}

	if len(identities) > 0 {
		finding.Description = fmt.Sprintf("All %d trust credential(s) pin their subject.", len(identities))
	} else {
		finding.Description = "No trust credentials are configured."
	}
	return finding
}
