package auditor

import (
	"context"
	"fmt"
	"time"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// AuthAuditor checks for authentication and key management issues
type AuthAuditor struct {
	client *client.Client
}

// authKeyChecks are the checks that read the tailnet's machine auth keys.
var authKeyChecks = []string{"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"}

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

// Audit performs authentication-related security checks
func (a *AuthAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
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
			reusableKeys = append(reusableKeys, fmt.Sprintf("%s (expires in %d days)", key.label(), key.DaysToExpiry))
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
			longExpiryKeys = append(longExpiryKeys, fmt.Sprintf("%s: %d days until expiry", key.label(), key.DaysToExpiry))
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
			preauthorizedKeys = append(preauthorizedKeys, fmt.Sprintf("%s (expires in %d days%s)", key.label(), key.DaysToExpiry, tagInfo))
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
