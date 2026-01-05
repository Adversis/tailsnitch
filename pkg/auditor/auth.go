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

// NewAuthAuditor creates a new auth auditor
func NewAuthAuditor(c *client.Client) *AuthAuditor {
	return &AuthAuditor{client: c}
}

// keyInfo holds parsed auth key information for auditing
type keyInfo struct {
	ID            string
	Reusable      bool
	Preauthorized bool
	Ephemeral     bool
	Tags          []string
	DaysToExpiry  int
	Created       time.Time
	Expires       time.Time
}

// Audit performs authentication-related security checks
func (a *AuthAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// Get all auth keys
	keyIDs, err := a.client.GetKeys(ctx)
	if err != nil {
		// Auth keys might not be accessible with all API keys
		findings = append(findings, types.Suggestion{
			ID:          "AUTH-ERR",
			Title:       "Could not retrieve auth keys",
			Severity:    types.Informational,
			Category:    types.Authentication,
			Description: fmt.Sprintf("Unable to retrieve auth keys: %v. This may require additional API permissions.", err),
			Pass:        true,
		})
		return findings, nil
	}

	var keys []keyInfo
	for _, id := range keyIDs {
		key, err := a.client.GetKey(ctx, id)
		if err != nil {
			continue // Skip keys we can't fetch
		}

		info := keyInfo{
			ID:      key.ID,
			Created: key.Created,
			Expires: key.Expires,
		}

		// Calculate days to expiry
		if !key.Expires.IsZero() {
			info.DaysToExpiry = int(time.Until(key.Expires).Hours() / 24)
		}

		// Extract capabilities
		if key.Capabilities.Devices.Create.Reusable {
			info.Reusable = true
		}
		if key.Capabilities.Devices.Create.Preauthorized {
			info.Preauthorized = true
		}
		if key.Capabilities.Devices.Create.Ephemeral {
			info.Ephemeral = true
		}
		info.Tags = key.Capabilities.Devices.Create.Tags

		keys = append(keys, info)
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
		Source:      "https://tailscale.com/kb/1085/auth-keys",
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
			reusableKeys = append(reusableKeys, fmt.Sprintf("Key %s (expires in %d days)", key.ID, key.DaysToExpiry))
			fixableItems = append(fixableItems, types.FixableItem{
				ID:          key.ID,
				Name:        key.ID,
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
		Description: "Auth keys with expiry periods longer than 90 days increase the exposure window if compromised.",
		Remediation: "Use shorter expiry periods for auth keys. The maximum is 90 days, but shorter periods reduce risk.",
		Source:      "https://tailscale.com/kb/1085/auth-keys",
		Pass:        true,
	}

	var longExpiryKeys []string
	var fixableItems []types.FixableItem
	for _, key := range keys {
		if key.DaysToExpiry > 90 {
			longExpiryKeys = append(longExpiryKeys, fmt.Sprintf("Key %s: %d days until expiry", key.ID, key.DaysToExpiry))
			fixableItems = append(fixableItems, types.FixableItem{
				ID:          key.ID,
				Name:        key.ID,
				Description: fmt.Sprintf("Expires in %d days", key.DaysToExpiry),
			})
		}
	}

	if len(longExpiryKeys) > 0 {
		finding.Pass = false
		finding.Details = longExpiryKeys
		finding.Description = fmt.Sprintf("Found %d auth key(s) with >90 days until expiry.", len(longExpiryKeys))
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
		Source:      "https://tailscale.com/kb/1085/auth-keys",
		Pass:        true,
	}

	var preauthorizedKeys []string
	for _, key := range keys {
		if key.Preauthorized {
			tagInfo := ""
			if len(key.Tags) > 0 {
				tagInfo = fmt.Sprintf(", tags: %v", key.Tags)
			}
			preauthorizedKeys = append(preauthorizedKeys, fmt.Sprintf("Key %s (expires in %d days%s)", key.ID, key.DaysToExpiry, tagInfo))
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
					Name:        key.ID,
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
		Source:      "https://tailscale.com/kb/1111/ephemeral-nodes",
		Pass:        true,
	}

	// Count reusable non-ephemeral keys (likely used for automation)
	var nonEphemeralReusable []string
	for _, key := range keys {
		if key.Reusable && !key.Ephemeral {
			nonEphemeralReusable = append(nonEphemeralReusable, fmt.Sprintf("Key %s: reusable but not ephemeral", key.ID))
		}
	}

	if len(nonEphemeralReusable) > 0 {
		finding.Pass = false
		finding.Details = nonEphemeralReusable
		finding.Description = fmt.Sprintf("Found %d reusable non-ephemeral key(s). If used for CI/CD, consider ephemeral keys instead.", len(nonEphemeralReusable))

		// Build fixable items for creating ephemeral replacement keys
		var fixableItems []types.FixableItem
		for _, key := range keys {
			if key.Reusable && !key.Ephemeral {
				desc := fmt.Sprintf("Expires in %d days", key.DaysToExpiry)
				if len(key.Tags) > 0 {
					desc += fmt.Sprintf(", tags: %v", key.Tags)
				}
				fixableItems = append(fixableItems, types.FixableItem{
					ID:          key.ID,
					Name:        key.ID,
					Description: desc,
				})
			}
		}

		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeAPI,
			Description: "Create ephemeral replacement keys (7-day expiry) and delete old keys",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			DocURL:      "https://tailscale.com/kb/1111/ephemeral-nodes",
			Items:       fixableItems,
			AutoFixSafe: false, // User should verify CI/CD usage before replacing
		}
	}

	return finding
}
