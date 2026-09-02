package auditor

import (
	"context"
	"fmt"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// DNSAuditor checks for DNS configuration issues
type DNSAuditor struct {
	client *client.Client
}

// NewDNSAuditor creates a new DNS auditor
func NewDNSAuditor(c *client.Client) *DNSAuditor {
	return &DNSAuditor{client: c}
}

// Audit performs DNS-related security checks
func (d *DNSAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
	var findings []types.Suggestion

	// Get DNS configuration
	config, err := d.client.GetDNSConfig(ctx)
	if err != nil {
		findings = append(findings, types.Suggestion{
			ID:          "DNS-ERR",
			Title:       "Could not retrieve DNS configuration",
			Severity:    types.Medium,
			Category:    types.DNSConfiguration,
			Description: fmt.Sprintf("Unable to retrieve DNS configuration: %v. The DNS checks were not evaluated.", err),
			Remediation: "Grant the credential the dns:read scope, then re-run the audit.",
			Pass:        false,
		})
		findings = append(findings, types.NotEvaluated("DNS-001",
			"The tailnet's DNS configuration could not be read. See DNS-ERR for the error."))
		return findings, nil
	}

	// DNS-001: Check MagicDNS status
	findings = append(findings, d.checkMagicDNS(config))

	return findings, nil
}

func (d *DNSAuditor) checkMagicDNS(config *client.DNSConfig) types.Suggestion {
	finding := types.Suggestion{
		ID:          "DNS-001",
		Title:       "MagicDNS configuration",
		Severity:    types.Informational,
		Category:    types.DNSConfiguration,
		Description: "MagicDNS enables automatic DNS resolution for tailnet devices using memorable names instead of IP addresses.",
		Remediation: "Enable MagicDNS in DNS settings for easier device addressing. Use MagicDNS names instead of IP addresses.",
		Source:      "https://tailscale.com/docs/features/magicdns",
		Pass:        true,
	}

	if !config.MagicDNS {
		finding.Pass = false
		finding.Description = "MagicDNS is disabled. Devices must be addressed by IP address instead of memorable names."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Enable MagicDNS in DNS settings",
			AdminURL:    "https://login.tailscale.com/admin/dns",
			DocURL:      "https://tailscale.com/docs/features/magicdns",
		}
	}

	return finding
}
