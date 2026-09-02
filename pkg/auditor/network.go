package auditor

import (
	"context"
	"fmt"
	"strings"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// NetworkAuditor checks for network exposure issues
type NetworkAuditor struct {
	client *client.Client
}

// NewNetworkAuditor creates a new network auditor
func NewNetworkAuditor(c *client.Client) *NetworkAuditor {
	return &NetworkAuditor{client: c}
}

// Audit performs network exposure security checks.
//
// tc carries tailnet-wide state shared with the other auditors. When nil, it is
// fetched here so an individual auditor can be run on its own.
func (n *NetworkAuditor) Audit(ctx context.Context, policy ACLPolicy, policyParsed bool, tc *TailnetContext) ([]types.Suggestion, error) {
	if tc == nil {
		tc = FetchTailnetContext(ctx, n.client)
	}

	var findings []types.Suggestion

	devices, err := n.client.GetDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	if policyParsed {
		// NET-001: Check for Funnel endpoints
		findings = append(findings, n.checkFunnelEndpoints(policy))

		// NET-002: Check for exit node ACL configuration
		findings = append(findings, n.checkExitNodeACLs(policy))

		// NET-006: Check for Serve exposure
		findings = append(findings, n.checkServeExposure(policy))
	} else {
		for _, id := range networkPolicyChecks {
			findings = append(findings, types.NotEvaluated(id,
				"The tailnet policy file could not be read or parsed, so the node attributes were not evaluated."))
		}
	}

	// NET-003: Check for unapproved subnet routes
	findings = append(findings, n.checkSubnetRoutes(ctx, devices))

	// NET-004: Check for HTTPS/Certificate Transparency exposure.
	// The tailnet setting is authoritative here, so this runs either way.
	findings = append(findings, n.checkHTTPSExposure(policy, tc))

	// NET-005: Check for exit nodes
	findings = append(findings, n.checkExitNodes(devices))

	// NET-007: Check for app connectors
	findings = append(findings, n.checkAppConnectors(devices))

	return findings, nil
}

// networkPolicyChecks are the network checks that read node attributes from
// the tailnet policy file. NET-004 is absent: it reads the authoritative
// tailnet setting and only falls back to the policy.
var networkPolicyChecks = []string{"NET-001", "NET-002", "NET-006"}

func (n *NetworkAuditor) checkFunnelEndpoints(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-001",
		Title:       "Funnel exposes services to public internet",
		Severity:    types.High,
		Category:    types.NetworkExposure,
		Description: "Tailscale Funnel routes traffic from the public internet to local services without requiring Tailscale authentication.",
		Remediation: "Review nodeAttrs for funnel attribute. Restrict Funnel to specific users/tags. Ensure only intended services are exposed.",
		Source:      "https://tailscale.com/docs/features/tailscale-funnel",
		Pass:        true,
	}

	var funnelConfigs []string
	for _, attr := range policy.NodeAttrs {
		for _, a := range attr.Attr {
			if strings.Contains(strings.ToLower(a), "funnel") {
				funnelConfigs = append(funnelConfigs, fmt.Sprintf("Target: %v, Attr: %s", attr.Target, a))
			}
		}
	}

	if len(funnelConfigs) > 0 {
		finding.Pass = false
		finding.Details = funnelConfigs
		finding.Description = fmt.Sprintf("Found %d Funnel configuration(s). These expose services to the public internet.", len(funnelConfigs))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review Funnel configuration in nodeAttrs",
			AdminURL:    "https://login.tailscale.com/admin/acls",
			DocURL:      "https://tailscale.com/docs/features/tailscale-funnel",
		}
	}

	return finding
}

func (n *NetworkAuditor) checkExitNodeACLs(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-002",
		Title:       "Exit node access configuration",
		Severity:    types.Medium,
		Category:    types.NetworkExposure,
		Description: "Exit node usage is controlled via autogroup:internet in ACLs. Verify intended users have access.",
		Remediation: "Review which users/groups have access to autogroup:internet. Exit node restrictions cannot be granular - it's all-or-nothing.",
		Source:      "https://tailscale.com/docs/features/exit-nodes",
		Pass:        true,
	}

	var exitNodeRules []string
	for i, rule := range policy.ACLs {
		for _, dst := range rule.Dst {
			if strings.Contains(dst, "autogroup:internet") {
				exitNodeRules = append(exitNodeRules, fmt.Sprintf("Rule %d: src=%v can use exit nodes", i+1, rule.Src))
			}
		}
	}

	if len(exitNodeRules) > 0 {
		finding.Pass = false
		finding.Severity = types.Low // Informational since exit node access is often intended
		finding.Details = exitNodeRules
		finding.Description = fmt.Sprintf("Found %d ACL rule(s) granting exit node (internet) access. Verify this is intended.", len(exitNodeRules))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review ACL rules granting autogroup:internet access",
			AdminURL:    "https://login.tailscale.com/admin/acls",
			DocURL:      "https://tailscale.com/docs/features/exit-nodes",
		}
	}

	return finding
}

func (n *NetworkAuditor) checkSubnetRoutes(ctx context.Context, devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-003",
		Title:       "Subnet routes expose trust boundary",
		Severity:    types.High,
		Category:    types.NetworkExposure,
		Description: "Subnet routers are a critical trust boundary. Traffic is encrypted only to the subnet router - traffic to final destinations is UNENCRYPTED on the local network. A compromised subnet router exposes the entire advertised subnet.",
		Remediation: "Enable stateful filtering on subnet routers. Restrict advertised routes to minimum required. Verify firewall rules on subnet router hosts. Consider separate subnet routers per security zone.",
		Source:      "https://tailscale.com/docs/features/subnet-routers",
		Pass:        true,
	}

	var subnetRouters []string
	var unapprovedRoutes []string

	for _, dev := range devices {
		// Check for advertised routes
		if len(dev.AdvertisedRoutes) > 0 {
			subnetRouters = append(subnetRouters, fmt.Sprintf("%s (%s): advertising %v", dev.Name, dev.Hostname, dev.AdvertisedRoutes))
		}

		// Check for unapproved routes (advertised but not enabled)
		if len(dev.AdvertisedRoutes) > len(dev.EnabledRoutes) {
			// Find routes that are advertised but not enabled
			enabledSet := make(map[string]bool)
			for _, r := range dev.EnabledRoutes {
				enabledSet[r] = true
			}
			for _, r := range dev.AdvertisedRoutes {
				if !enabledSet[r] {
					unapprovedRoutes = append(unapprovedRoutes, fmt.Sprintf("%s: %s (pending approval)", dev.Name, r))
				}
			}
		}
	}

	if len(subnetRouters) > 0 {
		finding.Pass = false
		finding.Details = subnetRouters
		finding.Description = fmt.Sprintf("Found %d device(s) advertising subnet routes. Ensure firewall rules are properly configured.", len(subnetRouters))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review and approve/reject subnet routes",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/docs/features/subnet-routers",
		}
	}

	if len(unapprovedRoutes) > 0 {
		if finding.Pass {
			// No subnet routers found, but there are unapproved routes
			finding.Pass = false
			finding.Details = append([]string{"Pending route approvals:"}, unapprovedRoutes...)
			finding.Description = fmt.Sprintf("Found %d pending route approval(s).", len(unapprovedRoutes))
			finding.Fix = &types.FixInfo{
				Type:        types.FixTypeManual,
				Description: "Review and approve/reject subnet routes",
				AdminURL:    "https://login.tailscale.com/admin/machines",
				DocURL:      "https://tailscale.com/docs/features/subnet-routers",
			}
		} else {
			// Append to existing subnet router details
			if details, ok := finding.Details.([]string); ok {
				details = append(details, "")
				details = append(details, "Pending route approvals:")
				details = append(details, unapprovedRoutes...)
				finding.Details = details
			}
		}
	}

	return finding
}

func (n *NetworkAuditor) checkHTTPSExposure(policy ACLPolicy, tc *TailnetContext) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-004",
		Title:       "HTTPS certificates publish names to CT logs",
		Severity:    types.Medium,
		Category:    types.NetworkExposure,
		Description: "HTTPS certificates publish machine names to public Certificate Transparency logs. Sensitive machine names could be exposed.",
		Remediation: "Review machine names before enabling HTTPS. Rename devices with sensitive information. Use randomized tailnet DNS name.",
		Source:      "https://tailscale.com/docs/how-to/set-up-https-certificates",
		Pass:        true,
	}

	// The tailnet setting is authoritative: HTTPS certificate provisioning is a
	// tailnet-wide switch, not something inferred from nodeAttrs.
	if settings := tc.settings(); settings != nil {
		if !settings.HTTPSEnabled {
			finding.Severity = types.Informational
			finding.Description = "HTTPS certificate provisioning is disabled for this tailnet, so machine names are not published to Certificate Transparency logs."
			finding.Details = "Confirmed via the Tailscale API (httpsEnabled is false)."
			return finding
		}

		finding.Pass = false
		finding.Description = "HTTPS certificate provisioning is enabled. Every machine name a certificate is issued for is published to public Certificate Transparency logs."
		finding.Details = []string{
			"Confirmed via the Tailscale API (httpsEnabled is true).",
			"See DEV-007 for machine names that look sensitive.",
		}
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review machine names, or disable HTTPS certificates if unused",
			AdminURL:    "https://login.tailscale.com/admin/dns",
			DocURL:      "https://tailscale.com/docs/how-to/set-up-https-certificates",
		}
		return finding
	}

	// Without the setting, fall back to looking for HTTPS-related nodeAttrs.
	var httpsConfigs []string
	for _, attr := range policy.NodeAttrs {
		for _, a := range attr.Attr {
			if strings.Contains(strings.ToLower(a), "https") || strings.Contains(strings.ToLower(a), "cert") {
				httpsConfigs = append(httpsConfigs, fmt.Sprintf("Target: %v, Attr: %s", attr.Target, a))
			}
		}
	}

	if len(httpsConfigs) > 0 {
		finding.Pass = false
		finding.Details = httpsConfigs
		finding.Description = fmt.Sprintf("Found %d HTTPS-related configuration(s). Machine names may be published to CT logs.", len(httpsConfigs))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review HTTPS configuration and machine names",
			AdminURL:    "https://login.tailscale.com/admin/dns",
			DocURL:      "https://tailscale.com/docs/how-to/set-up-https-certificates",
		}
	} else {
		// This is informational - HTTPS might be enabled at the tailnet level
		finding.Severity = types.Informational
		finding.Description = "Could not read the tailnet HTTPS setting and found no HTTPS-related nodeAttrs. If HTTPS certificates are enabled, machine names are published to CT logs."
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review HTTPS/DNS settings",
			AdminURL:    "https://login.tailscale.com/admin/dns",
			DocURL:      "https://tailscale.com/docs/how-to/set-up-https-certificates",
		}
	}

	return finding
}

func (n *NetworkAuditor) checkExitNodes(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-005",
		Title:       "Exit nodes can see all internet traffic",
		Severity:    types.Medium,
		Category:    types.NetworkExposure,
		Description: "Exit node operators can see all internet traffic from connected clients - browsing history, unencrypted HTTP content, and DNS queries. Destination logging is disabled by default, leaving no audit trail.",
		Remediation: "Only use trusted exit nodes. For mandatory exit node deployments, ensure high availability. Enable destination logging if compliance requires it. Review exit-node-allow-lan-access settings.",
		Source:      "https://tailscale.com/docs/features/exit-nodes",
		Pass:        true,
	}

	var exitNodes []string
	for _, dev := range devices {
		// Check if device is advertising 0.0.0.0/0 or ::/0 (exit node routes)
		for _, route := range dev.AdvertisedRoutes {
			if route == "0.0.0.0/0" || route == "::/0" {
				isApproved := false
				for _, enabled := range dev.EnabledRoutes {
					if enabled == route {
						isApproved = true
						break
					}
				}
				status := "approved"
				if !isApproved {
					status = "pending approval"
				}
				exitNodes = append(exitNodes, fmt.Sprintf("%s (%s) - %s", dev.Name, dev.Hostname, status))
				break
			}
		}
	}

	if len(exitNodes) > 0 {
		finding.Pass = false
		finding.Details = exitNodes
		finding.Description = fmt.Sprintf("Found %d exit node(s). Exit node destination logging is disabled by default.", len(exitNodes))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review exit node configuration and approve/reject routes",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/docs/features/exit-nodes",
		}
	}

	return finding
}

func (n *NetworkAuditor) checkServeExposure(policy ACLPolicy) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-006",
		Title:       "Tailscale Serve exposes services on tailnet",
		Severity:    types.Medium,
		Category:    types.NetworkExposure,
		Description: "Tailscale Serve exposes local services (HTTP, HTTPS, TCP) to the tailnet. Services are accessible to any device that can reach the host.",
		Remediation: "Review Serve configurations. Ensure only intended services are exposed. Use ACLs to restrict which users/devices can access served endpoints.",
		Source:      "https://tailscale.com/docs/reference/tailscale-cli/serve",
		Pass:        true,
	}

	var serveConfigs []string
	for _, attr := range policy.NodeAttrs {
		for _, a := range attr.Attr {
			lowerAttr := strings.ToLower(a)
			// Check for serve-related attributes
			if strings.Contains(lowerAttr, "serve") {
				serveConfigs = append(serveConfigs, fmt.Sprintf("Target: %v, Attr: %s", attr.Target, a))
			}
		}
	}

	if len(serveConfigs) > 0 {
		finding.Pass = false
		finding.Details = serveConfigs
		finding.Description = fmt.Sprintf("Found %d Serve configuration(s). Local services are exposed to the tailnet.", len(serveConfigs))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review Serve configuration and ensure ACLs restrict access appropriately",
			AdminURL:    "https://login.tailscale.com/admin/acls",
			DocURL:      "https://tailscale.com/docs/reference/tailscale-cli/serve",
		}
	}

	return finding
}

func (n *NetworkAuditor) checkAppConnectors(devices []*client.Device) types.Suggestion {
	finding := types.Suggestion{
		ID:          "NET-007",
		Title:       "App connectors provide SaaS access",
		Severity:    types.Informational,
		Category:    types.NetworkExposure,
		Description: "App connectors route traffic to specific SaaS applications through your tailnet. Review which apps are accessible and through which devices.",
		Remediation: "Audit app connector configurations. Ensure only approved SaaS applications are accessible. Review which devices are acting as app connectors.",
		Source:      "https://tailscale.com/docs/features/app-connectors",
		Pass:        true,
	}

	// App connectors typically advertise routes to specific IP ranges or domains
	// They're identified by advertising narrow routes that aren't traditional subnets
	var appConnectorCandidates []string

	for _, dev := range devices {
		if len(dev.AdvertisedRoutes) == 0 {
			continue
		}

		// Look for patterns that suggest app connectors:
		// - Routes to specific /32 or /128 addresses
		// - Routes that don't look like typical private subnets (10.x, 172.16-31.x, 192.168.x)
		for _, route := range dev.AdvertisedRoutes {
			// Skip exit node routes
			if route == "0.0.0.0/0" || route == "::/0" {
				continue
			}

			// Check for /32 routes (single IP)
			if strings.HasSuffix(route, "/32") || strings.HasSuffix(route, "/128") {
				appConnectorCandidates = append(appConnectorCandidates,
					fmt.Sprintf("%s (%s): narrow route %s (possible app connector)", dev.Name, dev.Hostname, route))
			}
		}
	}

	if len(appConnectorCandidates) > 0 {
		finding.Pass = false
		finding.Details = appConnectorCandidates
		finding.Description = fmt.Sprintf("Found %d device(s) with narrow routes that may be app connectors.", len(appConnectorCandidates))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Review app connector configurations",
			AdminURL:    "https://login.tailscale.com/admin/machines",
			DocURL:      "https://tailscale.com/docs/features/app-connectors",
		}
	}

	return finding
}
