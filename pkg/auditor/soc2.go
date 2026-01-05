package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// SOC2Collector gathers evidence for SOC 2 audit reports
type SOC2Collector struct {
	client   *client.Client
	registry *types.CheckRegistry
}

// NewSOC2Collector creates a new SOC2 evidence collector
func NewSOC2Collector(c *client.Client) *SOC2Collector {
	return &SOC2Collector{
		client:   c,
		registry: types.DefaultRegistry,
	}
}

// Collect gathers all SOC 2 evidence by evaluating resources against controls
func (c *SOC2Collector) Collect(ctx context.Context) (*types.SOC2Report, error) {
	report := &types.SOC2Report{
		Tailnet:     c.client.Tailnet(),
		GeneratedAt: time.Now(),
		Tests:       []types.SOC2ControlTest{},
	}

	now := time.Now()

	// Fetch devices
	devices, err := c.client.GetDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	// Fetch auth keys
	var keys []keyInfo
	keyIDs, err := c.client.GetKeys(ctx)
	if err == nil {
		for _, id := range keyIDs {
			key, err := c.client.GetKey(ctx, id)
			if err != nil {
				continue
			}
			info := keyInfo{
				ID:      key.ID,
				Created: key.Created,
				Expires: key.Expires,
			}
			if !key.Expires.IsZero() {
				info.DaysToExpiry = int(time.Until(key.Expires).Hours() / 24)
			}
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
	}

	// Fetch ACL policy
	var policy ACLPolicy
	aclHuJSON, err := c.client.GetACLHuJSON(ctx)
	if err == nil {
		standardizedACL, err := hujson.Standardize([]byte(aclHuJSON.ACL))
		if err == nil {
			json.Unmarshal(standardizedACL, &policy)
		}
	}

	// Evaluate devices against applicable checks
	report.Tests = append(report.Tests, c.evaluateDevices(devices, now)...)

	// Evaluate auth keys against applicable checks
	report.Tests = append(report.Tests, c.evaluateKeys(keys, now)...)

	// Evaluate ACL policy against applicable checks
	report.Tests = append(report.Tests, c.evaluateACL(policy, aclHuJSON, now)...)

	// Evaluate SSH configuration
	report.Tests = append(report.Tests, c.evaluateSSH(policy, now)...)

	// Calculate summary
	report.CalculateSummary()

	return report, nil
}

// evaluateDevices tests each device against DEV-* checks
func (c *SOC2Collector) evaluateDevices(devices []*client.Device, now time.Time) []types.SOC2ControlTest {
	var tests []types.SOC2ControlTest

	versionRegex := regexp.MustCompile(`v?(\d+)\.(\d+)`)
	sensitivePatterns := []string{
		"prod", "production", "staging", "dev", "database", "db",
		"api", "admin", "internal", "secret", "vault", "key",
	}

	for _, dev := range devices {
		resourceID := dev.NodeID
		if resourceID == "" {
			resourceID = dev.DeviceID
		}
		resourceName := dev.Name
		if resourceName == "" {
			resourceName = dev.Hostname
		}

		// DEV-001: Tagged devices with key expiry disabled
		check := c.registry.All()[18] // DEV-001 index
		for _, chk := range c.registry.All() {
			if chk.ID == "DEV-001" {
				check = chk
				break
			}
		}
		status := types.SOC2Pass
		details := ""
		if len(dev.Tags) > 0 {
			if dev.KeyExpiryDisabled {
				status = types.SOC2Fail
				details = fmt.Sprintf("Tags: %v, key expiry disabled", dev.Tags)
			} else {
				details = fmt.Sprintf("Tags: %v, key expiry enabled", dev.Tags)
			}
		} else {
			status = types.SOC2NA
			details = "No tags assigned"
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-003: Outdated Tailscale clients
		check = c.getCheck("DEV-003")
		major, minor, ok := parseVersion(dev.ClientVersion, versionRegex)
		status = types.SOC2Pass
		details = fmt.Sprintf("Version: %s", dev.ClientVersion)
		if ok {
			// Check if more than 3 minor versions behind (1.76 - 3 = 1.73)
			if major < 1 || (major == 1 && minor < 73) {
				status = types.SOC2Fail
				details = fmt.Sprintf("Version %s is outdated", dev.ClientVersion)
			}
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-004: Stale devices
		check = c.getCheck("DEV-004")
		status = types.SOC2Pass
		daysSinceSeen := 0
		if lastSeenTime, err := time.Parse(time.RFC3339, dev.LastSeen); err == nil {
			daysSinceSeen = int(now.Sub(lastSeenTime).Hours() / 24)
			details = fmt.Sprintf("Last seen: %s (%d days ago)", lastSeenTime.Format("2006-01-02"), daysSinceSeen)
		} else {
			details = fmt.Sprintf("Last seen: %s", dev.LastSeen)
		}
		if daysSinceSeen > 90 {
			status = types.SOC2Fail
			details = fmt.Sprintf("Stale: last seen %d days ago", daysSinceSeen)
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-005: Unauthorized devices
		check = c.getCheck("DEV-005")
		status = types.SOC2Pass
		details = "Device authorized"
		if !dev.Authorized {
			status = types.SOC2Fail
			details = "Device pending authorization"
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-006: External devices
		check = c.getCheck("DEV-006")
		status = types.SOC2Pass
		details = "Internal device"
		if dev.IsExternal {
			status = types.SOC2Fail
			details = "External/shared device"
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-007: Sensitive machine names
		check = c.getCheck("DEV-007")
		status = types.SOC2Pass
		details = "No sensitive patterns found"
		nameLower := strings.ToLower(resourceName)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(nameLower, pattern) {
				status = types.SOC2Fail
				details = fmt.Sprintf("Contains sensitive pattern: %s", pattern)
				break
			}
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// DEV-008: Long key expiry
		check = c.getCheck("DEV-008")
		status = types.SOC2Pass
		details = "Key expiry configured"
		if dev.KeyExpiryDisabled {
			status = types.SOC2Fail
			details = "Key expiry disabled"
		} else if dev.Expires != "" {
			if expiresTime, err := time.Parse(time.RFC3339, dev.Expires); err == nil {
				daysToExpiry := int(expiresTime.Sub(now).Hours() / 24)
				if daysToExpiry > 180 {
					status = types.SOC2Fail
					details = fmt.Sprintf("Key expires in %d days (>180)", daysToExpiry)
				} else {
					details = fmt.Sprintf("Key expires in %d days", daysToExpiry)
				}
			}
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "device",
			ResourceID:   resourceID,
			ResourceName: resourceName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})
	}

	return tests
}

// evaluateKeys tests each auth key against AUTH-* checks
func (c *SOC2Collector) evaluateKeys(keys []keyInfo, now time.Time) []types.SOC2ControlTest {
	var tests []types.SOC2ControlTest

	for _, key := range keys {
		// AUTH-001: Reusable keys
		check := c.getCheck("AUTH-001")
		status := types.SOC2Pass
		details := "Not reusable"
		if key.Reusable {
			status = types.SOC2Fail
			details = fmt.Sprintf("Reusable key, expires in %d days", key.DaysToExpiry)
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "key",
			ResourceID:   key.ID,
			ResourceName: key.ID,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// AUTH-002: Long expiry keys
		check = c.getCheck("AUTH-002")
		status = types.SOC2Pass
		details = fmt.Sprintf("Expires in %d days", key.DaysToExpiry)
		if key.DaysToExpiry > 90 {
			status = types.SOC2Fail
			details = fmt.Sprintf("Long expiry: %d days (>90)", key.DaysToExpiry)
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "key",
			ResourceID:   key.ID,
			ResourceName: key.ID,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// AUTH-003: Pre-authorized keys
		check = c.getCheck("AUTH-003")
		status = types.SOC2Pass
		details = "Not pre-authorized"
		if key.Preauthorized {
			status = types.SOC2Fail
			details = "Pre-authorized key bypasses approval"
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "key",
			ResourceID:   key.ID,
			ResourceName: key.ID,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// AUTH-004: Non-ephemeral reusable keys
		check = c.getCheck("AUTH-004")
		status = types.SOC2Pass
		details = "Ephemeral or single-use"
		if key.Reusable && !key.Ephemeral {
			status = types.SOC2Fail
			details = "Reusable but not ephemeral - consider ephemeral for CI/CD"
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "key",
			ResourceID:   key.ID,
			ResourceName: key.ID,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})
	}

	return tests
}

// evaluateACL tests ACL policy against ACL-* checks
func (c *SOC2Collector) evaluateACL(policy ACLPolicy, aclHuJSON *client.ACLHuJSON, now time.Time) []types.SOC2ControlTest {
	var tests []types.SOC2ControlTest

	// ACL-001: Allow all policy
	check := c.getCheck("ACL-001")
	status := types.SOC2Pass
	details := "No allow-all rules found"
	hasAllowAll := false
	if aclHuJSON != nil {
		rawACL := strings.ToLower(aclHuJSON.ACL)
		if strings.Contains(rawACL, `"action": "accept"`) || strings.Contains(rawACL, `"action":"accept"`) {
			for _, acl := range policy.ACLs {
				if acl.Action == "accept" {
					for _, src := range acl.Src {
						for _, dst := range acl.Dst {
							if src == "*" && (dst == "*" || dst == "*:*") {
								hasAllowAll = true
								break
							}
						}
					}
				}
			}
		}
	}
	if hasAllowAll {
		status = types.SOC2Fail
		details = "Default allow-all policy active"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-003: ACL tests defined
	check = c.getCheck("ACL-003")
	status = types.SOC2Pass
	details = fmt.Sprintf("%d ACL tests defined", len(policy.Tests))
	if len(policy.Tests) == 0 {
		status = types.SOC2Fail
		details = "No ACL tests defined"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-004: autogroup:member usage
	check = c.getCheck("ACL-004")
	status = types.SOC2Pass
	details = "No autogroup:member usage found"
	hasAutogroupMember := false
	for _, acl := range policy.ACLs {
		for _, src := range acl.Src {
			if strings.Contains(src, "autogroup:member") {
				hasAutogroupMember = true
				break
			}
		}
	}
	if hasAutogroupMember {
		status = types.SOC2Fail
		details = "autogroup:member grants access to external users"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-005: AutoApprovers
	check = c.getCheck("ACL-005")
	status = types.SOC2Pass
	details = "No auto-approvers configured"
	if policy.AutoApprovers != nil {
		routeCount := len(policy.AutoApprovers.Routes)
		exitCount := len(policy.AutoApprovers.ExitNode)
		if routeCount > 0 || exitCount > 0 {
			status = types.SOC2Fail
			details = fmt.Sprintf("Auto-approvers: %d routes, %d exit nodes", routeCount, exitCount)
		}
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-006: tagOwners misconfiguration
	check = c.getCheck("ACL-006")
	status = types.SOC2Pass
	details = "tagOwners configuration OK"
	hasBroadTagOwners := false
	for _, owners := range policy.TagOwners {
		for _, owner := range owners {
			if owner == "*" || strings.Contains(owner, "autogroup:member") {
				hasBroadTagOwners = true
				break
			}
		}
	}
	if hasBroadTagOwners {
		status = types.SOC2Fail
		details = "tagOwners grants privileges too broadly"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-007: autogroup:danger-all
	check = c.getCheck("ACL-007")
	status = types.SOC2Pass
	details = "No autogroup:danger-all usage"
	if aclHuJSON != nil && strings.Contains(aclHuJSON.ACL, "autogroup:danger-all") {
		status = types.SOC2Fail
		details = "autogroup:danger-all grants access to everyone"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-008: Groups defined
	check = c.getCheck("ACL-008")
	status = types.SOC2Pass
	details = fmt.Sprintf("%d groups defined", len(policy.Groups))
	if len(policy.Groups) == 0 {
		status = types.SOC2Fail
		details = "No groups defined in ACL policy"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	// ACL-009: Legacy ACLs vs grants
	check = c.getCheck("ACL-009")
	status = types.SOC2Pass
	details = "Using grants (modern format)"
	if len(policy.ACLs) > 0 && len(policy.Grants) == 0 {
		status = types.SOC2Fail
		details = "Using legacy ACLs instead of grants"
	} else if len(policy.ACLs) > 0 && len(policy.Grants) > 0 {
		details = "Mixed ACLs and grants"
	}
	tests = append(tests, types.SOC2ControlTest{
		ResourceType: "acl_policy",
		ResourceID:   "policy",
		ResourceName: "ACL Policy",
		CheckID:      check.ID,
		CheckTitle:   check.Title,
		CCCodes:      check.CCMappings,
		Status:       status,
		Details:      details,
		TestedAt:     now,
	})

	return tests
}

// evaluateSSH tests SSH configuration against SSH-* checks
func (c *SOC2Collector) evaluateSSH(policy ACLPolicy, now time.Time) []types.SOC2ControlTest {
	var tests []types.SOC2ControlTest

	// If no SSH rules, create N/A entries
	if len(policy.SSH) == 0 {
		for _, checkID := range []string{"SSH-001", "SSH-002"} {
			check := c.getCheck(checkID)
			tests = append(tests, types.SOC2ControlTest{
				ResourceType: "ssh_config",
				ResourceID:   "policy",
				ResourceName: "SSH Configuration",
				CheckID:      check.ID,
				CheckTitle:   check.Title,
				CCCodes:      check.CCMappings,
				Status:       types.SOC2NA,
				Details:      "No SSH rules configured",
				TestedAt:     now,
			})
		}
		return tests
	}

	// Evaluate each SSH rule
	for i, rule := range policy.SSH {
		ruleID := fmt.Sprintf("ssh-rule-%d", i+1)
		ruleName := fmt.Sprintf("SSH Rule %d", i+1)
		if len(rule.Dst) > 0 {
			ruleName = fmt.Sprintf("SSH Rule: %s", strings.Join(rule.Dst, ", "))
		}

		// SSH-001: Session recording
		check := c.getCheck("SSH-001")
		status := types.SOC2Pass
		details := "Session recording enforced"
		if !rule.EnforceRecorder {
			if len(rule.Recorder) == 0 {
				status = types.SOC2Fail
				details = "No session recording configured"
			} else {
				details = "Session recording configured but not enforced"
			}
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "ssh_rule",
			ResourceID:   ruleID,
			ResourceName: ruleName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})

		// SSH-002: Check mode for high-risk access
		check = c.getCheck("SSH-002")
		status = types.SOC2Pass
		details = "Check mode configured"
		isHighRisk := false
		for _, user := range rule.Users {
			if user == "root" || user == "*" {
				isHighRisk = true
				break
			}
		}
		if isHighRisk && rule.CheckPeriod == "" {
			status = types.SOC2Fail
			details = "High-risk SSH access (root/*) without check mode"
		} else if isHighRisk {
			details = fmt.Sprintf("High-risk access with check period: %s", rule.CheckPeriod)
		}
		tests = append(tests, types.SOC2ControlTest{
			ResourceType: "ssh_rule",
			ResourceID:   ruleID,
			ResourceName: ruleName,
			CheckID:      check.ID,
			CheckTitle:   check.Title,
			CCCodes:      check.CCMappings,
			Status:       status,
			Details:      details,
			TestedAt:     now,
		})
	}

	return tests
}

// getCheck retrieves check info by ID
func (c *SOC2Collector) getCheck(id string) types.CheckInfo {
	for _, check := range c.registry.All() {
		if check.ID == id {
			return check
		}
	}
	return types.CheckInfo{ID: id, Title: "Unknown check"}
}

// parseVersionForSOC2 extracts major/minor from version string
func parseVersionForSOC2(version string, re *regexp.Regexp) (major, minor int, ok bool) {
	matches := re.FindStringSubmatch(version)
	if len(matches) < 3 {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(matches[1])
	minor, _ = strconv.Atoi(matches[2])
	return major, minor, true
}
