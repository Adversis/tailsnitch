package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tailscale/hujson"

	"tailsnitch/pkg/client"
	"tailsnitch/pkg/types"
)

// isAuthError checks if an error indicates authentication failure
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "API token invalid") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "Forbidden")
}

// Auditor orchestrates all security audits
type Auditor struct {
	client *client.Client
}

// New creates a new auditor
func New(c *client.Client) *Auditor {
	return &Auditor{client: c}
}

// Run executes all audit checks and returns a report
func (a *Auditor) Run(ctx context.Context) (*types.AuditReport, error) {
	report := &types.AuditReport{
		Timestamp: time.Now(),
		Tailnet:   a.client.Tailnet(),
	}

	// Get ACL policy for checks that need it
	var policy ACLPolicy
	aclHuJSON, err := a.client.GetACLHuJSON(ctx)
	if err != nil {
		// Check for authentication errors - fail fast
		if isAuthError(err) {
			return nil, fmt.Errorf("authentication failed: %w\n\nPlease check your TSKEY environment variable contains a valid API key.\nGenerate a new key at: https://login.tailscale.com/admin/settings/keys", err)
		}

		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "SYS-001",
			Title:       "Could not retrieve ACL policy",
			Severity:    types.High,
			Category:    types.AccessControl,
			Description: fmt.Sprintf("Failed to retrieve ACL policy: %v. ACL-related checks will be skipped.", err),
			Remediation: "Verify API key has sufficient permissions to read ACL policy.",
			Pass:        false,
		})
	} else {
		// Standardize HuJSON (with comments) to valid JSON first
		standardizedACL, err := hujson.Standardize([]byte(aclHuJSON.ACL))
		if err != nil {
			report.Suggestions = append(report.Suggestions, types.Suggestion{
				ID:          "SYS-002",
				Title:       "ACL policy parsing warning",
				Severity:    types.Low,
				Category:    types.AccessControl,
				Description: fmt.Sprintf("Could not standardize HuJSON ACL: %v. Some checks may be incomplete.", err),
				Pass:        true,
			})
		} else if err := json.Unmarshal(standardizedACL, &policy); err != nil {
			report.Suggestions = append(report.Suggestions, types.Suggestion{
				ID:          "SYS-002",
				Title:       "ACL policy parsing warning",
				Severity:    types.Low,
				Category:    types.AccessControl,
				Description: fmt.Sprintf("ACL policy could not be fully parsed: %v. Some checks may be incomplete.", err),
				Pass:        true,
			})
		}
	}

	// Run ACL audits
	aclAuditor := NewACLAuditor(a.client)
	aclFindings, err := aclAuditor.Audit(ctx)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "ACL-ERR",
			Title:       "ACL audit error",
			Severity:    types.Medium,
			Category:    types.AccessControl,
			Description: fmt.Sprintf("Error during ACL audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, aclFindings...)
	}

	// Run auth audits
	authAuditor := NewAuthAuditor(a.client)
	authFindings, err := authAuditor.Audit(ctx)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "AUTH-ERR",
			Title:       "Auth audit error",
			Severity:    types.Medium,
			Category:    types.Authentication,
			Description: fmt.Sprintf("Error during auth key audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, authFindings...)
	}

	// Run device audits
	deviceAuditor := NewDeviceAuditor(a.client)
	deviceFindings, err := deviceAuditor.Audit(ctx)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "DEV-ERR",
			Title:       "Device audit error",
			Severity:    types.Medium,
			Category:    types.DeviceSecurity,
			Description: fmt.Sprintf("Error during device audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, deviceFindings...)
	}

	// Run network audits (requires ACL policy)
	networkAuditor := NewNetworkAuditor(a.client)
	networkFindings, err := networkAuditor.Audit(ctx, policy)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "NET-ERR",
			Title:       "Network audit error",
			Severity:    types.Medium,
			Category:    types.NetworkExposure,
			Description: fmt.Sprintf("Error during network audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, networkFindings...)
	}

	// Run SSH audits (requires ACL policy)
	sshAuditor := NewSSHAuditor(a.client)
	sshFindings, err := sshAuditor.Audit(ctx, policy)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "SSH-ERR",
			Title:       "SSH audit error",
			Severity:    types.Medium,
			Category:    types.SSHSecurity,
			Description: fmt.Sprintf("Error during SSH audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, sshFindings...)
	}

	// Run logging/admin audits
	loggingAuditor := NewLoggingAuditor(a.client)
	loggingFindings, err := loggingAuditor.Audit(ctx)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "LOG-ERR",
			Title:       "Logging audit error",
			Severity:    types.Medium,
			Category:    types.LoggingAdmin,
			Description: fmt.Sprintf("Error during logging audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, loggingFindings...)
	}

	// Run DNS audits
	dnsAuditor := NewDNSAuditor(a.client)
	dnsFindings, err := dnsAuditor.Audit(ctx)
	if err != nil {
		report.Suggestions = append(report.Suggestions, types.Suggestion{
			ID:          "DNS-ERR",
			Title:       "DNS audit error",
			Severity:    types.Medium,
			Category:    types.DNSConfiguration,
			Description: fmt.Sprintf("Error during DNS audit: %v", err),
			Pass:        false,
		})
	} else {
		report.Suggestions = append(report.Suggestions, dnsFindings...)
	}

	// Calculate summary
	report.CalculateSummary()

	return report, nil
}
