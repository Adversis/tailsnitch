package auditor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/hujson"
	"golang.org/x/sync/errgroup"

	"github.com/Adversis/tailsnitch/pkg/client"
	"github.com/Adversis/tailsnitch/pkg/types"
)

// auditorResult holds the findings and error from a single auditor
type auditorResult struct {
	name     string
	findings []types.Suggestion
	err      error
}

// isAuthError checks if an error indicates authentication failure
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	// Use typed error checking first
	if errors.Is(err, client.ErrAuthentication) || errors.Is(err, client.ErrPermission) {
		return true
	}
	// Fallback to string matching for legacy compatibility
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

	// Get ACL policy for checks that need it (Network and SSH auditors)
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

	// Run all auditors in parallel using errgroup
	var (
		results []auditorResult
		mu      sync.Mutex
		g, gctx = errgroup.WithContext(ctx)
	)

	// Helper to safely append results
	appendResult := func(r auditorResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	// ACL auditor
	g.Go(func() error {
		auditor := NewACLAuditor(a.client)
		findings, err := auditor.Audit(gctx)
		appendResult(auditorResult{name: "ACL", findings: findings, err: err})
		return nil // Don't fail the group on auditor errors
	})

	// Auth auditor
	g.Go(func() error {
		auditor := NewAuthAuditor(a.client)
		findings, err := auditor.Audit(gctx)
		appendResult(auditorResult{name: "Auth", findings: findings, err: err})
		return nil
	})

	// Device auditor
	g.Go(func() error {
		auditor := NewDeviceAuditor(a.client)
		findings, err := auditor.Audit(gctx)
		appendResult(auditorResult{name: "Device", findings: findings, err: err})
		return nil
	})

	// Network auditor (uses pre-fetched ACL policy)
	g.Go(func() error {
		auditor := NewNetworkAuditor(a.client)
		findings, err := auditor.Audit(gctx, policy)
		appendResult(auditorResult{name: "Network", findings: findings, err: err})
		return nil
	})

	// SSH auditor (uses pre-fetched ACL policy)
	g.Go(func() error {
		auditor := NewSSHAuditor(a.client)
		findings, err := auditor.Audit(gctx, policy)
		appendResult(auditorResult{name: "SSH", findings: findings, err: err})
		return nil
	})

	// Logging auditor
	g.Go(func() error {
		auditor := NewLoggingAuditor(a.client)
		findings, err := auditor.Audit(gctx)
		appendResult(auditorResult{name: "Logging", findings: findings, err: err})
		return nil
	})

	// DNS auditor
	g.Go(func() error {
		auditor := NewDNSAuditor(a.client)
		findings, err := auditor.Audit(gctx)
		appendResult(auditorResult{name: "DNS", findings: findings, err: err})
		return nil
	})

	// Wait for all auditors to complete
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}

	// Process results and build error suggestions
	errorMeta := map[string]struct {
		id       string
		category types.Category
	}{
		"ACL":     {"ACL-ERR", types.AccessControl},
		"Auth":    {"AUTH-ERR", types.Authentication},
		"Device":  {"DEV-ERR", types.DeviceSecurity},
		"Network": {"NET-ERR", types.NetworkExposure},
		"SSH":     {"SSH-ERR", types.SSHSecurity},
		"Logging": {"LOG-ERR", types.LoggingAdmin},
		"DNS":     {"DNS-ERR", types.DNSConfiguration},
	}

	for _, r := range results {
		if r.err != nil {
			meta := errorMeta[r.name]
			report.Suggestions = append(report.Suggestions, types.Suggestion{
				ID:          meta.id,
				Title:       fmt.Sprintf("%s audit error", r.name),
				Severity:    types.Medium,
				Category:    meta.category,
				Description: fmt.Sprintf("Error during %s audit: %v", r.name, r.err),
				Pass:        false,
			})
		} else {
			report.Suggestions = append(report.Suggestions, r.findings...)
		}
	}

	// Calculate summary
	report.CalculateSummary()

	return report, nil
}
