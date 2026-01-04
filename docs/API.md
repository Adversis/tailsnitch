# Tailsnitch API Reference

This document describes the public Go packages provided by Tailsnitch for programmatic security auditing of Tailscale tailnets.

## Package Overview

```
tailsnitch/
├── pkg/
│   ├── client/     # Tailscale API client wrapper
│   ├── auditor/    # Security audit orchestration
│   ├── types/      # Shared types, constants, and check registry
│   ├── output/     # Report rendering (text/JSON)
│   └── fixer/      # Interactive remediation
```

## pkg/types

Core types used throughout the application.

### Severity Levels

```go
type Severity string

const (
    Critical      Severity = "CRITICAL"  // Immediate action required
    High          Severity = "HIGH"      // Address soon
    Medium        Severity = "MEDIUM"    // Should be reviewed
    Low           Severity = "LOW"       // Minor concern
    Informational Severity = "INFO"      // For awareness
)
```

The `Severity.Order()` method returns numeric priority (0=Critical, 4=Informational) for sorting.

### Categories

```go
type Category string

const (
    AccessControl    Category = "Access Controls"
    Authentication   Category = "Authentication & Keys"
    NetworkExposure  Category = "Network Exposure"
    SSHSecurity      Category = "SSH & Device Security"
    LoggingAdmin     Category = "Logging & Admin"
    DeviceSecurity   Category = "Device Security"
    DNSConfiguration Category = "DNS Configuration"
)
```

### Suggestion (Finding)

Each security check produces a `Suggestion`:

```go
type Suggestion struct {
    ID          string      `json:"id"`           // e.g., "ACL-001"
    Title       string      `json:"title"`        // Short description
    Severity    Severity    `json:"severity"`     // CRITICAL to INFO
    Category    Category    `json:"category"`     // Category grouping
    Description string      `json:"description"`  // Detailed explanation
    Remediation string      `json:"remediation"`  // How to fix
    Source      string      `json:"source"`       // KB URL reference
    Details     interface{} `json:"details"`      // Additional context
    Pass        bool        `json:"pass"`         // true if check passed
    Fix         *FixInfo    `json:"fix"`          // Remediation info
}
```

### Fix Types

```go
type FixType string

const (
    FixTypeNone     FixType = "none"     // Cannot be fixed via CLI
    FixTypeAPI      FixType = "api"      // Fixable via Tailscale API
    FixTypeManual   FixType = "manual"   // Requires admin console
    FixTypeExternal FixType = "external" // Requires external system
)
```

### FixInfo

Contains remediation guidance:

```go
type FixInfo struct {
    Type        FixType       `json:"type"`
    Description string        `json:"description"`
    AdminURL    string        `json:"admin_url"`     // Admin console link
    DocURL      string        `json:"doc_url"`       // Documentation link
    Items       []FixableItem `json:"items"`         // Specific items to fix
    AutoFixSafe bool          `json:"auto_fix_safe"` // Safe for auto-fix
}
```

### AuditReport

Complete audit output:

```go
type AuditReport struct {
    Timestamp   time.Time    `json:"timestamp"`
    Tailnet     string       `json:"tailnet"`
    Suggestions []Suggestion `json:"suggestions"`
    Summary     Summary      `json:"summary"`
}

type Summary struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
    Info     int `json:"info"`
    Passed   int `json:"passed"`
    Total    int `json:"total"`
}
```

### Filter Functions

```go
// Filter by minimum severity
func FilterBySeverity(suggestions []Suggestion, minSeverity Severity) []Suggestion

// Filter by category
func FilterByCategory(suggestions []Suggestion, category Category) []Suggestion

// Return only failed checks
func FilterFailed(suggestions []Suggestion) []Suggestion

// Filter by fix type
func FilterByFixType(suggestions []Suggestion, fixType FixType) []Suggestion

// Return suggestions with any fix info
func FilterFixable(suggestions []Suggestion) []Suggestion

// Filter by specific check IDs
func FilterByCheckIDs(suggestions []Suggestion, ids []string) []Suggestion
```

### Check Registry

The registry maps check IDs and slugs to metadata:

```go
type CheckInfo struct {
    ID       string   // e.g., "ACL-001"
    Slug     string   // e.g., "default-allow-all-policy-active"
    Title    string   // Human-readable title
    Category Category // Check category
}

type CheckRegistry struct { /* internal */ }

// All returns all registered checks
func (r *CheckRegistry) All() []CheckInfo

// Resolve converts a check name (ID or slug) to the canonical check ID
func (r *CheckRegistry) Resolve(name string) (id string, ok bool)

// ResolveAll converts a list of check names to canonical IDs
func (r *CheckRegistry) ResolveAll(names []string) ([]string, error)

// DefaultRegistry is the global instance
var DefaultRegistry *CheckRegistry
```

**Example:**

```go
// Resolve check by slug
id, ok := types.DefaultRegistry.Resolve("stale-devices")
// id = "DEV-004", ok = true

// Resolve multiple checks
ids, err := types.DefaultRegistry.ResolveAll([]string{"ACL-001", "auth-keys-exist"})
// ids = ["ACL-001", "AUTH-001"]
```

## pkg/client

Wrapper around the official Tailscale Go client.

### Creating a Client

```go
import "tailsnitch/pkg/client"

// Requires TSKEY environment variable
c, err := client.New("your-tailnet")
if err != nil {
    log.Fatal(err)
}

// Use "-" for default tailnet
c, err := client.New("-")
```

### Available Methods

```go
// Tailnet info
func (c *Client) Tailnet() string

// ACL Policy
func (c *Client) GetACL(ctx context.Context) (*tailscale.ACL, error)
func (c *Client) GetACLHuJSON(ctx context.Context) (*tailscale.ACLHuJSON, error)
func (c *Client) SetACLHuJSON(ctx context.Context, acl *tailscale.ACLHuJSON) (*tailscale.ACLHuJSON, error)

// Devices
func (c *Client) GetDevices(ctx context.Context) ([]*tailscale.Device, error)
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*tailscale.Device, error)
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) error
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error
func (c *Client) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error
func (c *Client) GetDeviceRoutes(ctx context.Context, deviceID string) (*tailscale.Routes, error)

// Auth Keys
func (c *Client) GetKeys(ctx context.Context) ([]string, error)
func (c *Client) GetKey(ctx context.Context, keyID string) (*tailscale.Key, error)
func (c *Client) DeleteKey(ctx context.Context, keyID string) error
func (c *Client) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
func (c *Client) CreateKeyWithExpiry(ctx context.Context, caps tailscale.KeyCapabilities, expiry time.Duration) (string, *tailscale.Key, error)

// DNS
func (c *Client) GetDNSConfig(ctx context.Context) (*DNSConfig, error)
```

### DNSConfig Type

```go
type DNSConfig struct {
    MagicDNS    bool
    NameServers []string
    SearchPaths []string
}
```

## pkg/auditor

Security audit orchestration.

### Tailscale Binary Configuration

For Tailnet Lock checks (DEV-010, DEV-012), the auditor needs to execute the local `tailscale` CLI binary. You can specify a custom path:

```go
import "tailsnitch/pkg/auditor"

// Set a custom path to the tailscale binary
// Path must be absolute and point to an existing file
err := auditor.SetTailscaleBinaryPath("/custom/path/to/tailscale")
if err != nil {
    log.Fatal(err)
}
```

If no custom path is set, the auditor searches these locations in order:
1. `/usr/bin/tailscale`
2. `/usr/local/bin/tailscale`
3. `/opt/homebrew/bin/tailscale` (macOS Homebrew ARM)
4. `/snap/bin/tailscale` (Ubuntu Snap)
5. `/usr/sbin/tailscale`
6. PATH lookup (with current directory rejection for security)

### Running an Audit

```go
import (
    "tailsnitch/pkg/client"
    "tailsnitch/pkg/auditor"
)

// Create client
c, err := client.New("-")
if err != nil {
    log.Fatal(err)
}

// Create auditor and run
a := auditor.New(c)
report, err := a.Run(context.Background())
if err != nil {
    log.Fatal(err)
}

// Process results
report.CalculateSummary()
for _, finding := range report.Suggestions {
    if !finding.Pass {
        fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.ID, finding.Title)
    }
}
```

### Individual Auditors

You can also run individual auditor modules:

```go
// ACL auditor
aclAuditor := auditor.NewACLAuditor(c)
findings, err := aclAuditor.Audit(ctx)

// Auth key auditor
authAuditor := auditor.NewAuthAuditor(c)
findings, err := authAuditor.Audit(ctx)

// Device auditor
deviceAuditor := auditor.NewDeviceAuditor(c)
findings, err := deviceAuditor.Audit(ctx)

// Network auditor (requires ACL policy)
networkAuditor := auditor.NewNetworkAuditor(c)
findings, err := networkAuditor.Audit(ctx, policy)

// SSH auditor (requires ACL policy)
sshAuditor := auditor.NewSSHAuditor(c)
findings, err := sshAuditor.Audit(ctx, policy)

// Logging auditor
loggingAuditor := auditor.NewLoggingAuditor(c)
findings, err := loggingAuditor.Audit(ctx)

// DNS auditor
dnsAuditor := auditor.NewDNSAuditor(c)
findings, err := dnsAuditor.Audit(ctx)
```

### Security Considerations

The auditor module implements several security measures:

- **HTTP Client Timeout**: External API calls (e.g., GitHub releases API for version checking) use a 10-second timeout to prevent hanging connections
- **PATH Hijacking Prevention**: The `tailscale` binary is located using known safe paths first, rejecting any binary found in the current working directory
- **Local Check Warnings**: Tailnet Lock checks run against the local machine's daemon and may not reflect the status of a remote tailnet being audited via `--tailnet`

### ACLPolicy Type

Parsed ACL policy structure used by auditors:

```go
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
```

## pkg/output

Report rendering utilities.

### Functions

```go
// Text outputs the audit report as formatted text with colors
func Text(w io.Writer, report *types.AuditReport, showPassing bool) error

// JSON outputs the audit report as formatted JSON
func JSON(w io.Writer, report *types.AuditReport) error

// PrintBanner prints the header banner (before audit completes)
func PrintBanner(w io.Writer, tailnetName, version, buildID string)
```

## pkg/fixer

Interactive remediation module.

### Options

```go
type Options struct {
    AutoFix  bool // Auto-select safe fixes
    DryRun   bool // Preview actions without executing
    AuditLog bool // Enable audit logging (default: true)
}
```

### Fixer

```go
// NewWithOptions creates a new Fixer with full options
func NewWithOptions(c *client.Client, report *types.AuditReport, opts Options) *Fixer

// Run starts the interactive fix process
func (f *Fixer) Run(ctx context.Context) error
```

**Example:**

```go
opts := fixer.Options{
    AutoFix:  false,
    DryRun:   true,
    AuditLog: true,
}
f := fixer.NewWithOptions(client, report, opts)
err := f.Run(ctx)
```

## Usage Example

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "tailsnitch/pkg/auditor"
    "tailsnitch/pkg/client"
    "tailsnitch/pkg/types"
)

func main() {
    // Create client
    c, err := client.New("-")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    // Run audit
    a := auditor.New(c)
    report, err := a.Run(context.Background())
    if err != nil {
        fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
        os.Exit(1)
    }

    // Calculate summary
    report.CalculateSummary()

    // Filter to high+ severity issues
    critical := types.FilterBySeverity(report.Suggestions, types.High)
    critical = types.FilterFailed(critical)

    // Output as JSON
    json.NewEncoder(os.Stdout).Encode(critical)
}
```

## Environment Variables

Tailsnitch supports two authentication methods. OAuth is preferred when both are configured.

### Option 1: OAuth Client (Recommended)

| Variable | Description |
|----------|-------------|
| `TS_OAUTH_CLIENT_ID` | OAuth client ID |
| `TS_OAUTH_CLIENT_SECRET` | OAuth client secret (`tskey-client-...`) |

### Option 2: API Key

| Variable | Description |
|----------|-------------|
| `TSKEY` | Tailscale API key |

## API Permissions

Read access required:
- ACL policy (`policy_file:read`)
- Devices (`devices:core:read`)
- Auth keys (`auth_keys:read`, optional for AUTH-* checks)
- DNS settings (`dns:read`)

For fix mode, also need: `devices:core:write`, `auth_keys:write`
