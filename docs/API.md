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

Wrapper around `tailscale.com/client/tailscale/v2`, the official Tailscale API
client. It adds client-side rate limiting, typed error classification, and a
few reads the typed client does not model.

### Creating a Client

Credentials come from the environment: `TS_OAUTH_CLIENT_ID` plus
`TS_OAUTH_CLIENT_SECRET` if both are set, otherwise `TS_API_KEY`.

```go
import "github.com/Adversis/tailsnitch/pkg/client"

c, err := client.New("your-tailnet")
if err != nil {
    log.Fatal(err)
}

// Use "-" for the credential's default tailnet
c, err := client.New("-")
```

### Available Methods

```go
// Tailnet info
func (c *Client) Tailnet() string

// ACL Policy
func (c *Client) GetACL(ctx context.Context) (*ACL, error)
func (c *Client) GetACLHuJSON(ctx context.Context) (*RawACL, error)
func (c *Client) SetACLHuJSON(ctx context.Context, acl *RawACL) error
func (c *Client) SetACLHuJSONWithCollisionCheck(ctx context.Context, acl *RawACL) error

// Devices (always requested with fields=all)
func (c *Client) GetDevices(ctx context.Context) ([]*Device, error)
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*Device, error)
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) error
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error
func (c *Client) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error
func (c *Client) GetDeviceRoutes(ctx context.Context, deviceID string) (*DeviceRoutes, error)

// Keys (always listed with all=true)
func (c *Client) GetKeys(ctx context.Context) ([]Key, error)          // every key type
func (c *Client) GetAuthKeys(ctx context.Context) ([]Key, error)      // machine auth keys only
func (c *Client) GetOAuthClients(ctx context.Context) ([]Key, error)  // OAuth clients only
func (c *Client) GetKey(ctx context.Context, keyID string) (*Key, error)
func (c *Client) DeleteKey(ctx context.Context, keyID string) error
func (c *Client) CreateKey(ctx context.Context, caps KeyCapabilities) (string, *Key, error)
func (c *Client) CreateKeyWithExpiry(ctx context.Context, caps KeyCapabilities, expiry time.Duration) (string, *Key, error)

// Tailnet-wide state
func (c *Client) GetTailnetSettings(ctx context.Context) (*TailnetSettings, error)
func (c *Client) GetUsers(ctx context.Context) ([]User, error)
func (c *Client) GetWebhooks(ctx context.Context) ([]Webhook, error)
func (c *Client) GetContacts(ctx context.Context) (*Contacts, error)
func (c *Client) GetPostureIntegrations(ctx context.Context) ([]PostureIntegration, error)
func (c *Client) HasLogstream(ctx context.Context, logType LogType) (bool, error)

// DNS
func (c *Client) GetDNSConfig(ctx context.Context) (*DNSConfig, error)
```

Two request parameters matter enough to be worth stating:

- **Devices are fetched with `fields=all`.** The API's default field set omits
  `advertisedRoutes`, `enabledRoutes`, `sshEnabled`, `postureIdentity` and
  `clientConnectivity`, which the network and device checks read.
- **Keys are listed with `all=true`.** Without it the endpoint returns only the
  calling user's own keys, and for an OAuth-derived token it returns the
  tailnet's OAuth clients rather than its auth keys. `GetAuthKeys` filters to
  `keyType == "auth"` and drops revoked and invalidated keys.

### Device Type

`Device` embeds the API client's device model and adds fields it does not
model yet:

```go
type Device struct {
    tsapi.Device

    // MultipleConnections reports that several devices are connected using
    // this node key, which usually means node state was copied between
    // machines. Omitted by the API when only one connection is live.
    MultipleConnections bool
}

// LastSeenTime returns the last-seen timestamp and whether one is set. The API
// omits lastSeen for devices currently connected to control.
func (d *Device) LastSeenTime() (time.Time, bool)
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

Tailnet lock state is not exposed by the Tailscale API, so the Tailnet Lock
checks (DEV-010, DEV-012) run `tailscale lock status --json` against the local
daemon. Devices locked out by tailnet lock are visible through the API and are
reported without the CLI. You can specify a custom path to the binary:

```go
import "github.com/Adversis/tailsnitch/pkg/auditor"

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

### TailnetContext

Several checks read tailnet-wide state (settings, users, webhooks, contacts,
posture integrations, log stream configuration, OAuth clients). `Auditor.Run`
fetches it once and shares it, rather than having each parallel auditor
re-request it.

```go
tc := auditor.FetchTailnetContext(ctx, c)
```

`FetchTailnetContext` never returns an error. A credential scoped for a
read-only audit may legitimately lack access to some of these resources, so a
failure is recorded on the matching `*Err` field and leaves the rest usable.
Checks whose input is missing report that they could not read the setting; they
do not pass. Passing `nil` where a `*TailnetContext` is expected makes the
auditor fetch its own.

### Running an Audit

```go
import (
    "github.com/Adversis/tailsnitch/pkg/client"
    "github.com/Adversis/tailsnitch/pkg/auditor"
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

// Device auditor (nil TailnetContext fetches its own)
deviceAuditor := auditor.NewDeviceAuditor(c)
findings, err := deviceAuditor.Audit(ctx, nil)

// Network auditor (requires ACL policy; nil TailnetContext fetches its own)
networkAuditor := auditor.NewNetworkAuditor(c)
findings, err := networkAuditor.Audit(ctx, policy, nil)

// SSH auditor (requires ACL policy)
sshAuditor := auditor.NewSSHAuditor(c)
findings, err := sshAuditor.Audit(ctx, policy)

// Logging auditor (nil TailnetContext fetches its own)
loggingAuditor := auditor.NewLoggingAuditor(c)
findings, err := loggingAuditor.Audit(ctx, nil)

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

    "github.com/Adversis/tailsnitch/pkg/auditor"
    "github.com/Adversis/tailsnitch/pkg/client"
    "github.com/Adversis/tailsnitch/pkg/types"
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
| `TS_API_KEY` | Tailscale API key |

## API Permissions

`all:read` covers a full read-only audit. Granting scopes individually:

| Scope | Used for |
|-------|----------|
| `policy_file:read` | Tailnet policy file |
| `devices:core:read` | Device list |
| `dns:read` | DNS configuration |
| `auth_keys:read` | Machine auth keys |
| `feature_settings:read` | Tailnet settings |
| `logs:network:read` | Network flow logging setting |
| `networking_settings:read` | HTTPS certificate setting |
| `log_streaming:read` | Log stream destinations |
| `webhooks:read` | Webhook endpoints |
| `oauth_keys:read` | OAuth clients |
| `users:read` | User roles and status |
| `account_settings:read` | Security contact |
| `devices:posture_attributes:read` | Posture integrations |

Omitting a scope only affects the checks that need it: those report that they
could not read the setting rather than passing.

For fix mode, also grant `devices:core` and `auth_keys`.
