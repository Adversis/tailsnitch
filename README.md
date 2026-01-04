# Tailsnitch

A security auditor for Tailscale configurations. Scans your tailnet for misconfigurations, overly permissive access controls, and security best practice violations.

## Installation

Download latest [release](https://github.com/Adversis/tailsnitch/releases) then ungatekeeper.

```
sudo xattr -rd com.apple.quarantine
```

Or go install

```bash
go install github.com/Adversis/tailsnitch@latest
```

Or build from source:

```bash
git clone https://github.com/Adversis/tailsnitch.git
cd tailsnitch
go build -o tailsnitch .
```

## Usage

```bash
# Set your Tailscale API key (see Authentication below for more info)
export TSKEY="tskey-api-..."

# Run audit
./tailsnitch

# Output as JSON
./tailsnitch --json

# Filter by severity
./tailsnitch --severity high

# Show passing checks too
./tailsnitch --verbose

# Interactive fix mode
./tailsnitch --fix
```

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--severity` | Filter by minimum severity (critical, high, medium, low, info) |
| `--category` | Filter by category (access, auth, network, ssh, log, device, dns) |
| `--checks` | Run only specific checks (comma-separated IDs or slugs) |
| `--list-checks` | List all available checks and exit |
| `--tailnet` | Specify tailnet to audit (default: from API key) |
| `--verbose` | Show passing checks |
| `--fix` | Enable interactive fix mode |
| `--auto` | Auto-select safe fixes (requires `--fix`) |
| `--dry-run` | Preview fix actions without executing (requires `--fix`) |
| `--no-audit-log` | Disable audit logging of fix actions |
| `--tailscale-path` | Path to tailscale CLI binary (for Tailnet Lock checks) |
| `--soc2` | Export SOC2 evidence report (`json` or `csv`) |

## Security Checks

Tailsnitch performs **52 security checks** across 7 categories.

### Access Controls (ACL)

| ID | Severity | Check |
|----|----------|-------|
| ACL-001 | Critical | **Default 'allow all' policy active** (Access Rules) - Detects missing `acls` field (default allow-all) or wildcard rules (`src: ["*"]`, `dst: ["*:*"]`) |
| ACL-002 | Critical | **SSH autogroup:nonroot misconfiguration** (Tailscale SSH) - SSH rules with `autogroup:nonroot` targeting tagged devices allow SSH as ANY non-root user |
| ACL-003 | Low | **No ACL tests defined** (Tests) - ACL tests validate access controls and prevent accidental permission changes |
| ACL-004 | Medium | **autogroup:member grants access to external users** (Access Rules) - Includes external invited users with shared devices |
| ACL-005 | Medium | **AutoApprovers bypass administrative route approval** (Auto Approvers) - Auto-approvers can approve subnet routes without admin intervention |
| ACL-006 | Critical | **tagOwners grants tag privileges too broadly** (Tag Owners) - Overly permissive tagOwners allows privilege escalation |
| ACL-007 | Critical | **autogroup:danger-all grants access to everyone** (Access Rules) - Matches ALL users including external users, shared nodes, and tagged devices |
| ACL-008 | Info | **No groups defined in ACL policy** (Groups) - Groups allow logical organization of users for easier policy management |
| ACL-009 | Info | **Using legacy ACLs instead of grants** (Access Rules) - Grants are a newer, more flexible format for access control |
| ACL-010 | Info | **Taildrop file sharing configuration** (Node Attributes) - Review if Taildrop aligns with data transfer policies |

### Authentication & Keys (AUTH)

| ID | Severity | Check |
|----|----------|-------|
| AUTH-001 | High | **Reusable auth keys exist** - Can be reused to add multiple devices if compromised |
| AUTH-002 | High | **Auth keys with long expiry period** - Keys with >90 days expiry increase exposure window |
| AUTH-003 | High | **Pre-authorized auth keys bypass device approval** - Devices join without admin approval |
| AUTH-004 | Medium | **Non-ephemeral keys may be used for CI/CD** - Ephemeral keys auto-remove nodes after inactivity |

### Device Security (DEV)

| ID | Severity | Check |
|----|----------|-------|
| DEV-001 | High | **Tagged devices with key expiry disabled** - Creates indefinite access if credentials compromised |
| DEV-002 | High | **User devices tagged (should be servers only)** - Tagged user devices remain on network after user removal |
| DEV-003 | Medium | **Outdated Tailscale clients** - May have security vulnerabilities |
| DEV-004 | Medium | **Stale devices not seen recently** - Devices not seen in >30 days should be reviewed |
| DEV-005 | Medium | **Unauthorized devices pending approval** - May indicate attempted unauthorized access |
| DEV-006 | Info | **External devices in tailnet** - Shared devices from other tailnets |
| DEV-007 | Medium | **Potentially sensitive machine names** - Names published to CT logs when HTTPS enabled (only runs if MagicDNS is enabled) |
| DEV-008 | Low/Medium | **Devices with long key expiry periods** - Dev devices >90 days, servers >180 days flagged |
| DEV-009 | Medium | **Device approval configuration** - Verifies device approval is enabled |
| DEV-010 | High | **Tailnet Lock not enabled** - Prevents attackers from adding devices even with stolen auth keys |
| DEV-011 | Info | **Unique users in tailnet** - Summary of users owning devices, flags users with many devices |
| DEV-012 | High | **Nodes awaiting Tailnet Lock signature** - Unsigned nodes require review when Tailnet Lock is enabled |

### Network Exposure (NET)

| ID | Severity | Check |
|----|----------|-------|
| NET-001 | High | **Funnel exposes services to public internet** - Routes traffic from public internet without Tailscale auth |
| NET-002 | Low | **Exit node access configuration** - Reviews `autogroup:internet` ACL rules |
| NET-003 | High | **Subnet routes expose trust boundary** - Traffic is UNENCRYPTED on local network after subnet router |
| NET-004 | Medium | **HTTPS certificates publish names to CT logs** - Machine names publicly exposed in Certificate Transparency |
| NET-005 | Medium | **Exit nodes can see all internet traffic** - Browsing history, HTTP content, DNS queries visible to exit node |
| NET-006 | Medium | **Tailscale Serve exposes services on tailnet** - Local services exposed to tailnet devices |
| NET-007 | Info | **App connectors provide SaaS access** - Devices with narrow routes may be app connectors |

### SSH Security (SSH)

| ID | Severity | Check |
|----|----------|-------|
| SSH-001 | Info | **SSH session recording not enforced** - Sessions can bypass recording if recorders unavailable |
| SSH-002 | High/Medium | **High-risk SSH access without check mode** - Flags root access, sensitive destinations, broad sources without re-authentication |
| SSH-003 | Info | **Session recorder UI may be exposed** - Recorder web UI exposes sessions to anyone with network access |
| SSH-004 | Info | **Tailscale SSH configuration** - Lists all SSH rules for review |

### Logging & Admin (LOG)

| ID | Severity | Check |
|----|----------|-------|
| LOG-001 | Info | **Network flow logs configuration** - Disabled by default, Premium/Enterprise only |
| LOG-002 | Info | **Log streaming for long-term retention** - Required for retention beyond 30/90 days |
| LOG-003 | Info | **Audit log limitations** - 90-day retention, no read-only action logging |
| LOG-004 | Info | **Failed login monitoring via IdP** - Must be monitored through identity provider |
| LOG-005 | Info | **Webhook secrets never expire** - Compromised secrets allow fake events |
| LOG-006 | Info | **OAuth clients persist after user removal** - Creates persistent access vectors |
| LOG-007 | Info | **SCIM API keys never expire** - Increased exposure window if compromised |
| LOG-008 | Info | **Passkey-authenticated backup admin** - Required for IdP failure recovery |
| LOG-009 | Info | **MFA enforcement in identity provider** - MFA must be configured in IdP, not Tailscale |
| LOG-010 | Info | **DNS rebinding attack protection** - Must be configured on each HTTP service |
| LOG-011 | Info | **Security contact email configuration** - Ensures receipt of security notifications |
| LOG-012 | Info | **Webhooks for critical events** - Configure webhooks for security monitoring of tailnet events |
| USER-001 | Info | **Review user roles and ownership** - Regular audit of user roles prevents privilege creep |
| DEV-013 | Info | **Device posture configuration** - Enterprise feature for device health/compliance integration |

### DNS Configuration (DNS)

| ID | Severity | Check |
|----|----------|-------|
| DNS-001 | Info | **MagicDNS configuration** - MagicDNS enables automatic DNS resolution for tailnet devices |

## Fix Mode

Use `--fix` to enter interactive fix mode, which provides:

- **API fixes** for auth keys, stale devices, and device tags
- **Direct links** to admin console for manual fixes
- **Documentation links** for external system configurations

```bash
./tailsnitch --fix
```

### API-Fixable Items

| Suggestion | Action |
|------------|--------|
| AUTH-001/002/003 | Delete auth keys |
| AUTH-004 | Create ephemeral replacement keys |
| DEV-002 | Remove tags from user devices |
| DEV-004 | Delete stale devices |
| DEV-005 | Authorize pending devices |

## Output Example

```
╔══════════════════════════════════════════════════════════════════╗
║                    TAILSNITCH SECURITY AUDIT                     ║
║            Tailnet: example.com                                  ║
║            Date: 2025-12-17 10:30:00                             ║
╚══════════════════════════════════════════════════════════════════╝

━━━ ACCESS CONTROLS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] ACL-001: Default 'allow all' policy active
  Your ACL policy omits the 'acls' field. Tailscale applies a
  default 'allow all' policy, granting all devices full access.

  Remediation:
  Define explicit ACL rules following least privilege principle.

  Source: https://tailscale.com/kb/1192/acl-samples
────────────────────────────────────────────────────────────────────

SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Critical: 2  High: 5  Medium: 8  Low: 1  Info: 3
  Total suggestions: 19
```

## JSON Output & Export

Export results as JSON for processing with other tools:

```bash
# Output as JSON
./tailsnitch --json > audit.json

# Filter to failed checks only and export as TSV
./tailsnitch --json | jq -r '
  .suggestions
  | map(select(.pass == false))
  | .[]
  | [.id, .title, .severity, (.details // [] | if type == "array" then join("; ") else . end), .remediation, (.fix.admin_url // "")]
  | @tsv
' > audit.tsv

# Quick summary of failed checks
./tailsnitch --json | jq -r '
  .suggestions
  | map(select(.pass == false))
  | group_by(.severity)
  | map({severity: .[0].severity, count: length})
'

# List all critical/high issues with admin links
./tailsnitch --json | jq -r '
  .suggestions
  | map(select(.pass == false and (.severity == "CRITICAL" or .severity == "HIGH")))
  | .[]
  | "\(.id): \(.title)\n  Admin: \(.fix.admin_url // "N/A")\n"
'
```

### JSON Schema

```json
{
  "timestamp": "2025-12-17T10:30:00Z",
  "tailnet": "example.com",
  "suggestions": [
    {
      "id": "ACL-001",
      "title": "Default 'allow all' policy active (Access Rules)",
      "severity": "CRITICAL",
      "category": "Access Controls",
      "description": "Your ACL policy contains wildcard rules...",
      "remediation": "Define explicit ACL rules...",
      "details": ["Rule 1: src=[*] dst=[*:*]"],
      "pass": false,
      "fix": {
        "type": "manual",
        "description": "Replace wildcard rules...",
        "admin_url": "https://login.tailscale.com/admin/acls/visual/general-access-rules",
        "doc_url": "https://tailscale.com/kb/1192/acl-samples"
      }
    }
  ],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 1,
    "info": 3,
    "passed": 10,
    "total": 29
  }
}
```

## Authentication

Tailsnitch supports two authentication methods. OAuth is preferred when both are configured.

### Option 1: OAuth Client (Recommended)

OAuth clients provide scoped, auditable access that doesn't expire when users leave.

```bash
export TS_OAUTH_CLIENT_ID="..."
export TS_OAUTH_CLIENT_SECRET="tskey-client-..."
```

Create an OAuth client at: https://login.tailscale.com/admin/settings/oauth

**Required scope:** `all:read` for auditing, or these individual scopes:
- `policy_file:read` - Read ACL policy
- `devices:core:read` - List devices
- `dns:read` - Read DNS configuration
- `auth_keys:read` - List auth keys (for AUTH checks)

For fix mode, add write scopes: `devices:core:write`, `auth_keys:write`

### Option 2: API Key

API keys operate as the user who created them and inherit that user's permissions.

```bash
export TSKEY="tskey-api-..."
```

Create an API key at: https://login.tailscale.com/admin/settings/keys

## Security

Tailsnitch implements several security measures to protect against common attack vectors:

### PATH Hijacking Prevention

When executing the `tailscale` CLI binary for Tailnet Lock checks (DEV-010, DEV-012), Tailsnitch uses secure path resolution:

1. **Known safe paths first**: Checks standard installation directories (`/usr/bin/tailscale`, `/usr/local/bin/tailscale`, `/opt/homebrew/bin/tailscale`, etc.) before falling back to PATH lookup
2. **Current directory rejection**: Refuses to execute any binary found in the current working directory to prevent local hijacking attacks
3. **Absolute path validation**: All paths are resolved to absolute paths before execution

If your tailscale binary is installed in a non-standard location, use the `--tailscale-path` flag:

```bash
./tailsnitch --tailscale-path /custom/path/to/tailscale
```

The custom path must be an absolute path to an existing file.

### HTTP Client Timeouts

All external HTTP requests (e.g., GitHub API calls for version checking) use a 10-second timeout to prevent hanging connections.

### Local vs Remote Tailnet Checks

Tailnet Lock status checks (DEV-010, DEV-012) run against the **local machine's tailscale daemon**. When auditing a remote tailnet via `--tailnet`, these checks reflect the local machine's Tailnet Lock status, not necessarily the audited tailnet. The output includes warnings when this distinction is relevant.

### Conditional Checks

Some checks only run when their prerequisites are met:

| Check | Condition |
|-------|-----------|
| DEV-007 (Sensitive machine names) | Only runs when MagicDNS is enabled (names only appear in CT logs with HTTPS certs) |
| DEV-010, DEV-012 (Tailnet Lock) | Requires local `tailscale` CLI binary |

## References

- [Tailscale Security Hardening Guide](https://tailscale.com/kb/1196/security-hardening)
- [ACL Syntax Reference](https://tailscale.com/kb/1337/policy-syntax)
- [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)
- [Audit Logging](https://tailscale.com/kb/1203/audit-logging)
- [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)

## License

MIT
