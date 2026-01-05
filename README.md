# Tailsnitch

A security auditor for Tailscale configurations. Tailsnitch scans your tailnet for 50+ misconfigurations, overly permissive access controls, and security best practice violations.

## Quick Start

```bash
# 1. Set your Tailscale API credentials
export TSKEY="tskey-api-..."

# 2. Run audit
tailsnitch

# 3. See only high-severity findings
tailsnitch --severity high

# 4. Fix some issues  ~interactively~ yolo mode
tailsnitch --fix
```

## Installation

### Download Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/Adversis/tailsnitch/releases).

**macOS users:** Remove quarantine attribute after download:
```bash
sudo xattr -rd com.apple.quarantine tailsnitch
```

### Install via Go

```bash
go install github.com/Adversis/tailsnitch@latest
```

### Build from Source

```bash
git clone https://github.com/Adversis/tailsnitch.git
cd tailsnitch
go build -o tailsnitch .
```

## Authentication

Tailsnitch supports two authentication methods. OAuth is preferred when both are configured.

### Option 1: OAuth Client (Recommended)

OAuth clients provide scoped, auditable access that doesn't expire when employees leave.

```bash
export TS_OAUTH_CLIENT_ID="..."
export TS_OAUTH_CLIENT_SECRET="tskey-client-..."
```

Create an OAuth client at: https://login.tailscale.com/admin/settings/oauth

**Required scopes for read-only audit:**
- `all:read` (simplest), or individually:
- `policy_file:read` - ACL policy
- `devices:core:read` - Device list
- `dns:read` - DNS configuration
- `auth_keys:read` - Auth keys (for AUTH checks)

**Additional scopes for fix mode:**
- `devices:core` - Delete devices, modify tags (requires tag selection)
- `auth_keys` - Delete auth keys

### Option 2: API Key

API keys operate as the user who created them and inherit that user's permissions.

```bash
export TSKEY="tskey-api-..."
```

Create an API key at: https://login.tailscale.com/admin/settings/keys

## Usage Examples

### Basic Audit

```bash
# Run full audit
tailsnitch

# Show passing checks too (verbose)
tailsnitch --verbose

# Output as JSON for processing
tailsnitch --json

# Audit a specific tailnet (when OAuth client has access to multiple)
tailsnitch --tailnet mycompany.com
```

### Filter Results

```bash
# Only show critical and high severity issues
tailsnitch --severity high

# Filter by category
tailsnitch --category access    # ACL issues
tailsnitch --category auth      # Authentication & keys
tailsnitch --category device    # Device security
tailsnitch --category network   # Network exposure
tailsnitch --category ssh       # SSH rules
tailsnitch --category log       # Logging & admin

# Run specific checks only
tailsnitch --checks ACL-001,AUTH-001,DEV-010
tailsnitch --checks stale-devices,tailnet-lock-not-enabled

# List all available checks
tailsnitch --list-checks
```

### Interactive Fix Mode

Fix mode allows you to remediate issues directly via the Tailscale API:

```bash
# Interactive fix mode
tailsnitch --fix

# Preview what would be fixed (dry run)
tailsnitch --fix --dry-run

# Auto-select safe fixes (still requires confirmation)
tailsnitch --fix --auto

# Disable audit logging of fix actions
tailsnitch --fix --no-audit-log
```

**API-fixable items:**

| Check | Action |
|-------|--------|
| AUTH-001, AUTH-002, AUTH-003 | Delete auth keys |
| AUTH-004 | Replace with ephemeral keys |
| DEV-002 | Remove tags from user devices |
| DEV-004 | Delete stale devices |
| DEV-005 | Authorize pending devices |

Fix mode also provides direct links to the admin console for issues that require manual intervention.

### SOC 2 Evidence Export

Generate evidence reports for SOC 2 audits with Common Criteria (CC) control mappings:

```bash
# Export as JSON
tailsnitch --soc2 json > soc2-evidence.json

# Export as CSV (for spreadsheets)
tailsnitch --soc2 csv > soc2-evidence.csv
```

The SOC 2 report includes:
- Per-resource test results (each device, key, ACL rule tested individually)
- CC code mappings (CC6.1, CC6.2, CC6.3, CC6.6, CC7.1, CC7.2, etc.)
- Pass/Fail/N/A status for each control test
- Timestamp for audit trail

**Example CSV output:**
```csv
resource_type,resource_id,resource_name,check_id,check_title,cc_codes,status,details,tested_at
device,node123,prod-server,DEV-001,Tagged devices with key expiry disabled,CC6.1;CC6.3,PASS,Tags: [tag:server] key expiry enabled,2025-01-05T10:30:00Z
key,tskey-auth-xxx,tskey-auth-xxx,AUTH-001,Reusable auth keys exist,CC6.1;CC6.2;CC6.3,FAIL,Reusable key expires in 45 days,2025-01-05T10:30:00Z
```

### Ignore Known Risks

Create a `.tailsnitch-ignore` file to suppress findings for known-accepted risks:

```bash
# .tailsnitch-ignore
# Ignore informational checks
ACL-008  # We intentionally don't use groups
ACL-009  # Legacy ACLs are fine for our use case

# Ignore specific medium checks with justification
DEV-006  # External devices are approved contractors
LOG-001  # Flow logs require Enterprise plan
```

**Ignore file locations (checked in order):**
1. `.tailsnitch-ignore` in current directory
2. `~/.tailsnitch-ignore` in home directory

```bash
# Use a specific ignore file
tailsnitch --ignore-file /path/to/ignore

# Disable ignore file processing entirely
tailsnitch --no-ignore
```

### JSON Export and Processing

```bash
# Export full report
tailsnitch --json > audit.json

# Extract failed checks as TSV
tailsnitch --json | jq -r '
  .suggestions
  | map(select(.pass == false))
  | .[]
  | [.id, .title, .severity, .remediation]
  | @tsv
' > findings.tsv

# Summary by severity
tailsnitch --json | jq '
  .suggestions
  | map(select(.pass == false))
  | group_by(.severity)
  | map({severity: .[0].severity, count: length})
'

# List critical/high issues with admin links
tailsnitch --json | jq -r '
  .suggestions
  | map(select(.pass == false and (.severity == "CRITICAL" or .severity == "HIGH")))
  | .[]
  | "\(.id): \(.title)\n  Fix: \(.fix.admin_url // "manual")\n"
'
```

## Command Reference

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--severity` | Filter by minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--category` | Filter by category: `access`, `auth`, `network`, `ssh`, `log`, `device`, `dns` |
| `--checks` | Run specific checks (comma-separated IDs or slugs) |
| `--list-checks` | List all available checks and exit |
| `--tailnet` | Specify tailnet to audit (default: from API key) |
| `--verbose` | Show passing checks too |
| `--fix` | Enable interactive fix mode |
| `--auto` | Auto-select safe fixes (requires `--fix`) |
| `--dry-run` | Preview fix actions without executing (requires `--fix`) |
| `--no-audit-log` | Disable audit logging of fix actions |
| `--soc2` | Export SOC 2 evidence: `json` or `csv` |
| `--tailscale-path` | Path to tailscale CLI (for Tailnet Lock checks) |
| `--ignore-file` | Path to ignore file |
| `--no-ignore` | Disable ignore file processing |
| `--version` | Show version information |

## Security Checks

Tailsnitch performs 52 security checks across 7 categories. See [docs/CHECKS.md](docs/CHECKS.md) for detailed documentation of each check.

### Critical Severity

| ID | Check | Risk |
|----|-------|------|
| ACL-001 | Default 'allow all' policy | All devices have unrestricted access |
| ACL-002 | SSH autogroup:nonroot misconfiguration | SSH as any non-root user |
| ACL-006 | tagOwners too broad | Privilege escalation via tags |
| ACL-007 | autogroup:danger-all usage | Access granted to external users |

### High Severity

| ID | Check | Risk |
|----|-------|------|
| AUTH-001 | Reusable auth keys | Unlimited device additions if stolen |
| AUTH-002 | Long expiry auth keys | Extended exposure window |
| AUTH-003 | Pre-authorized keys | Bypass device approval |
| DEV-001 | Tagged devices without key expiry | Indefinite access |
| DEV-002 | User devices tagged | Persist after user removal |
| DEV-010 | Tailnet Lock disabled | No protection against stolen keys |
| DEV-012 | Pending Tailnet Lock signatures | Unsigned nodes need review |
| NET-001 | Funnel exposure | Public internet access |
| NET-003 | Subnet router trust boundary | Unencrypted traffic on local network |
| SSH-002 | Root SSH without check mode | No re-authentication required |

### Medium Severity

| ID | Check | Risk |
|----|-------|------|
| ACL-004 | autogroup:member usage | External users included |
| ACL-005 | AutoApprovers configured | Bypass route approval |
| AUTH-004 | Non-ephemeral CI/CD keys | Stale devices accumulate |
| DEV-003 | Outdated clients | Potential vulnerabilities |
| DEV-004 | Stale devices | Unused attack surface |
| DEV-005 | Unauthorized devices | Pending approval queue |
| DEV-007 | Sensitive machine names | CT log exposure |
| DEV-009 | Device approval config | May not be enabled |
| NET-004 | HTTPS CT log exposure | Machine names public |
| NET-005 | Exit node traffic visibility | Operator sees all traffic |
| NET-006 | Serve exposure | Local services on tailnet |
| SSH-003 | Recorder UI exposure | Sessions visible to network |

### Informational

Checks for logging configuration, DNS settings, user roles, and manual verification items.

## Output Example

```
+=====================================================================+
|                    TAILSNITCH SECURITY AUDIT                        |
|            Tailnet: example.com                                     |
|            Version: 1.0.0 (build: abc123)                           |
+=====================================================================+

  Using ignore file: .tailsnitch-ignore (3 rules)

=== ACCESS CONTROLS ===================================================

[CRITICAL] ACL-001: Default 'allow all' policy active
  Your ACL policy omits the 'acls' field. Tailscale applies a
  default 'allow all' policy, granting all devices full access.

  Remediation:
  Define explicit ACL rules following least privilege principle.

  Source: https://tailscale.com/kb/1192/acl-samples
----------------------------------------------------------------------

=== AUTHENTICATION & KEYS =============================================

[HIGH] AUTH-001: Reusable auth keys exist
  Found 2 reusable auth key(s). These can be reused to add
  multiple devices if compromised.

  Details:
    - Key tskey-auth-xxx (expires in 45 days)
    - Key tskey-auth-yyy (expires in 89 days)

  Remediation:
  Store reusable keys in a secrets manager. Prefer one-off keys.

  Source: https://tailscale.com/kb/1085/auth-keys
----------------------------------------------------------------------

SUMMARY
======================================================================
  Critical: 1  High: 3  Medium: 5  Low: 2  Info: 8
  Total findings: 19  |  Passed: 33
```

## Tailnet Lock Checks

Tailnet Lock checks (DEV-010, DEV-012) require the local `tailscale` CLI and run against the **local machine's daemon**. When auditing a remote tailnet via `--tailnet`, these checks reflect local status, not the audited tailnet.

```bash
# Specify custom tailscale binary path if needed
tailsnitch --tailscale-path /opt/tailscale/bin/tailscale
```

## CI/CD Integration

Run Tailsnitch in CI/CD pipelines to catch security regressions:

```yaml
# GitHub Actions example
- name: Audit Tailscale Security
  env:
    TS_OAUTH_CLIENT_ID: ${{ secrets.TS_OAUTH_CLIENT_ID }}
    TS_OAUTH_CLIENT_SECRET: ${{ secrets.TS_OAUTH_CLIENT_SECRET }}
  run: |
    tailsnitch --json > audit.json
    # Fail if critical or high severity issues exist
    if tailsnitch --severity high --json | jq -e '.summary.critical + .summary.high > 0' > /dev/null; then
      echo "Critical or high severity issues found!"
      tailsnitch --severity high
      exit 1
    fi
```

## References

- [Tailscale Security Hardening Guide](https://tailscale.com/kb/1196/security-hardening)
- [ACL Syntax Reference](https://tailscale.com/kb/1337/policy-syntax)
- [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)
- [Audit Logging](https://tailscale.com/kb/1203/audit-logging)
- [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
