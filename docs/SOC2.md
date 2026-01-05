# SOC 2 Compliance with Tailsnitch

This guide explains how to use Tailsnitch for SOC 2 Type II audit evidence collection and demonstrates the mapping between Tailsnitch checks and SOC 2 Common Criteria (CC) controls.

## Overview

SOC 2 audits evaluate an organization's controls related to security, availability, processing integrity, confidentiality, and privacy. Tailsnitch helps collect evidence for security-related controls, specifically those in the Common Criteria (CC) framework that relate to network access and authentication.

## Generating SOC 2 Evidence

### Export Evidence Report

```bash
# JSON format (recommended for programmatic processing)
tailsnitch --soc2 json > soc2-evidence-$(date +%Y-%m-%d).json

# CSV format (for spreadsheet analysis)
tailsnitch --soc2 csv > soc2-evidence-$(date +%Y-%m-%d).csv
```

### Report Contents

The SOC 2 report tests each resource (device, auth key, ACL rule, SSH rule) against applicable security checks and includes:

| Field | Description |
|-------|-------------|
| `resource_type` | Type of resource: `device`, `key`, `acl_policy`, `ssh_rule`, `ssh_config` |
| `resource_id` | Unique identifier for the resource |
| `resource_name` | Human-readable name |
| `check_id` | Tailsnitch check ID (e.g., `AUTH-001`) |
| `check_title` | Description of the check |
| `cc_codes` | SOC 2 Common Criteria mappings (e.g., `CC6.1;CC6.2`) |
| `status` | Result: `PASS`, `FAIL`, or `N/A` |
| `details` | Specific details about the test result |
| `tested_at` | ISO 8601 timestamp of the test |

### Example Output

**JSON:**
```json
{
  "tailnet": "example.com",
  "generated_at": "2025-01-05T10:30:00Z",
  "tests": [
    {
      "resource_type": "device",
      "resource_id": "node123",
      "resource_name": "prod-server",
      "check_id": "DEV-001",
      "check_title": "Tagged devices with key expiry disabled",
      "cc_codes": ["CC6.1", "CC6.3"],
      "status": "PASS",
      "details": "Tags: [tag:server], key expiry enabled",
      "tested_at": "2025-01-05T10:30:00Z"
    }
  ],
  "summary": {
    "total": 150,
    "pass": 142,
    "fail": 6,
    "na": 2
  }
}
```

**CSV:**
```csv
resource_type,resource_id,resource_name,check_id,check_title,cc_codes,status,details,tested_at
device,node123,prod-server,DEV-001,Tagged devices with key expiry disabled,CC6.1;CC6.3,PASS,Tags: [tag:server] key expiry enabled,2025-01-05T10:30:00Z
key,tskey-auth-xxx,tskey-auth-xxx,AUTH-001,Reusable auth keys exist,CC6.1;CC6.2;CC6.3,FAIL,Reusable key expires in 45 days,2025-01-05T10:30:00Z
```

## Common Criteria Mappings

Tailsnitch checks map to the following SOC 2 Common Criteria controls:

### CC6.1 - Logical Access Security

Controls to restrict logical access to information assets.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| ACL-001 | Default 'allow all' policy | Unrestricted access violates least privilege |
| ACL-002 | SSH autogroup:nonroot | Overly permissive SSH user access |
| ACL-004 | autogroup:member usage | External users may have unintended access |
| ACL-006 | tagOwners too broad | Privilege escalation via tag assignment |
| ACL-007 | autogroup:danger-all | Access granted to all users including external |
| AUTH-001 | Reusable auth keys | Credentials can be reused indefinitely |
| AUTH-002 | Long expiry auth keys | Extended credential validity period |
| AUTH-003 | Pre-authorized keys | Bypass device approval controls |
| DEV-001 | Tagged devices key expiry | Indefinite device authentication |
| DEV-002 | User devices tagged | Identity-based access controls bypassed |
| DEV-010 | Tailnet Lock | Device enrollment controls |

### CC6.2 - Access Control

Controls for authorization and modification of access.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| ACL-001 | Default 'allow all' policy | No access restrictions defined |
| ACL-002 | SSH autogroup:nonroot | Broad SSH authorization |
| ACL-005 | AutoApprovers | Automatic authorization without review |
| ACL-006 | tagOwners | Authorization for privilege assignment |
| AUTH-003 | Pre-authorized keys | Automatic device authorization |
| DEV-005 | Unauthorized devices | Pending authorization queue |
| DEV-009 | Device approval | Device authorization workflow |
| LOG-008 | Passkey admin | Administrative access recovery |

### CC6.3 - Access Removal

Controls for timely removal of access.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| AUTH-001 | Reusable auth keys | Keys persist until expiry |
| AUTH-002 | Long expiry auth keys | Extended window before automatic removal |
| AUTH-004 | Non-ephemeral keys | Devices not auto-removed |
| DEV-001 | Tagged devices key expiry | Never-expiring device access |
| DEV-004 | Stale devices | Inactive devices retain access |
| DEV-008 | Long key expiry | Extended device authentication periods |
| DEV-013 | User device key expiry | Disabled expiry on user devices |
| LOG-005 | Webhook secrets | No automatic secret rotation |
| LOG-006 | OAuth clients | Clients persist after user removal |
| LOG-007 | SCIM keys | No automatic key expiration |

### CC6.6 - Boundary Protection

Controls to protect system boundaries.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| NET-001 | Funnel exposure | Public internet access to tailnet |
| NET-002 | Exit node access | Internet routing configuration |
| NET-003 | Subnet routes | Network perimeter extension |
| NET-004 | HTTPS CT logs | Certificate transparency exposure |
| NET-005 | Exit node traffic | Traffic routing through third party |
| NET-006 | Serve exposure | Service exposure to tailnet |
| SSH-002 | SSH check mode | SSH access without re-authentication |
| SSH-003 | Recorder UI | Session recording access |
| LOG-010 | DNS rebinding | HTTP host header validation |

### CC6.7 - Transmission Protection

Controls for protecting data in transmission.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| NET-001 | Funnel exposure | Unencrypted path to services |
| NET-002 | Exit node access | Traffic routing encryption |
| NET-003 | Subnet routes | Unencrypted traffic after router |
| NET-005 | Exit node traffic | Traffic visibility at exit node |
| NET-007 | App connectors | SaaS traffic routing |

### CC7.1 - System Operations

Controls for detecting and monitoring security events.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| DEV-003 | Outdated clients | Security patch status |
| DEV-010 | Tailnet Lock | Device enrollment monitoring |
| DEV-012 | Pending signatures | Unsigned node detection |
| LOG-001 | Network flow logs | Network traffic monitoring |
| LOG-002 | Log streaming | Log retention and forwarding |
| LOG-003 | Audit logs | Configuration change monitoring |
| LOG-010 | DNS rebinding | Attack detection |
| LOG-011 | Security contact | Security notification receipt |
| LOG-012 | Webhooks | Event notification |

### CC7.2 - Monitoring

Controls for monitoring system components.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| SSH-001 | Session recording | SSH session audit trail |
| SSH-002 | SSH check mode | Access monitoring |
| SSH-003 | Recorder UI | Session recording access |
| LOG-001 | Network flow logs | Network activity logging |
| LOG-002 | Log streaming | Centralized logging |
| LOG-003 | Audit logs | Administrative action logging |
| LOG-004 | Failed login monitoring | Authentication monitoring |
| LOG-012 | Webhooks | Real-time event monitoring |

### CC7.3 - Evaluation

Controls for evaluating security events.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| LOG-002 | Log streaming | Log analysis capability |
| LOG-011 | Security contact | Security incident communication |

### C1.1 - Confidentiality

Controls related to confidentiality commitments.

| Check ID | Title | Relevance |
|----------|-------|-----------|
| ACL-010 | Taildrop | File transfer controls |
| DEV-007 | Sensitive names | Information disclosure in CT logs |
| NET-004 | HTTPS CT logs | Machine name exposure |
| NET-005 | Exit node traffic | Traffic confidentiality |

## Audit Workflow

### 1. Pre-Audit Preparation

```bash
# Run full audit to identify issues
tailsnitch --verbose

# Focus on critical and high severity issues
tailsnitch --severity high
```

### 2. Remediate Findings

```bash
# Use fix mode to address API-fixable issues
tailsnitch --fix

# Review manual fixes in admin console
tailsnitch --fix  # Follow admin console links
```

### 3. Generate Evidence

```bash
# Generate dated evidence file
tailsnitch --soc2 json > evidence/tailscale-soc2-$(date +%Y-%m-%d).json

# Also generate CSV for auditor spreadsheets
tailsnitch --soc2 csv > evidence/tailscale-soc2-$(date +%Y-%m-%d).csv
```

### 4. Document Exceptions

Create a `.tailsnitch-ignore` file for known-accepted risks with justification:

```bash
# .tailsnitch-ignore
# Approved exceptions for SOC 2 audit

# ACL-008: Groups not used - small team, direct user references
ACL-008

# DEV-006: External devices are approved contractors
# Approved by security team on 2025-01-01, review quarterly
DEV-006

# LOG-001: Flow logs require Enterprise plan
# Risk accepted per security committee decision 2024-12-15
LOG-001
```

### 5. Periodic Evidence Collection

Schedule regular evidence collection (monthly or quarterly):

```bash
#!/bin/bash
# collect-soc2-evidence.sh
DATE=$(date +%Y-%m-%d)
tailsnitch --soc2 json > "evidence/tailscale-${DATE}.json"
tailsnitch --soc2 csv > "evidence/tailscale-${DATE}.csv"

# Also capture summary
tailsnitch --json | jq '.summary' > "evidence/summary-${DATE}.json"
```

## Evidence Retention

For SOC 2 Type II audits, retain evidence for the audit period (typically 12 months):

```bash
# Archive evidence with compression
tar -czf evidence-archive-$(date +%Y).tar.gz evidence/

# Verify JSON files are valid
for f in evidence/*.json; do
  jq empty "$f" && echo "Valid: $f"
done
```

## Integrating with GRC Tools

### Export for Import

The CSV format is designed for import into GRC (Governance, Risk, Compliance) tools:

```bash
# Convert JSON to CSV if needed
tailsnitch --soc2 json | jq -r '
  .tests[]
  | [.resource_type, .resource_id, .resource_name, .check_id, .check_title,
     (.cc_codes | join(";")), .status, .details, .tested_at]
  | @csv
'
```

### Summary Statistics

Generate summary statistics for GRC dashboards:

```bash
tailsnitch --soc2 json | jq '{
  tailnet: .tailnet,
  tested_at: .generated_at,
  total_tests: .summary.total,
  pass_rate: ((.summary.pass / .summary.total) * 100 | floor | tostring + "%"),
  failed_by_control: [
    .tests
    | map(select(.status == "FAIL"))
    | group_by(.cc_codes[0])
    | .[]
    | {control: .[0].cc_codes[0], failures: length}
  ]
}'
```
