# Tailscale Hardening Checklist

Implementation-ready security controls for Tailscale deployments. This checklist accompanies a longer piece [Tailscale Security: Threat-Based Hardening for Growing Companies](https://www.adversis.io/blogs/
tailscale-hardening-guide).

## Quick Start

1. **Identify your threat scenario** — opportunistic, targeted, or sophisticated/compliance-driven
2. **Look at your current ACLs** from admin console → Access Controls
3. **Check for `"*:*"`** — if found, you have permit-all rules that need immediate attention
4. **Run tailsnitch** to catch obvious misconfigurations before your auditors do
5. **Work through the priorities** in order, stopping when you've matched your threat model

```bash
# Audit your configuration
tailsnitch

# Check for specific issues
tailsnitch --checks=default-allow-all-policy-active,auto-approvers-bypass-admin-approval
```
---

## Threat Scenarios Quick Reference

| You Are | Primary Threats | Implement Up To |
|---------|-----------------|---------|
| Most B2B SaaS companies | Opportunistic criminals, commodity malware | Priority 2 |
| Companies with valuable data, enterprise customers | Targeted cybercrime, ransomware groups | Priority 4 |
| Sensitive industries, strict compliance | Sophisticated actors, supply chain attacks | Priority 6 |

---

## Priority 1: Non-Negotiables (Everyone)

*Scenario A minimum. If you do nothing else, do this.*

### 1.1 Replace Default ACL

- [ ] Export current ACL for audit trail
- [ ] Replace with deny-all baseline: `{"acls": []}`
- [ ] Add explicit allow rules with specific ports
- [ ] Verify no `"dst": ["*:*"]` or `"dst": ["tag:x:*"]` patterns remain
- [ ] Run `tailsnitch` to verify

> **Note on ACLs vs Grants:** Tailscale now recommends using [grants](https://tailscale.com/kb/1458/grant-examples) for all new tailnet policy file configurations. Grants provide all the capabilities of ACLs plus application-layer permissions. ACLs will continue to work indefinitely, but grants are the preferred modern approach. This checklist uses ACL syntax for compatibility, but consider migrating to grants for new deployments.

**Deny-All Baseline:**
```json
{
  "acls": []
}
```

**Minimum Viable ACL:**
```json
{
  "groups": {
    "group:engineering": ["alice@company.com", "bob@company.com"],
    "group:devops": ["charlie@company.com"],
    "group:prod-access": []
  },
  "tagOwners": {
    "tag:dev": ["autogroup:admin"],
    "tag:staging": ["autogroup:admin"],
    "tag:prod": ["autogroup:admin"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:dev:443", "tag:dev:8080", "tag:dev:3000"]
    },
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:staging:443"]
    },
    {
      "action": "accept",
      "src": ["group:devops"],
      "dst": ["tag:staging:22", "tag:staging:443", "tag:staging:5432"]
    },
    {
      "action": "accept",
      "src": ["group:prod-access"],
      "dst": ["tag:prod:22", "tag:prod:443"]
    },
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["autogroup:self:*"]
    }
  ]
}
```

### 1.2 Add Deny Tests for Critical Boundaries

Tests run on every ACL change—if they fail, the change is rejected. This is your safety net against configuration drift.

```json
{
  "tests": [
    {
      "src": "group:engineering",
      "deny": ["tag:prod:*", "tag:prod-db:5432", "tag:prod-db:3306"]
    },
    {
      "src": "group:devops",
      "accept": ["tag:bastion:22"]
    }
  ]
}
```

### 1.3 Lock Down Subnet Route Approval

Subnet routers are high-value targets—compromise one advertising a /16 and you can reach everything behind it.

- [ ] Inventory all subnet routers and advertised routes
- [ ] Restrict who can advertise routes:

```json
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/24": ["tag:vpc-router"],
      "0.0.0.0/0": ["tag:exit-node"]
    }
  }
}
```

- [ ] Never allow `autogroup:member` to auto-approve routes
- [ ] Document what's behind each subnet router

### 1.4 Enable Device Approval

- [ ] Admin console → Settings → Device management → Require approval
- [ ] Designate approvers (minimum 2)
- [ ] Document approval process

### 1.5 Audit Auth Keys

- [ ] List all auth keys: Admin console → Settings → Keys
- [ ] Revoke any reusable keys not actively needed
- [ ] Document purpose of each remaining key
- [ ] Check repositories for committed keys: `git log -p | grep -i "tskey"`

### 1.6 Secure Admin Accounts

- [ ] Verify MFA enabled on all Owner/Admin accounts
- [ ] Reduce Owner count to minimum (ideally 2)
- [ ] Set session timeout to 5 minutes idle
- [ ] Document who has administrative access

**Audit Evidence:**
- Screenshot of ACL showing explicit rules
- ACL test assertions
- Screenshot of device approval setting enabled
- Auth key inventory with documented purposes
- Admin account list with MFA status

---

## Priority 2: Visibility and Alerting



*You can't secure what you can't see. Start with management plane visibility—it's achievable without Enterprise.*

### 2.1 Configure Webhooks for Management Events

Tailscale supports [webhooks](https://tailscale.com/kb/1213/webhooks) for management plane events. Send to Slack, PagerDuty, or wherever your team actually looks.

- [ ] Configure webhook endpoint
- [ ] Enable alerts for critical events:

| Event | Priority | Why It Matters |
|-------|----------|----------------|
| `userRoleUpdated` | Critical | Someone just got admin access |
| `nodeCreated` | High | New device joined—expected? |
| `subnetIPForwardingNotEnabled` | High | Subnet router has IP forwarding disabled |
| `exitNodeIPForwardingNotEnabled` | High | Exit node has IP forwarding disabled |
| `userCreated` | High | New user—are you onboarding? |
| `nodeDeleted` | Medium | Device removed |
| `userApproved` | Medium | User was approved |

- [ ] Test webhook delivery
- [ ] Document escalation process for alerts

### 2.2 SIEM Integration (If Available)

If you have a SIEM, [Panther has published Tailscale-specific detection rules](https://github.com/panther-labs/panther-analysis/tree/main/rules/tailscale_rules) covering:

- Admin role grants
- New user creation
- Policy (ACL) changes
- Device posture changes

Even if you don't use Panther, the rule logic is useful reference.

- [ ] Export configuration audit logs to SIEM
- [ ] Configure log retention (minimum 90 days for SOC 2)
- [ ] Implement detection rules for critical events

**Audit Evidence:**
- Webhook configuration screenshot
- Alert routing documentation
- SIEM integration (if applicable)
- Log retention policy

---

## Priority 3: Segmentation and Posture

*Limit blast radius. A compromised frontend developer laptop shouldn't reach backend infrastructure.*

### 3.1 Segment by Function

```json
{
  "tagOwners": {
    "tag:frontend-dev": ["autogroup:admin"],
    "tag:backend-dev": ["autogroup:admin"],
    "tag:data-infra": ["autogroup:admin"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:frontend"],
      "dst": ["tag:frontend-dev:443", "tag:frontend-dev:3000"]
    },
    {
      "action": "accept",
      "src": ["group:backend"],
      "dst": ["tag:backend-dev:443", "tag:backend-dev:8080"]
    }
  ]
}
```

### 3.2 Add Tests for Segmentation Boundaries

```json
{
  "tests": [
    {"src": "group:frontend", "deny": ["tag:backend-dev:*", "tag:data-infra:*"]},
    {"src": "group:backend", "deny": ["tag:data-infra:*"]},
    {"src": "group:engineering", "deny": ["tag:prod:*"]},
    {"src": "tag:prod", "deny": ["autogroup:internet:*"]}
  ]
}
```

### 3.3 Enable Device Posture (If You Have EDR)

If you're already paying for CrowdStrike/SentinelOne/Defender, connect it:

```json
{
  "postures": {
    "posture:baseline": [
      "node:tsVersion >= '1.50.0'"
    ],
    "posture:compliant": [
      "node:tsVersion >= '1.50.0'",
      "node:os in ['macOS', 'Windows', 'iOS']"
    ],
    "posture:high-trust": [
      "node:tsVersion >= '1.50.0'",
      "falcon:ztaScore >= 70"
    ]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:devops"],
      "srcPosture": ["posture:high-trust"],
      "dst": ["tag:prod:22", "tag:prod:443"]
    }
  ]
}
```

- [ ] Define posture levels appropriate to your environment
- [ ] Configure EDR integration (CrowdStrike, SentinelOne, Intune/Jamf)
- [ ] Apply posture requirements to sensitive ACLs
- [ ] Test posture blocking with non-compliant device

### 3.4 Harden Subnet Routers

- [ ] Enable stateful filtering: `tailscale up --advertise-routes=10.0.0.0/24 --stateful-filtering`
- [ ] Evaluate replacing subnet routers with app connectors where possible
- [ ] Document compensating controls (security groups, NACLs) for each router

**Audit Evidence:**
- Network diagram showing segmentation
- Posture definitions and EDR integration
- Subnet router inventory with routes and compensating controls

---

## Priority 4: Access Controls

*Time-limited access, third-party management, and SSH hardening.*

### 4.1 Third-Party and Contractor Access

Third parties don't fit cleanly into employee groups. Make their access explicit and time-bounded.

- [ ] Create explicit third-party groups with expiration in name:

```json
{
  "groups": {
    "group:vendor-acme-2025q2": ["contractor@acme.com"],
    "group:msp-cloudops": ["admin@cloudops-msp.com"]
  }
}
```

- [ ] Scope third-party access narrowly:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:vendor-acme-2025q2"],
      "dst": ["tag:acme-integration:443"]
    }
  ]
}
```

- [ ] Use separate tags for resources third parties touch
- [ ] Add deny tests for third-party boundaries:

```json
{
  "tests": [
    {
      "src": "group:vendor-acme-2025q2",
      "deny": ["tag:prod:*", "tag:staging:*", "tag:internal:*"]
    }
  ]
}
```

- [ ] Schedule quarterly third-party access review

### 4.2 Time-Limited Production Access

Choose the approach you'll actually maintain:

**Option 1: Manual process with teeth**
- [ ] Create `group:prod-access` that's normally empty
- [ ] Document request/approval process in ticketing system
- [ ] Admin adds user, sets calendar reminder to remove
- [ ] Monthly audit: anyone in the group who shouldn't be?

**Option 2: IdP-driven group sync**
- [ ] Configure IdP time-limited group membership (Okta, Azure AD, Google Workspace)
- [ ] Sync IdP groups to Tailscale
- [ ] Access expires when IdP removes membership

**Option 3: Device posture with expiring attributes**
```json
{
  "postures": {
    "posture:oncall-active": [
      "custom:oncallExpiry > now()"
    ]
  }
}
```
- [ ] Configure on-call tool integration (PagerDuty, Opsgenie)
- [ ] Test automatic expiration

**Option 4: Purpose-built JIT tooling**
- [ ] Evaluate ConductorOne, Opal, Sym, Abbey
- [ ] Implement with approval workflows and audit trails

### 4.3 Tailscale SSH

Tailscale SSH uses Tailscale identity instead of managing SSH keys. Access is controlled through ACLs.

```json
{
  "ssh": [
    {
      "action": "accept",
      "src": ["group:devops"],
      "dst": ["tag:staging"],
      "users": ["ubuntu", "deploy"]
    },
    {
      "action": "accept",
      "src": ["group:devops"],
      "dst": ["tag:prod"],
      "users": ["deploy"]
    }
  ]
}
```

**Check mode** adds human approval before the session connects:

```json
{
  "ssh": [
    {
      "action": "check",
      "src": ["group:engineering"],
      "dst": ["tag:prod"],
      "users": ["deploy"]
    }
  ]
}
```

- [ ] Define SSH access rules in ACL
- [ ] Use `check` action for production access requiring approval
- [ ] Add SSH tests:

```json
{
  "sshTests": [
    {"src": "group:engineering", "dst": ["tag:dev"], "accept": ["ubuntu"], "deny": ["root"]},
    {"src": "group:engineering", "dst": ["tag:prod"], "deny": ["root", "ubuntu", "autogroup:nonroot"]},
    {"src": "group:devops", "dst": ["tag:prod"], "accept": ["deploy"], "check": ["root"]}
  ]
}
```

**Audit Evidence:**
- Third-party group inventory with expiration dates
- JIT workflow documentation
- SSH ACL configuration
- Access grant/revoke logs

---

## Priority 5: GitOps and Testing

*Treat ACL changes like code changes.*

### 5.1 Version Control Your ACL

- [ ] Store ACL in git repository
- [ ] Require PR review for changes
- [ ] Maintain change history with commit messages

### 5.2 CI/CD Integration

```yaml
# .github/workflows/tailscale-acl.yml
name: Tailscale ACL CI
on:
  pull_request:
    paths: ['policy.hujson']
  push:
    branches: [main]
    paths: ['policy.hujson']

jobs:
  test-acl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run tailsnitch
        run: tailsnitch --severity high
      
      - name: Test ACL
        if: github.event_name == 'pull_request'
        uses: tailscale/gitops-acl-action@v1
        with:
          api-key: ${{ secrets.TS_API_KEY }}
          tailnet: ${{ secrets.TS_TAILNET }}
          action: test
      
      - name: Apply ACL
        if: github.event_name == 'push'
        uses: tailscale/gitops-acl-action@v1
        with:
          api-key: ${{ secrets.TS_API_KEY }}
          tailnet: ${{ secrets.TS_TAILNET }}
          action: apply
```

### 5.3 Comprehensive Test Suite

```json
{
  "tests": [
    // Anti-lockout
    {"src": "group:devops", "accept": ["tag:bastion:22", "tag:bastion:443"]},
    {"src": "group:prod-access", "accept": ["tag:prod:22", "tag:prod:443"]},
    
    // Security boundaries
    {"src": "group:engineering", "deny": ["tag:prod:*"]},
    {"src": "group:engineering", "deny": ["tag:prod-db:5432", "tag:prod-db:3306"]},
    {"src": "group:frontend", "deny": ["tag:backend-dev:*", "tag:data-infra:*"]},
    
    // Third-party boundaries
    {"src": "group:vendor-acme-2025q2", "deny": ["tag:prod:*", "tag:staging:*"]},
    {"src": "group:msp-cloudops", "deny": ["tag:prod-db:*"]},
    
    // Internet exposure
    {"src": "tag:prod", "deny": ["autogroup:internet:*"]},
    {"src": "tag:prod-db", "deny": ["autogroup:internet:*"]}
  ],
  "sshTests": [
    {"src": "group:engineering", "dst": ["tag:dev"], "accept": ["ubuntu"], "deny": ["root"]},
    {"src": "group:engineering", "dst": ["tag:prod"], "deny": ["root", "ubuntu", "autogroup:nonroot"]},
    {"src": "group:devops", "dst": ["tag:prod"], "accept": ["deploy"], "check": ["root"]}
  ]
}
```

**Audit Evidence:**
- Git repository with ACL history
- CI/CD pipeline configuration
- Screenshot of failed test blocking deployment

---

## Priority 6: High-Security Controls

*For sensitive industries, strict compliance requirements, or genuine nation-state concerns.*

### 6.1 Tailnet Lock

Tailnet Lock removes Tailscale's coordination servers from your trust chain. New devices need cryptographic signatures from customer-controlled signing nodes.

**When you need this:**
- Compliance frameworks requiring customer-controlled key management
- Defense contractors or sensitive industries
- Enterprise customers who specifically ask about control plane trust

**When you can trust the Tailscale control plane (most companies):**
For the vast majority of B2B SaaS companies, trusting Tailscale's coordination servers is reasonable. The operational burden of managing signing nodes likely exceeds the risk reduction if you're not in a sensitive industry.

If you proceed:

```bash
# Get the Tailnet Lock key for each signing node
tailscale lock

# On a trusted, hardened node, initialize with at least 2 signing nodes
# All trusted keys are passed at init time
tailscale lock init tlpub:<SIGNING_NODE_1_KEY> tlpub:<SIGNING_NODE_2_KEY>

# When new devices need to join, sign them from a signing node
tailscale lock sign nodekey:<NEW_NODE_KEY>
```

- [ ] Document signing node inventory
- [ ] Establish device signing process
- [ ] Plan for signing node unavailability
- [ ] **Never use pre-signed auth keys** (they embed the signing key and remain trusted until explicitly removed)

> **Warning:** Pre-signed auth keys create a new trusted signing key that gets encoded into the auth key. Even if the auth key is single-use, the signing key remains trusted until it's removed from the tailnet key authority. This poses a significant security risk if leaked.

### 6.2 App Connectors

Replace subnet routers with app connectors where possible to expose specific applications rather than entire subnets.

- [ ] Inventory services accessed via subnet routers
- [ ] Migrate to app connectors where feasible
- [ ] Document remaining subnet router justifications

### 6.3 Advanced Monitoring

- [ ] Cross-reference endpoint logs against server logs
- [ ] Investigate discrepancies (may indicate endpoint compromise)
- [ ] Regular penetration testing including Tailscale configuration
- [ ] Tabletop exercises for compromised endpoint scenarios

**Audit Evidence:**
- Signing node inventory and procedures
- App connector migration documentation
- Penetration test results
- Incident response procedures

---

## Operational Cadence

*Be honest about what you'll actually maintain. Consistent periodic reviews beat an elaborate checklist that gets ignored.*

### Regular Reviews

- [ ] Review webhook alerts
- [ ] Check device approval queue
- [ ] Glance at auth key list, revoke unused

### Periodic Reviews

- [ ] Audit group memberships against employee roster
- [ ] Verify offboarded employees removed
- [ ] Review ACL changes from past period
- [ ] Check posture integrations syncing (if applicable)

### Quarterly Reviews

- [ ] Full access review: who can reach what?
- [ ] Third-party access review: still needed? still scoped correctly?
- [ ] Test JIT access workflow
- [ ] Review subnet router configurations
- [ ] Update ACL tests for new resources
- [ ] ACL audit against least-privilege principle

### On Employee Departure (Immediately)

- [ ] Remove from all Tailscale groups
- [ ] Delete user from tailnet
- [ ] Revoke any auth keys they created
- [ ] Remove their devices
- [ ] Audit their recent ACL changes
- [ ] Check for tagged devices they owned

### On Third-Party Engagement End

- [ ] Remove third-party group or let it expire
- [ ] Revoke any auth keys created for engagement
- [ ] Remove tagged resources if no longer needed
- [ ] Document access removal in ticketing system

---

## Audit Evidence Summary

### Access Controls (CC6.1, CC6.6)
- [ ] Current ACL export with timestamp
- [ ] ACL test assertions (deny tests, anti-lockout)
- [ ] CI/CD pipeline showing tests run on changes
- [ ] Network segmentation diagram
- [ ] Subnet router inventory

### Access Provisioning (CC6.2)
- [ ] Device approval setting screenshot
- [ ] Auth key inventory with purposes
- [ ] JIT access workflow documentation
- [ ] Third-party access groups with expiration
- [ ] Access request/approval logs

### Access Removal (CC6.3)
- [ ] Offboarding checklist
- [ ] Sample termination showing access revocation
- [ ] Third-party access removal documentation
- [ ] Auth key revocation logs

### Monitoring (CC7.1, CC7.2)
- [ ] Webhook configuration
- [ ] Alert routing and escalation
- [ ] SIEM integration (if applicable)
- [ ] Log retention policy

### Administrative Access
- [ ] Admin account inventory with MFA status
- [ ] Session timeout configuration
- [ ] Role assignment documentation

---

## Compliance Control Mapping

| Control | SOC 2 | CIS v8 | ISO 27001 | NIST 800-53 |
|---------|-------|--------|-----------|-------------|
| Explicit ACLs | CC6.1 | 3.3 | A.8.3 | AC-3 |
| ACL Tests | CC6.1 | 4.1 | A.8.3 | AC-3 |
| Device Posture | CC6.1 | 6.4 | A.8.3 | AC-3 |
| Network Segmentation | CC6.6 | 12.2 | A.8.20 | SC-7 |
| JIT Access | CC6.1, CC6.2 | 13.5 | A.5.18 | AC-6 |
| Webhook Alerts | CC7.1, CC7.2 | 8.5 | A.8.16 | AU-2, AU-6 |
| Auth Key Management | CC6.2, CC6.3 | 6.3 | A.5.15 | AC-2 |

---

## Additional Resources

- [Full Threat Analysis](https://www.adversis.io/blogs/
tailscale-hardening-guide) — Detailed threat scenarios and architectural guidance
- [Tailscale ACL Documentation](https://tailscale.com/kb/1018/acls/)
- [Tailscale Grants Documentation](https://tailscale.com/kb/1458/grant-examples) — Recommended modern approach
- [Tailscale Webhooks](https://tailscale.com/kb/1213/webhooks)
- [Tailscale Security Bulletins](https://tailscale.com/security-bulletins/)
- [GitOps ACL Action](https://github.com/tailscale/gitops-acl-action)
- [Panther Tailscale Detection Rules](https://github.com/panther-labs/panther-analysis/tree/main/rules/tailscale_rules)

---

## Contributing

Found an issue or have a suggestion? Open a PR or issue on this repository.