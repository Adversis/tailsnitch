# Tailsnitch Security Checks Reference

This document provides detailed information about all 52 security checks performed by Tailsnitch.

## Check Categories

| Category | Prefix | Count | Description |
|----------|--------|-------|-------------|
| Access Controls | ACL | 10 | ACL policy misconfigurations |
| Authentication & Keys | AUTH | 4 | Auth key security |
| Device Security | DEV | 13 | Device configuration issues |
| Network Exposure | NET | 7 | Network and routing concerns |
| SSH & Device Security | SSH | 4 | SSH access controls |
| Logging & Admin | LOG | 12 | Logging and administrative settings |
| User Management | USER | 1 | User role review |
| DNS Configuration | DNS | 1 | DNS settings |

---

## Access Control Checks (ACL)

### ACL-001: Default 'allow all' policy active

**Severity:** CRITICAL

**Description:** Detects when ACL policy omits both 'acls' and 'grants' fields, causing Tailscale to apply default allow-all policy where all devices can access each other.

**What it checks:**
- Presence of "acls" or "grants" field in policy
- Wildcard rules with `src: ["*"]` and `dst: ["*:*"]`
- Empty acls array with no grants (deny-all)

**Remediation:** Define explicit ACL rules following least privilege principle.

**Admin Console:** [Access Rules](https://login.tailscale.com/admin/acls/visual/general-access-rules)

**Documentation:** [ACL Samples](https://tailscale.com/kb/1192/acl-samples)

---

### ACL-002: SSH autogroup:nonroot misconfiguration

**Severity:** CRITICAL

**Description:** SSH rules with `autogroup:nonroot` users targeting tagged devices allow anyone matching `src` to SSH as ANY non-root user on the target.

**What it checks:**
- SSH rules with `autogroup:nonroot` in users
- Combined with `tag:*` destinations

**Remediation:** Replace `autogroup:nonroot` with explicit usernames when targeting tagged devices.

**Admin Console:** [SSH Rules](https://login.tailscale.com/admin/acls/visual/ssh)

**Documentation:** [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)

---

### ACL-003: No ACL tests defined

**Severity:** LOW

**Description:** ACL tests validate access controls and prevent accidental permission changes during policy updates.

**What it checks:**
- Presence of "tests" section in ACL
- Both "accept" and "deny" assertions exist

**Remediation:** Add tests section with both accept and deny assertions.

**Admin Console:** [Tests](https://login.tailscale.com/admin/acls/visual/tests)

**Documentation:** [Security Hardening](https://tailscale.com/kb/1196/security-hardening)

---

### ACL-004: autogroup:member grants access to external users

**Severity:** MEDIUM

**Description:** Using `autogroup:member` in ACLs also grants access to external invited users who have shared devices.

**What it checks:**
- ACL rules with `autogroup:member` in source

**Remediation:** Review rules using `autogroup:member` and consider specific groups instead.

**Admin Console:** [Access Rules](https://login.tailscale.com/admin/acls/visual/general-access-rules)

**Documentation:** [Policy Syntax](https://tailscale.com/kb/1337/policy-syntax)

---

### ACL-005: AutoApprovers bypass administrative route approval

**Severity:** MEDIUM/LOW

**Description:** AutoApprovers automatically approve subnet routes and exit nodes without admin intervention.

**What it checks:**
- `*` or `autogroup:member` in auto-approvers (MEDIUM)
- Any auto-approvers configured (LOW)

**Remediation:** Use specific tags rather than broad groups for auto-approval.

**Admin Console:** [Auto Approvers](https://login.tailscale.com/admin/acls/visual/auto-approvers)

**Documentation:** [Policy Syntax](https://tailscale.com/kb/1337/policy-syntax)

---

### ACL-006: tagOwners grants tag privileges too broadly

**Severity:** CRITICAL

**Description:** Overly permissive tagOwners settings allow privilege escalation - anyone who can apply tags can gain tag-based ACL access.

**What it checks:**
- Tags owned by `autogroup:member` or `*`

**Remediation:** Restrict tagOwners to `autogroup:admin` or specific security groups.

**Admin Console:** [Tag Owners](https://login.tailscale.com/admin/acls/visual/tag-owners)

**Documentation:** [Tags](https://tailscale.com/kb/1068/tags)

---

### ACL-007: autogroup:danger-all grants access to everyone

**Severity:** CRITICAL

**Description:** `autogroup:danger-all` matches ALL users and devices including external users, shared nodes, and tagged devices - the most permissive autogroup.

**What it checks:**
- `autogroup:danger-all` in ACL rules, SSH rules, tagOwners, autoApprovers

**Remediation:** Replace with specific groups or `autogroup:member`.

**Admin Console:** [Access Rules](https://login.tailscale.com/admin/acls/visual/general-access-rules)

**Documentation:** [Policy Syntax](https://tailscale.com/kb/1337/policy-syntax)

---

### ACL-008: No groups defined in ACL policy

**Severity:** INFO

**Description:** Groups enable logical organization of users for ACL rules, making policy management easier.

**What it checks:**
- Presence of groups in policy

**Remediation:** Define groups to organize users logically.

**Admin Console:** [Groups](https://login.tailscale.com/admin/acls/visual/groups)

**Documentation:** [Policy Syntax](https://tailscale.com/kb/1337/policy-syntax)

---

### ACL-009: Using legacy ACLs instead of grants

**Severity:** INFO

**Description:** Grants are a newer, more flexible format supporting app-level permissions and better composability.

**What it checks:**
- Whether policy uses only legacy ACLs vs grants format

**Remediation:** Consider migrating to grants for new configurations.

**Admin Console:** [Access Rules](https://login.tailscale.com/admin/acls/visual/general-access-rules)

**Documentation:** [Grants](https://tailscale.com/kb/1324/grants)

---

### ACL-010: Taildrop file sharing configuration

**Severity:** INFO

**Description:** Taildrop allows direct file transfer between devices. Review if this aligns with data transfer policies.

**What it checks:**
- nodeAttrs for taildrop configuration
- Default is enabled for all devices

**Remediation:** Disable via nodeAttrs if Taildrop poses data exfiltration risk.

**Admin Console:** [Node Attributes](https://login.tailscale.com/admin/acls/visual/node-attributes)

**Documentation:** [Taildrop](https://tailscale.com/kb/1106/taildrop)

---

## Authentication Checks (AUTH)

### AUTH-001: Reusable auth keys exist

**Severity:** HIGH

**Description:** Reusable auth keys can add unlimited devices if stolen, until they expire.

**What it checks:**
- Keys with `Capabilities.Devices.Create.Reusable = true`

**Remediation:** Store in secrets manager. Prefer one-off keys. Review and delete unnecessary reusable keys.

**Admin Console:** [Auth Keys](https://login.tailscale.com/admin/settings/keys)

**Documentation:** [Auth Keys](https://tailscale.com/kb/1085/auth-keys)

---

### AUTH-002: Auth keys with long expiry period

**Severity:** HIGH

**Description:** Keys with >90 days expiry increase the exposure window if compromised.

**What it checks:**
- Keys with more than 90 days until expiry

**Remediation:** Use shorter expiry periods to reduce risk.

**Admin Console:** [Auth Keys](https://login.tailscale.com/admin/settings/keys)

**Documentation:** [Auth Keys](https://tailscale.com/kb/1085/auth-keys)

---

### AUTH-003: Pre-authorized auth keys bypass device approval

**Severity:** HIGH

**Description:** Pre-authorized keys allow devices to join without admin approval.

**What it checks:**
- Keys with `Capabilities.Devices.Create.Preauthorized = true`

**Remediation:** Restrict to essential automation. Use webhooks to alert on new devices.

**Admin Console:** [Auth Keys](https://login.tailscale.com/admin/settings/keys)

**Documentation:** [Auth Keys](https://tailscale.com/kb/1085/auth-keys)

---

### AUTH-004: Non-ephemeral keys may be used for CI/CD

**Severity:** MEDIUM

**Description:** For CI/CD workloads, ephemeral keys are recommended as nodes are auto-removed after inactivity.

**What it checks:**
- Keys that are reusable but NOT ephemeral

**Remediation:** Use ephemeral keys for CI/CD. Add `tailscale logout` to scripts.

**Admin Console:** [Auth Keys](https://login.tailscale.com/admin/settings/keys)

**Documentation:** [Ephemeral Nodes](https://tailscale.com/kb/1111/ephemeral-nodes)

---

## Device Checks (DEV)

### DEV-001: Tagged devices with key expiry disabled

**Severity:** HIGH

**Description:** Tagged devices have key expiry disabled by default, creating indefinite access if compromised.

**What it checks:**
- Devices with tags AND `KeyExpiryDisabled = true`

**Remediation:** Review and enable expiry for sensitive infrastructure.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Tags](https://tailscale.com/kb/1068/tags)

---

### DEV-002: User devices tagged (should be servers only)

**Severity:** HIGH

**Description:** Tags are intended for service accounts and servers. Tagged user devices remain on network after user removal.

**What it checks:**
- Devices with tags that appear to be user devices (macbook, iphone, windows, etc.)

**Remediation:** Remove tags from end-user devices. Use tags only for servers.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Tags](https://tailscale.com/kb/1068/tags)

---

### DEV-003: Outdated Tailscale clients

**Severity:** MEDIUM

**Description:** Outdated clients may have security vulnerabilities. Includes 7-day grace period for auto-update rollout.

**What it checks:**
- Devices more than 2 minor versions behind expected (GitHub releases with 7-day grace)
- Devices older than v1.34 (no flow logs support)

**Remediation:** Enable auto-updates in Device management.

**Admin Console:** [Device Management](https://login.tailscale.com/admin/settings/device-management)

**Documentation:** [Shared Responsibility](https://tailscale.com/kb/1212/shared-responsibility)

---

### DEV-004: Stale devices not seen recently

**Severity:** MEDIUM

**Description:** Devices not seen in over 60 days may be unused.

**What it checks:**
- `LastSeen` more than 60 days ago

**Remediation:** Review and remove unused devices.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Tags](https://tailscale.com/kb/1068/tags)

---

### DEV-005: Unauthorized devices pending approval

**Severity:** MEDIUM

**Description:** Devices pending authorization cannot access the tailnet but may indicate attempted unauthorized access.

**What it checks:**
- Devices with `Authorized = false`

**Remediation:** Review and authorize legitimate devices. Investigate unknown attempts.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Device Authorization](https://tailscale.com/kb/1099/device-authorization)

---

### DEV-006: External devices in tailnet

**Severity:** INFO

**Description:** External devices are shared from other tailnets.

**What it checks:**
- Devices with `IsExternal = true`

**Remediation:** Verify shared devices should have access.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Sharing](https://tailscale.com/kb/1084/sharing)

---

### DEV-007: Potentially sensitive machine names

**Severity:** MEDIUM

**Description:** Machine names are published to CT logs when HTTPS is enabled.

**What it checks:**
- Names containing: password, secret, prod-db, IP addresses, admin, api-key, etc.

**Remediation:** Rename devices before enabling HTTPS. Use generic names.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Enabling HTTPS](https://tailscale.com/kb/1153/enabling-https)

---

### DEV-008: Devices with long key expiry periods

**Severity:** LOW/MEDIUM

**Description:** Default key expiry is 180 days. Dev devices should use shorter periods.

**What it checks:**
- Dev devices (laptops, phones) with >90 days expiry → MEDIUM
- Servers with >180 days expiry → LOW

**Remediation:** Customize key expiry: shorter for dev devices, up to 180 days for servers.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Security Hardening](https://tailscale.com/kb/1196/security-hardening)

---

### DEV-009: Device approval configuration

**Severity:** MEDIUM/INFO

**Description:** Device approval requires admin review before new devices access the tailnet.

**What it checks:**
- Heuristic: If all devices authorized with >5 devices, approval may not be enabled

**Remediation:** Enable device approval in Device management.

**Admin Console:** [Device Management](https://login.tailscale.com/admin/settings/device-management)

**Documentation:** [Device Authorization](https://tailscale.com/kb/1099/device-authorization)

---

### DEV-010: Tailnet Lock not enabled

**Severity:** HIGH

**Description:** Tailnet Lock prevents attackers from adding devices even with stolen auth keys.

**What it checks:**
- `tailscale lock status` CLI output

**Remediation:** Enable with `tailscale lock init` on a trusted node.

**Documentation:** [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)

---

### DEV-011: Unique users in tailnet

**Severity:** INFO/LOW

**Description:** Summary of users owning devices. Flags users with >10 devices.

**What it checks:**
- Device ownership count per user

**Remediation:** Audit user list periodically. Remove departed employees.

**Admin Console:** [Users](https://login.tailscale.com/admin/users)

**Documentation:** [Deprovisioning](https://tailscale.com/kb/1184/deprovisioning)

---

### DEV-012: Nodes awaiting Tailnet Lock signature

**Severity:** HIGH

**Description:** With Tailnet Lock enabled, new nodes require signatures from trusted keys.

**What it checks:**
- `tailscale lock status` for "awaiting" or "pending" nodes

**Remediation:** Review pending nodes and sign legitimate ones.

**Documentation:** [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)

---

### DEV-013: Device posture configuration

**Severity:** INFO (Manual Check)

**Description:** Device posture integrations (Intune, Jamf, CrowdStrike) restrict access based on compliance.

**What it checks:** Manual verification required

**Remediation:** Configure device posture integration if available on your plan.

**Admin Console:** [Integrations](https://login.tailscale.com/admin/settings/integrations)

**Documentation:** [Device Posture](https://tailscale.com/kb/1288/device-posture)

---

## Network Checks (NET)

### NET-001: Funnel exposes services to public internet

**Severity:** HIGH

**Description:** Tailscale Funnel routes public internet traffic to local services without Tailscale authentication.

**What it checks:**
- nodeAttrs for funnel configuration

**Remediation:** Restrict Funnel to specific users/tags. Ensure only intended services exposed.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Funnel](https://tailscale.com/kb/1223/funnel)

---

### NET-002: Exit node access configuration

**Severity:** LOW

**Description:** Exit node usage is controlled via `autogroup:internet` in ACLs.

**What it checks:**
- ACL rules with `autogroup:internet` in destinations

**Remediation:** Verify intended users have access. Exit node restrictions are all-or-nothing.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Exit Nodes](https://tailscale.com/kb/1103/exit-nodes)

---

### NET-003: Subnet routes expose trust boundary

**Severity:** HIGH

**Description:** Subnet routers are a critical trust boundary. Traffic to final destinations is UNENCRYPTED on the local network.

**What it checks:**
- Devices with AdvertisedRoutes
- Routes advertised but not enabled (pending approval)

**Remediation:** Enable stateful filtering. Restrict advertised routes to minimum required.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Subnets](https://tailscale.com/kb/1019/subnets)

---

### NET-004: HTTPS certificates publish names to CT logs

**Severity:** MEDIUM/INFO

**Description:** HTTPS certificates publish machine names to public Certificate Transparency logs.

**What it checks:**
- nodeAttrs for https/cert configuration

**Remediation:** Review machine names before enabling HTTPS. Use randomized tailnet DNS name.

**Admin Console:** [DNS](https://login.tailscale.com/admin/dns)

**Documentation:** [Enabling HTTPS](https://tailscale.com/kb/1153/enabling-https)

---

### NET-005: Exit nodes can see all internet traffic

**Severity:** MEDIUM

**Description:** Exit node operators can see browsing history, unencrypted HTTP, and DNS queries. Destination logging is disabled by default.

**What it checks:**
- Devices advertising `0.0.0.0/0` or `::/0`

**Remediation:** Only use trusted exit nodes. Enable destination logging if compliance requires.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [Exit Nodes](https://tailscale.com/kb/1103/exit-nodes)

---

### NET-006: Tailscale Serve exposes services on tailnet

**Severity:** MEDIUM

**Description:** Tailscale Serve exposes local services to the tailnet.

**What it checks:**
- nodeAttrs for serve configuration

**Remediation:** Use ACLs to restrict access to served endpoints.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve)

---

### NET-007: App connectors provide SaaS access

**Severity:** INFO

**Description:** App connectors route traffic to specific SaaS applications through your tailnet.

**What it checks:**
- Devices advertising narrow routes (/32 or /128) that aren't exit node routes

**Remediation:** Audit app connector configurations.

**Admin Console:** [Machines](https://login.tailscale.com/admin/machines)

**Documentation:** [App Connectors](https://tailscale.com/kb/1281/app-connectors)

---

## SSH Checks (SSH)

### SSH-001: SSH session recording not enforced

**Severity:** INFO

**Description:** Session recording without `enforceRecorder:true` allows sessions when recorders are unreachable.

**What it checks:**
- SSH rules with recorder configured but `enforceRecorder = false`

**Remediation:** Set `enforceRecorder:true` for compliance-critical SSH rules.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Session Recording](https://tailscale.com/kb/1246/tailscale-ssh-session-recording)

---

### SSH-002: High-risk SSH access without check mode

**Severity:** MEDIUM/HIGH

**Description:** SSH check mode requires re-authentication through IdP before connecting.

**What it checks:**
- Accept rules without check mode that have:
  - Root user access
  - Sensitive destinations (prod, db, vault, etc.)
  - Broad source access (*, autogroup:member)
  - Broad destination access (*, autogroup:tagged)

**Remediation:** Use `action: check` or `checkPeriod` for high-risk access.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)

---

### SSH-003: Session recorder UI may be exposed

**Severity:** INFO

**Description:** If recorder container web UI is enabled, it exposes recorded sessions to anyone with network access.

**What it checks:**
- Lists recorder nodes from SSH rules

**Remediation:** Verify ACL restricts port 443 access on recorder node.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Session Recording](https://tailscale.com/kb/1246/tailscale-ssh-session-recording)

---

### SSH-004: Tailscale SSH configuration

**Severity:** INFO

**Description:** Lists all SSH rules for review.

**What it checks:**
- Enumerates all SSH rules

**Remediation:** Review SSH rules regularly. Use check mode for sensitive access.

**Admin Console:** [ACLs](https://login.tailscale.com/admin/acls)

**Documentation:** [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh)

---

## Logging & Admin Checks (LOG)

### LOG-001: Network flow logs configuration

**Severity:** INFO (Manual Check)

**Description:** Network flow logs are disabled by default (Premium/Enterprise only).

**Admin Console:** [Network Logs](https://login.tailscale.com/admin/logs/network)

**Documentation:** [Network Flow Logs](https://tailscale.com/kb/1219/network-flow-logs)

---

### LOG-002: Log streaming for long-term retention

**Severity:** INFO (Manual Check)

**Description:** Config logs: 90 days, flow logs: 30 days. Streaming required for longer retention.

**Admin Console:** [Logs](https://login.tailscale.com/admin/logs)

**Documentation:** [Audit Logging](https://tailscale.com/kb/1203/audit-logging)

---

### LOG-003: Audit log limitations

**Severity:** INFO

**Description:** Audit logs have 90-day retention, no read-only action logging, no Tailscale support action logging.

**Documentation:** [Audit Logging](https://tailscale.com/kb/1203/audit-logging)

---

### LOG-004: Failed login monitoring via IdP

**Severity:** INFO (FYI)

**Description:** Failed authentication must be monitored through your identity provider.

**Documentation:** [Audit Logging](https://tailscale.com/kb/1203/audit-logging)

---

### LOG-005: Webhook secrets never expire

**Severity:** INFO (Manual Check)

**Description:** Webhook endpoint secrets have no automatic expiration.

**Admin Console:** [Webhooks](https://login.tailscale.com/admin/settings/webhooks)

**Documentation:** [Webhooks](https://tailscale.com/kb/1213/webhooks)

---

### LOG-006: OAuth clients persist after user removal

**Severity:** INFO (Manual Check)

**Description:** OAuth clients continue functioning after creating user loses access.

**Admin Console:** [OAuth](https://login.tailscale.com/admin/settings/oauth)

**Documentation:** [OAuth Clients](https://tailscale.com/kb/1215/oauth-clients)

---

### LOG-007: SCIM API keys never expire

**Severity:** INFO (Manual Check)

**Description:** SCIM API keys have no automatic expiration.

**Admin Console:** [SCIM](https://login.tailscale.com/admin/settings/scim)

**Documentation:** [Key Management](https://tailscale.com/kb/1252/key-secret-management)

---

### LOG-008: Passkey-authenticated backup admin

**Severity:** INFO (Manual Check)

**Description:** If SSO IdP fails, users may be locked out without a passkey-authenticated admin.

**Admin Console:** [User Management](https://login.tailscale.com/admin/settings/user-management)

**Documentation:** [Passkey Admin](https://tailscale.com/kb/1341/tailnet-passkey-admin)

---

### LOG-009: MFA enforcement in identity provider

**Severity:** INFO (FYI)

**Description:** MFA must be configured in your identity provider, not Tailscale.

**Documentation:** [MFA](https://tailscale.com/kb/1075/multifactor-auth)

---

### LOG-010: DNS rebinding attack protection

**Severity:** INFO (FYI)

**Description:** HTTP services may be vulnerable to DNS rebinding if they don't validate Host headers.

**Documentation:** [Security Hardening](https://tailscale.com/kb/1196/security-hardening)

---

### LOG-011: Security contact email configuration

**Severity:** INFO (Manual Check)

**Description:** Security contact ensures your team receives security notifications.

**Admin Console:** [General Settings](https://login.tailscale.com/admin/settings/general)

**Documentation:** [Security Hardening](https://tailscale.com/kb/1196/security-hardening)

---

### LOG-012: Webhooks for critical events

**Severity:** INFO (Manual Check)

**Description:** Webhooks notify external systems about critical events (device additions, ACL changes, etc.).

**Recommended events:**
- `nodeCreated`, `nodeDeleted`, `nodeApproved`
- `aclUpdated`
- `userCreated`, `userDeleted`, `userRoleUpdated`

**Admin Console:** [Webhooks](https://login.tailscale.com/admin/settings/webhooks)

**Documentation:** [Webhooks](https://tailscale.com/kb/1213/webhooks)

---

## User Checks (USER)

### USER-001: Review user roles and ownership

**Severity:** INFO (Manual Check)

**Description:** User roles control access to tailnet administration. Regular review prevents privilege creep.

**Role hierarchy:**
1. Owner - Full control, cannot be removed
2. Admin - Full control, can manage users/ACLs/devices
3. IT Admin - Device management only
4. Network Admin - ACL and network settings
5. Auditor - Read-only access
6. Billing Admin - Billing only
7. Member - Regular user

**Admin Console:** [Users](https://login.tailscale.com/admin/users)

**Documentation:** [Roles](https://tailscale.com/kb/1352/roles)

---

## DNS Checks (DNS)

### DNS-001: MagicDNS configuration

**Severity:** INFO

**Description:** MagicDNS enables automatic DNS resolution for tailnet devices using memorable names.

**What it checks:**
- `MagicDNS` setting from DNS config

**Remediation:** Enable MagicDNS for easier device addressing.

**Admin Console:** [DNS](https://login.tailscale.com/admin/dns)

**Documentation:** [MagicDNS](https://tailscale.com/kb/1081/magicdns)
