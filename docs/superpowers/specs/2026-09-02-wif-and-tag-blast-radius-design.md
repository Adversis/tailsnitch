# Workload identity federation and tag blast radius

Date: 2026-09-02
Branch: `feat/wif-and-tag-blast-radius`

## Why

Tailscale published a post-mortem on the Hugging Face intrusion. An agent read a
secret store, found a reusable Tailscale auth key in it, and used that key to
enroll 181 nodes onto the tailnet over four days. Each node received a CI tag and
everything that tag could reach.

Tailsnitch already flags the reusable key (AUTH-001, High). Two things it cannot
say today:

1. Whether workload identity federation is available as a replacement. The
   `/keys` endpoint returns federated identities, and `GetAuthKeys` discards them
   at `pkg/client/client.go:478`.
2. What a tag actually reaches. ACL-006 checks `tagOwners` — who may *apply* a
   tag. Nothing computes what the tag can *touch* once applied.

## What this is not

The tool has no business context. It cannot know whether 47 reachable devices are
CI runners or production databases, and a `tag:monitoring` that legitimately
reaches everything must not be rated CRITICAL. A check that cries wolf on correct
configuration gets muted, and then it is worth nothing for the real case.

So severity comes only from a structural fact that crosses a boundary. Counts are
reported, never judged. Where the tool cannot compute something, it says so
through `types.NotEvaluated` rather than passing.

---

## Component 1: the reach resolver

New file `pkg/auditor/reach.go`. One job: given a parsed `ACLPolicy` and the
device inventory, answer what a tag can reach.

```go
type Reach struct {
    Tag          string
    Devices      []DeviceReach // resolved, concrete
    TotalDevices int           // denominator
    Wildcard     bool          // a rule grants *:*
    Routed       []RoutedReach // CIDR destinations that a router forwards
    Egress       []*client.Device // exit nodes serving autogroup:internet
    Unresolved   []string      // dst selectors naming no device
    ViaRules     []RuleRef     // provenance
}

type DeviceReach struct {
    Device   *client.Device
    AllPorts bool     // dst was :* rather than a port list
    Ports    []string // when AllPorts is false
}

type RoutedReach struct {
    CIDR   string
    Router *client.Device // device whose EnabledRoutes cover CIDR
}

type RuleRef struct {
    Kind  string // "grant" | "acl"
    Index int
    Src   []string
    Dst   []string
}
```

### Source matching

Does a rule apply to `tag:T` as source? Only two selectors match:

- `src` contains `tag:T`
- `src` contains `*`

Everything else must **not** match. `autogroup:member`, `autogroup:admin` and
named groups all contain *users*. A tagged device is not a user, so a rule with
`src: ["autogroup:member"]` grants a tagged node nothing. Treating those as
matches would inflate every number in the report. This is the single easiest way
to get the math wrong and it gets a dedicated test.

### Destination expansion

| Destination | Resolution |
|---|---|
| `*` / `*:*` | Set `Wildcard`. Do **not** enumerate devices. |
| `tag:X:ports` | Devices whose `Tags` contain `tag:X`. |
| `group:g:ports` | Expand group to users, match devices by `User`. |
| `user@host:ports` | Match devices by `User`. |
| hostname in `policy.Hosts` | Resolve to its address, match a device by address. No match → `Unresolved`. |
| CIDR | See below — routed reach, not device reach. |
| `autogroup:internet` | Egress via exit nodes. Not a device. |
| user autogroups (`autogroup:self`, `autogroup:member`, …) | `Unresolved`. A tag has no owning user, so inventing a device set here would be fabrication. |

`Wildcard` is a flag rather than an enumeration on purpose. A rule granting `*:*`
covers every device that joins tomorrow, so rendering it as "52 of 52" understates
it.

### Routed reach — the part that is easy to get backwards

A subnet router forwards traffic to a destination CIDR. Reaching the router's own
Tailscale address on port 22 is SSH to that box; it is not routed access to
anything behind it.

So routed reach is driven by **CIDR destinations in rules**, matched against
devices' `EnabledRoutes`:

- for each dst that parses as a CIDR, find devices whose `EnabledRoutes` cover it
- record `RoutedReach{CIDR, Router}`
- a CIDR that no device routes is `Unresolved`, not an escalation

Use `EnabledRoutes` (approved) rather than `AdvertisedRoutes` (merely requested).
An advertised-but-unapproved route forwards nothing. NET-003 already reports the
unapproved ones; this resolver stays out of that.

`autogroup:internet` as a destination resolves to `Egress` via any exit node.

### Ports

`tag:prod:22` is not `tag:prod:*`. Track per-device whether reach is all-ports or
a restricted set, so output can distinguish them. Flattening the two would let a
metrics-scraping rule read as full access.

---

## Component 2: AUTH-005 and AUTH-006

`pkg/client/client.go` gains `KeyTypeFederated = "federated"` alongside the
existing consts at line 338, and `GetFederatedIdentities` mirroring
`GetOAuthClients`. The `Key` struct already carries `Issuer`, `Subject`,
`Audience`, `CustomClaimRules`, `Tags` and `Scopes`.

Both new IDs join `authKeyChecks` (`pkg/auditor/auth.go:18`) so a failed keys
fetch reports them as not evaluated.

### AUTH-005: Workload identity federation not in use

Category Authentication. CC mappings `CC6.1`, `CC6.2`, `CC6.3`.

A key is a *migration candidate* when it is reusable, non-ephemeral, tagged, and
not expired. These are the workload credentials — the shape of the key that leaked
at Hugging Face.

| State | Result |
|---|---|
| No migration candidates | Pass |
| Candidates exist, zero federated identities | Fail, Medium |
| Candidates exist, some tags covered by a federated identity | Fail, Low — name only the uncovered tags |

"Covered" means a federated identity exists whose `Tags` include the tag the
candidate key can mint.

This severity is defensible without business context: it states that a leakable
credential path exists where a non-leakable one is available. It does not claim
the key is misconfigured.

### AUTH-006: Federated identity subject admits unintended principals

Category Authentication. CC mappings `CC6.1`, `CC6.2`.

Verdict logic is issuer-agnostic, classified by where the wildcard sits:

| Subject | Result |
|---|---|
| `*`, empty, or wildcard-only | Fail, High — any principal the issuer vouches for can mint the tag |
| Wildcard in the leading segment | Fail, Low |
| Wildcard in a trailing segment | Report, no verdict |
| No wildcard | Pass |

Two supporting facts are surfaced in details, and neither sets severity on its own:

- empty `Audience` — audience binding is what stops a token minted for another
  relying party being replayed here
- absent `CustomClaimRules` — claim rules are the tightening mechanism

An empty audience alongside a wildcard subject is called out as the bad pair.

Issuer awareness lives in the remediation string only, never in verdict logic: a
recognized issuer host gets a tailored sentence, an unrecognized one gets generic
guidance and the identical verdict. Verdicts must not rot when a provider changes
its subject grammar.

---

## Component 3: ACL-011

Category AccessControl. CC mappings `CC6.1`, `CC6.2`.

A tag is **mintable** when it appears in `Capabilities.Devices.Create.Tags` of a
non-revoked, non-invalid, non-expired auth key.

Fails only on a structural fact, and only for mintable tags:

| Condition | Severity |
|---|---|
| Mintable tag reaches `*:*` | High if mintable by a reusable key, else Medium |
| Mintable tag reaches a routed CIDR or exit-node egress | High if mintable by a reusable key, else Medium |
| Neither | Informational — reach table only |

Reusable versus one-off is itself a structural property of the credential, not a
judgment about the environment, so it is allowed to move severity.

The informational body reports every tag's reach ordered by breadth, marks which
tags are mintable, and lists unresolved destinations separately from counts.

When auth keys cannot be read, mintability is unknown. ACL-011 then reports the
reach table as informational and states that it could not determine mintability.
It must not pass silently — a check that did not fully run has not passed.

---

## Component 4: enrichment of AUTH-001, AUTH-002, AUTH-003

The Auth auditor gains `policy ACLPolicy, policyParsed bool, devices []*client.Device`,
wired the way the Network auditor already is at `pkg/auditor/auditor.go:156`.

For each flagged key, append one detail line naming the reach of the tags it can
mint. **Severity is unchanged.** Whether that reach is appropriate is the judgment
the tool does not have grounds to make; it supplies the fact and lets a reader who
has the context decide.

If the policy did not parse or devices are unavailable, omit the line. Never print
a reach figure that was not computed.

---

## Component 5: per-item ignore

`pkg/types/ignore.go` currently parses one check ID per line. ACL-011 will
legitimately fire on a broad-by-design tag, and with only whole-check muting the
operator loses the signal for every other tag with it.

Extend the format to accept `CHECK-ID:item`:

```
ACL-011:tag:monitoring   # backup agent, broad by design
ACL-011                  # still valid — mutes the whole check
```

`IgnoreList` gains `IsItemIgnored(checkID, item string) bool`. Whole-ID behaviour
is unchanged, so existing ignore files keep working.

What counts as the *item* is per-check and must be stated where the check is
implemented. For ACL-011 the item is the tag name (`tag:monitoring`). For checks
carrying a `FixInfo`, it is `FixableItem.ID`. A check with no defined item
notion ignores the suffix and matches on the check ID alone.

Suppressing every item of a check does not make the check pass. The finding is
still emitted with the suppressed items removed from its details; if nothing
remains, it reports as informational rather than as a satisfied control. This
keeps the ignore file from quietly converting a real gap into a green result.

Parsing subtlety: split on the *first* colon only. The item itself contains a
colon, so `ACL-011:tag:monitoring` is check `ACL-011`, item `tag:monitoring`.

---

## Component 6: LOG-001 severity

When the API confirms `NetworkFlowLoggingOn` is false, severity becomes `Low`,
matching how LOG-012 already treats a confirmed gap. The unavailable and
unknown paths are unchanged.

---

## Testing

Table-driven, targeting the traps rather than the happy path.

`reach_test.go`:
- a rule with `src: ["autogroup:member"]` grants a tag nothing
- a rule with `src: ["group:eng"]` grants a tag nothing
- `src: ["*"]` does match a tag
- `dst: ["*:*"]` sets `Wildcard` and enumerates no devices
- a CIDR destination resolves against `EnabledRoutes`, not device addresses
- a CIDR no device routes is `Unresolved`, not a `RoutedReach`
- reaching a router's own address is device reach, not routed reach
- `AdvertisedRoutes` alone produces no routed reach
- port-restricted reach is distinguished from all-ports reach

`auth_test.go`: AUTH-005 across the three states; AUTH-006 across subject shapes,
unknown issuer, empty audience, absent claim rules.

`acl_test.go`: ACL-011 fails on each structural condition; a broad tag that is
**not** mintable stays informational; unreadable auth keys degrade to
informational rather than passing.

`ignore_test.go`: per-item parsing, first-colon split, back-compatibility.

`registry_coverage_test.go` already fails on unregistered IDs, so the new checks
cannot ship undocumented.

## Documentation

- `pkg/types/registry.go` — three new entries with CC mappings
- `docs/CHECKS.md` — entries matching the existing format
- `README.md` — scope table; verify whether federated identities need
  `auth_keys:read` or a separate scope, and state the uncertainty if unverified
- `HARDENING_TAILSCALE.md` — handled separately

## Out of scope

- Burst-enrollment detection. Device `Created` plus `Tags` would surface the
  181-node shape, but CI tailnets churn nodes legitimately and the signal is weak.
- TPM node state storage and `--no-logs-no-support` detection. Both are
  client-side and not visible through the API. They belong in the hardening doc.
- Credential-injecting proxies. A separate product, not tailnet configuration.
