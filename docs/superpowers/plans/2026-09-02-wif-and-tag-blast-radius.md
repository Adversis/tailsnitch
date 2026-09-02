# Workload Identity Federation and Tag Blast Radius Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three checks — AUTH-005, AUTH-006, ACL-011 — backed by a new policy reach resolver, so tailsnitch can say whether workload identity federation replaces a leakable auth key and what a tag actually reaches.

**Architecture:** A new `pkg/auditor/reach.go` resolves what a tag can reach by expanding policy selectors against the device inventory. Three checks consume it. Severity comes only from structural boundary-crossing facts, never from device counts.

**Tech Stack:** Go 1.24, `tailscale.com/client/tailscale/v2 v2.10.1`, `net/netip` for CIDR math, standard `testing` with table-driven tests.

**Spec:** `docs/superpowers/specs/2026-09-02-wif-and-tag-blast-radius-design.md`

## Global Constraints

- Every check ID emitted as a `ID: "XXX-000"` literal in `pkg/auditor/*.go` MUST have a `pkg/types/registry.go` entry in the same commit. `pkg/auditor/registry_coverage_test.go` scans for this and fails otherwise.
- A check that could not run reports `types.NotEvaluated(id, reason)`, never `Pass: true`. A passing finding is filtered out of default output and counted as a satisfied control.
- `GetDevices` already requests `allFields`, which is what populates `EnabledRoutes` and `AdvertisedRoutes`. Do not change it to default fields — routed reach silently becomes empty.
- Severity may be set from structural facts only (wildcard destination, boundary crossing, credential reusability). Never from a device count or a percentage.
- Run tests with `go test ./...` from the repo root. Build with `make build`.
- Commit after each task.

---

### Task 1: Reach types and source matching

**Files:**
- Create: `pkg/auditor/reach.go`
- Test: `pkg/auditor/reach_test.go`

**Interfaces:**
- Consumes: `ACLPolicy`, `Grant`, `ACLRule` from `pkg/auditor/acl.go`; `client.Device`.
- Produces: `Reach`, `DeviceReach`, `RoutedReach`, `RuleRef` types; `tagMatchesSource(tag string, src []string) bool`.

- [ ] **Step 1: Write the failing test**

```go
package auditor

import "testing"

func TestTagMatchesSource(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		src  []string
		want bool
	}{
		{"exact tag", "tag:ci", []string{"tag:ci"}, true},
		{"tag among several", "tag:ci", []string{"tag:web", "tag:ci"}, true},
		{"wildcard", "tag:ci", []string{"*"}, true},
		{"different tag", "tag:ci", []string{"tag:prod"}, false},
		{"empty src", "tag:ci", nil, false},

		// Groups and user autogroups contain USERS. A tagged device is not a
		// user, so none of these grant a tag anything. Treating them as a
		// match would inflate every reach number in the report.
		{"autogroup:member", "tag:ci", []string{"autogroup:member"}, false},
		{"autogroup:admin", "tag:ci", []string{"autogroup:admin"}, false},
		{"autogroup:self", "tag:ci", []string{"autogroup:self"}, false},
		{"named group", "tag:ci", []string{"group:eng"}, false},
		{"user email", "tag:ci", []string{"someone@example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagMatchesSource(tt.tag, tt.src); got != tt.want {
				t.Errorf("tagMatchesSource(%q, %v) = %v, want %v", tt.tag, tt.src, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestTagMatchesSource -v`
Expected: FAIL — `undefined: tagMatchesSource`

- [ ] **Step 3: Write the types and the function**

```go
package auditor

import (
	"github.com/Adversis/tailsnitch/pkg/client"
)

// Reach describes everything a single tag can touch under the tailnet policy.
type Reach struct {
	Tag          string
	Devices      []DeviceReach
	TotalDevices int
	Wildcard     bool
	Routed       []RoutedReach
	Egress       []*client.Device
	Unresolved   []string
	ViaRules     []RuleRef
}

// DeviceReach is one device a tag can reach, and on which ports.
type DeviceReach struct {
	Device   *client.Device
	AllPorts bool
	Ports    []string
}

// RoutedReach is a CIDR destination that some device forwards traffic to.
// Reaching a router's own address is device reach, not routed reach.
type RoutedReach struct {
	CIDR   string
	Router *client.Device
}

// RuleRef records which policy rule produced a piece of reach.
type RuleRef struct {
	Kind  string // "grant" or "acl"
	Index int
	Src   []string
	Dst   []string
}

// tagMatchesSource reports whether a rule with this src applies to the given
// tag. Only an exact tag match and the wildcard match. Named groups and user
// autogroups contain users, and a tagged device is not a user.
func tagMatchesSource(tag string, src []string) bool {
	for _, s := range src {
		if s == "*" || s == tag {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/auditor/ -run TestTagMatchesSource -v`
Expected: PASS, all 10 subtests

- [ ] **Step 5: Commit**

```bash
git add pkg/auditor/reach.go pkg/auditor/reach_test.go
git commit -m "Add reach types and tag source matching

Only an exact tag and the wildcard match a tag as source. Groups and
user autogroups contain users, so they grant a tagged device nothing.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi"
```

---

### Task 2: Destination parsing — target and ports

**Files:**
- Modify: `pkg/auditor/reach.go`
- Test: `pkg/auditor/reach_test.go`

**Interfaces:**
- Produces: `splitDst(dst string) (target string, ports string)`.

Grants and ACLs carry ports differently. An ACL rule writes `tag:prod:22` — the port spec is appended to the destination. A grant writes `"dst": ["tag:prod"]` with the ports in a separate `"ip": ["tcp:22"]` field. This function handles the ACL form only; grants pass their `dst` straight through with no port suffix.

- [ ] **Step 1: Write the failing test**

```go
func TestSplitDst(t *testing.T) {
	tests := []struct {
		name       string
		dst        string
		wantTarget string
		wantPorts  string
	}{
		{"tag with port", "tag:prod:22", "tag:prod", "22"},
		{"tag all ports", "tag:prod:*", "tag:prod", "*"},
		{"wildcard both", "*:*", "*", "*"},
		{"cidr with ports", "10.0.0.0/8:*", "10.0.0.0/8", "*"},
		{"port range", "tag:prod:8000-9000", "tag:prod", "8000-9000"},
		{"port list", "tag:prod:80,443", "tag:prod", "80,443"},
		{"user with port", "someone@example.com:22", "someone@example.com", "22"},
		{"no port suffix (grant form)", "tag:prod", "tag:prod", ""},
		{"bare wildcard (grant form)", "*", "*", ""},
		{"autogroup internet", "autogroup:internet:*", "autogroup:internet", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, ports := splitDst(tt.dst)
			if target != tt.wantTarget || ports != tt.wantPorts {
				t.Errorf("splitDst(%q) = (%q, %q), want (%q, %q)",
					tt.dst, target, ports, tt.wantTarget, tt.wantPorts)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestSplitDst -v`
Expected: FAIL — `undefined: splitDst`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/reach.go`:

```go
import "strings"

// portSuffix reports whether s looks like a port spec: a number, a range, a
// comma list, or the wildcard. Anything else is part of the target.
func portSuffix(s string) bool {
	if s == "" {
		return false
	}
	if s == "*" {
		return true
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != ',' && r != '-' {
			return false
		}
	}
	return true
}

// splitDst separates an ACL destination into its target and port spec.
//
// ACL rules append ports to the destination ("tag:prod:22"). Grants keep them
// in a separate ip field, so a grant destination arrives here with no suffix
// and is returned unchanged. The target itself contains colons, so the split
// is on the last colon and only when what follows looks like a port spec.
func splitDst(dst string) (target string, ports string) {
	idx := strings.LastIndex(dst, ":")
	if idx < 0 {
		return dst, ""
	}
	candidate := dst[idx+1:]
	if !portSuffix(candidate) {
		return dst, ""
	}
	return dst[:idx], candidate
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/auditor/ -run TestSplitDst -v`
Expected: PASS, all 10 subtests

- [ ] **Step 5: Commit**

```bash
git add pkg/auditor/reach.go pkg/auditor/reach_test.go
git commit -m "Split ACL destinations into target and ports

ACL rules append ports to the destination; grants keep them in a
separate ip field. Split on the last colon, and only when the suffix
looks like a port spec, because targets contain colons too.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi"
```

---

### Task 3: Routed reach and exit-node egress

**Files:**
- Modify: `pkg/auditor/reach.go`
- Test: `pkg/auditor/reach_test.go`

**Interfaces:**
- Produces: `routersFor(cidr string, devices []*client.Device) []*client.Device`, `exitNodes(devices []*client.Device) []*client.Device`, `isDefaultRoute(route string) bool`.

This is the task most likely to be implemented backwards. A subnet router forwards traffic to a destination CIDR. Reaching the router's own Tailscale address on port 22 is SSH to that box — it is not routed access to anything behind it. So routed reach is driven by CIDR destinations in rules matched against devices' `EnabledRoutes`, never by "the router device appears in the reachable set".

Use `EnabledRoutes` (approved), not `AdvertisedRoutes` (merely requested). An advertised-but-unapproved route forwards nothing. NET-003 already reports unapproved routes; this resolver stays out of that.

- [ ] **Step 1: Write the failing test**

```go
import "github.com/Adversis/tailsnitch/pkg/client"

func dev(name string, enabled, advertised []string) *client.Device {
	d := &client.Device{}
	d.Name = name
	d.EnabledRoutes = enabled
	d.AdvertisedRoutes = advertised
	return d
}

func TestRoutersFor(t *testing.T) {
	gw := dev("prod-gw", []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"})
	// Advertises but is not approved: forwards nothing.
	pending := dev("pending-gw", nil, []string{"192.168.0.0/16"})
	plain := dev("web-01", nil, nil)
	devices := []*client.Device{gw, pending, plain}

	tests := []struct {
		name string
		cidr string
		want []string
	}{
		{"exact route match", "10.0.0.0/8", []string{"prod-gw"}},
		{"subnet inside an enabled route", "10.1.2.0/24", []string{"prod-gw"}},
		{"advertised but not enabled", "192.168.0.0/16", nil},
		{"nothing routes it", "172.16.0.0/12", nil},
		{"not a cidr", "tag:prod", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routersFor(tt.cidr, devices)
			if len(got) != len(tt.want) {
				t.Fatalf("routersFor(%q) returned %d routers, want %d", tt.cidr, len(got), len(tt.want))
			}
			for i, r := range got {
				if r.Name != tt.want[i] {
					t.Errorf("router %d = %q, want %q", i, r.Name, tt.want[i])
				}
			}
		})
	}
}

func TestExitNodes(t *testing.T) {
	exit := dev("edge-01", []string{"0.0.0.0/0", "::/0"}, nil)
	gw := dev("prod-gw", []string{"10.0.0.0/8"}, nil)
	plain := dev("web-01", nil, nil)

	got := exitNodes([]*client.Device{exit, gw, plain})
	if len(got) != 1 || got[0].Name != "edge-01" {
		t.Errorf("exitNodes = %v, want [edge-01]", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run 'TestRoutersFor|TestExitNodes' -v`
Expected: FAIL — `undefined: routersFor`, `undefined: exitNodes`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/reach.go`:

```go
import "net/netip"

// isDefaultRoute reports whether a route covers all egress, which is what makes
// a device an exit node.
func isDefaultRoute(route string) bool {
	return route == "0.0.0.0/0" || route == "::/0"
}

// routersFor returns the devices that forward traffic to cidr, by matching it
// against each device's approved routes.
//
// A device is a router for cidr when one of its enabled routes covers cidr.
// Enabled routes are the approved ones; a merely advertised route forwards
// nothing, so it is ignored here. NET-003 reports advertised-but-unapproved
// routes separately.
func routersFor(cidr string, devices []*client.Device) []*client.Device {
	want, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}

	var routers []*client.Device
	for _, d := range devices {
		for _, route := range d.EnabledRoutes {
			if isDefaultRoute(route) {
				continue // exit-node egress, reported separately
			}
			have, err := netip.ParsePrefix(route)
			if err != nil {
				continue
			}
			// have covers want when it contains want's address and is no more
			// specific than want.
			if have.Bits() <= want.Bits() && have.Contains(want.Addr()) {
				routers = append(routers, d)
				break
			}
		}
	}
	return routers
}

// exitNodes returns the devices approved to carry all egress traffic.
func exitNodes(devices []*client.Device) []*client.Device {
	var nodes []*client.Device
	for _, d := range devices {
		for _, route := range d.EnabledRoutes {
			if isDefaultRoute(route) {
				nodes = append(nodes, d)
				break
			}
		}
	}
	return nodes
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/auditor/ -run 'TestRoutersFor|TestExitNodes' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/auditor/reach.go pkg/auditor/reach_test.go
git commit -m "Resolve routed reach from CIDR destinations

A subnet router forwards traffic to a destination CIDR. Reaching the
router's own address is device reach, not routed reach, so routed reach
matches CIDR destinations against approved routes. An advertised route
that was never approved forwards nothing.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi"
```

---

### Task 4: ComputeReach assembly

**Files:**
- Modify: `pkg/auditor/reach.go`
- Test: `pkg/auditor/reach_test.go`

**Interfaces:**
- Consumes: `tagMatchesSource`, `splitDst`, `routersFor`, `exitNodes` from Tasks 1-3.
- Produces: `ComputeReach(tag string, policy ACLPolicy, devices []*client.Device) Reach` and `AllTagReach(policy ACLPolicy, devices []*client.Device) []Reach`.

`AllTagReach` covers every tag named in `policy.TagOwners`, sorted broadest first: wildcard tags, then by descending device count.

- [ ] **Step 1: Write the failing test**

```go
func TestComputeReach(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}

	db := &client.Device{}
	db.Name = "db-01"
	db.Tags = []string{"tag:prod"}

	gw := dev("prod-gw", []string{"10.0.0.0/8"}, nil)
	gw.Tags = []string{"tag:infra"}

	devices := []*client.Device{web, db, gw}

	t.Run("tag reaches tagged devices on one port", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil, "tag:prod": nil},
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if r.Wildcard {
			t.Error("Wildcard set for a tag-scoped destination")
		}
		if len(r.Devices) != 2 {
			t.Fatalf("reached %d devices, want 2", len(r.Devices))
		}
		if r.Devices[0].AllPorts {
			t.Error("AllPorts set for a destination scoped to port 22")
		}
		if r.TotalDevices != 3 {
			t.Errorf("TotalDevices = %d, want 3", r.TotalDevices)
		}
	})

	t.Run("wildcard sets the flag and enumerates nothing", func(t *testing.T) {
		policy := ACLPolicy{
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if !r.Wildcard {
			t.Error("Wildcard not set for dst *:*")
		}
		if len(r.Devices) != 0 {
			t.Errorf("enumerated %d devices for a wildcard; should enumerate none", len(r.Devices))
		}
	})

	t.Run("cidr destination is routed reach, not device reach", func(t *testing.T) {
		policy := ACLPolicy{
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if len(r.Routed) != 1 || r.Routed[0].Router.Name != "prod-gw" {
			t.Fatalf("Routed = %+v, want one entry via prod-gw", r.Routed)
		}
		if len(r.Devices) != 0 {
			t.Errorf("a CIDR destination produced %d device reaches; should produce none", len(r.Devices))
		}
	})

	t.Run("unrouted cidr is unresolved, not an escalation", func(t *testing.T) {
		policy := ACLPolicy{
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"172.16.0.0/12:*"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if len(r.Routed) != 0 {
			t.Errorf("Routed = %+v for a CIDR no device routes", r.Routed)
		}
		if len(r.Unresolved) != 1 {
			t.Errorf("Unresolved = %v, want the unrouted CIDR", r.Unresolved)
		}
	})

	t.Run("autogroup source grants the tag nothing", func(t *testing.T) {
		policy := ACLPolicy{
			ACLs: []ACLRule{
				{Action: "accept", Src: []string{"autogroup:member"}, Dst: []string{"*:*"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if r.Wildcard || len(r.Devices) != 0 {
			t.Error("an autogroup:member source granted reach to a tag")
		}
	})

	t.Run("grant carries ports in the ip field", func(t *testing.T) {
		policy := ACLPolicy{
			Grants: []Grant{
				{Src: []string{"tag:ci"}, Dst: []string{"tag:prod"}, IP: []string{"tcp:22"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if len(r.Devices) != 2 {
			t.Fatalf("reached %d devices, want 2", len(r.Devices))
		}
		if r.Devices[0].AllPorts {
			t.Error("AllPorts set for a grant restricted to tcp:22")
		}
	})

	t.Run("grant with no ip field is all ports", func(t *testing.T) {
		policy := ACLPolicy{
			Grants: []Grant{
				{Src: []string{"tag:ci"}, Dst: []string{"tag:prod"}},
			},
		}
		r := ComputeReach("tag:ci", policy, devices)
		if len(r.Devices) != 2 || !r.Devices[0].AllPorts {
			t.Error("a grant with no ip restriction should reach all ports")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestComputeReach -v`
Expected: FAIL — `undefined: ComputeReach`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/reach.go`:

```go
import "sort"

// allPorts reports whether a port spec leaves every port open. An empty spec
// comes from a grant with no ip restriction, which is unrestricted.
func allPorts(ports string) bool {
	return ports == "" || ports == "*"
}

// addDevice records reach to one device, merging with an existing entry so a
// device reachable through two rules is counted once.
func (r *Reach) addDevice(d *client.Device, ports string) {
	for i := range r.Devices {
		if r.Devices[i].Device == d {
			if allPorts(ports) {
				r.Devices[i].AllPorts = true
			} else {
				r.Devices[i].Ports = append(r.Devices[i].Ports, ports)
			}
			return
		}
	}
	dr := DeviceReach{Device: d, AllPorts: allPorts(ports)}
	if !dr.AllPorts {
		dr.Ports = []string{ports}
	}
	r.Devices = append(r.Devices, dr)
}

// expandTarget resolves one destination target into the reach it grants.
func (r *Reach) expandTarget(target, ports string, policy ACLPolicy, devices []*client.Device) {
	switch {
	case target == "*":
		// Covers every device now and every device that joins later, so it is
		// recorded as a flag rather than an enumeration.
		r.Wildcard = true
		return

	case target == "autogroup:internet":
		r.Egress = append(r.Egress, exitNodes(devices)...)
		return

	case strings.HasPrefix(target, "tag:"):
		for _, d := range devices {
			for _, tag := range d.Tags {
				if tag == target {
					r.addDevice(d, ports)
					break
				}
			}
		}
		return

	case strings.HasPrefix(target, "group:"):
		members := policy.Groups[target]
		for _, d := range devices {
			for _, m := range members {
				if d.User == m {
					r.addDevice(d, ports)
					break
				}
			}
		}
		return

	case strings.HasPrefix(target, "autogroup:"):
		// User autogroups resolve against users. A tag has no owning user, so
		// naming a device set here would be fabrication.
		r.Unresolved = append(r.Unresolved, target)
		return

	case strings.Contains(target, "@"):
		for _, d := range devices {
			if d.User == target {
				r.addDevice(d, ports)
			}
		}
		return
	}

	// A named host resolves to an address; match a device holding it.
	if addr, ok := policy.Hosts[target]; ok {
		if matched := deviceByAddress(addr, devices); matched != nil {
			r.addDevice(matched, ports)
			return
		}
		r.Unresolved = append(r.Unresolved, target+" ("+addr+")")
		return
	}

	// A CIDR is routed reach: some device forwards traffic to it. Reaching a
	// router's own address is device reach and is handled above.
	if _, err := netip.ParsePrefix(target); err == nil {
		routers := routersFor(target, devices)
		if len(routers) == 0 {
			r.Unresolved = append(r.Unresolved, target+" (no device routes it)")
			return
		}
		for _, router := range routers {
			r.Routed = append(r.Routed, RoutedReach{CIDR: target, Router: router})
		}
		return
	}

	// A bare address may still name a device.
	if matched := deviceByAddress(target, devices); matched != nil {
		r.addDevice(matched, ports)
		return
	}

	r.Unresolved = append(r.Unresolved, target)
}

// deviceByAddress finds the device holding a Tailscale address.
func deviceByAddress(addr string, devices []*client.Device) *client.Device {
	for _, d := range devices {
		for _, a := range d.Addresses {
			if a == addr {
				return d
			}
		}
	}
	return nil
}

// ComputeReach resolves everything the given tag can reach under the policy.
func ComputeReach(tag string, policy ACLPolicy, devices []*client.Device) Reach {
	r := Reach{Tag: tag, TotalDevices: len(devices)}

	for i, rule := range policy.ACLs {
		if rule.Action != "" && rule.Action != "accept" {
			continue
		}
		if !tagMatchesSource(tag, rule.Src) {
			continue
		}
		r.ViaRules = append(r.ViaRules, RuleRef{Kind: "acl", Index: i, Src: rule.Src, Dst: rule.Dst})
		for _, dst := range rule.Dst {
			target, ports := splitDst(dst)
			r.expandTarget(target, ports, policy, devices)
		}
	}

	for i, grant := range policy.Grants {
		if !tagMatchesSource(tag, grant.Src) {
			continue
		}
		r.ViaRules = append(r.ViaRules, RuleRef{Kind: "grant", Index: i, Src: grant.Src, Dst: grant.Dst})
		// Grants keep ports in the ip field rather than on the destination.
		ports := ""
		if len(grant.IP) > 0 {
			ports = strings.Join(grant.IP, ",")
		}
		for _, dst := range grant.Dst {
			r.expandTarget(dst, ports, policy, devices)
		}
	}

	return r
}

// AllTagReach computes reach for every tag the policy defines, broadest first.
func AllTagReach(policy ACLPolicy, devices []*client.Device) []Reach {
	reaches := make([]Reach, 0, len(policy.TagOwners))
	for tag := range policy.TagOwners {
		reaches = append(reaches, ComputeReach(tag, policy, devices))
	}
	sort.Slice(reaches, func(i, j int) bool {
		if reaches[i].Wildcard != reaches[j].Wildcard {
			return reaches[i].Wildcard
		}
		if len(reaches[i].Devices) != len(reaches[j].Devices) {
			return len(reaches[i].Devices) > len(reaches[j].Devices)
		}
		return reaches[i].Tag < reaches[j].Tag
	})
	return reaches
}
```

- [ ] **Step 4: Run the whole reach suite**

Run: `go test ./pkg/auditor/ -run 'TestTagMatchesSource|TestSplitDst|TestRoutersFor|TestExitNodes|TestComputeReach' -v`
Expected: PASS

- [ ] **Step 5: Commit**

Commit `pkg/auditor/reach.go` and `pkg/auditor/reach_test.go` with the message:

```
Assemble tag reach from grants and ACL rules

Grants keep ports in the ip field while ACL rules append them to the
destination, so the two forms are read separately. A wildcard sets a
flag instead of enumerating devices, because it also covers every
device that joins later.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 5: Fetch federated identities

**Files:**
- Modify: `pkg/client/client.go:335-342` (key type consts), and near `GetOAuthClients` (~line 489)
- Test: `pkg/client/client_test.go`

**Interfaces:**
- Produces: `client.KeyTypeFederated` const and `(*Client).GetFederatedIdentities(ctx context.Context) ([]Key, error)`.

The `/keys` endpoint already returns these; `GetAuthKeys` discards them at `pkg/client/client.go:478` because their `KeyType` is not `auth`. The `Key` struct already carries `Issuer`, `Subject`, `Audience`, `CustomClaimRules`, `Tags` and `Scopes`. Tailscale's admin console calls these **trust credentials**.

- [ ] **Step 1: Write the failing test**

Follow the existing table style in `pkg/client/client_test.go`. Add:

```go
func TestGetFederatedIdentitiesFiltersByKeyType(t *testing.T) {
	keys := []Key{
		{ID: "k1", KeyType: KeyTypeAuth},
		{ID: "k2", KeyType: KeyTypeFederated, Subject: "repo:org/repo:ref:refs/heads/main"},
		{ID: "k3", KeyType: KeyTypeClient},
		{ID: "k4", KeyType: KeyTypeFederated, Invalid: true},
		{ID: "k5", KeyType: KeyTypeFederated, Revoked: time.Now()},
	}

	got := filterFederatedIdentities(keys)
	if len(got) != 1 || got[0].ID != "k2" {
		t.Errorf("filterFederatedIdentities returned %v, want only k2", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/client/ -run TestGetFederatedIdentitiesFiltersByKeyType -v`
Expected: FAIL — `undefined: KeyTypeFederated`, `undefined: filterFederatedIdentities`

- [ ] **Step 3: Implement**

Add `KeyTypeFederated` to the const block at `pkg/client/client.go:338`:

```go
const (
	KeyTypeAuth      = "auth"
	KeyTypeAPI       = "api"
	KeyTypeClient    = "client"
	KeyTypeFederated = "federated"
)
```

Add next to `GetOAuthClients`:

```go
// filterFederatedIdentities keeps the live federated identities from a key
// listing, dropping revoked and invalidated entries.
func filterFederatedIdentities(keys []Key) []Key {
	identities := make([]Key, 0, len(keys))
	for _, key := range keys {
		if key.KeyType == KeyTypeFederated && !key.Invalid && key.Revoked.IsZero() {
			identities = append(identities, key)
		}
	}
	return identities
}

// GetFederatedIdentities fetches the tailnet's workload identity federation
// entries, which the admin console calls trust credentials. They arrive from
// the same keys endpoint as auth keys and OAuth clients.
func (c *Client) GetFederatedIdentities(ctx context.Context) ([]Key, error) {
	keys, err := c.GetKeys(ctx)
	if err != nil {
		return nil, err
	}
	return filterFederatedIdentities(keys), nil
}
```

Also update the comment at `pkg/client/client.go:335-337` so it no longer implies federated identities are unused.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/client/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

Commit `pkg/client/client.go` and `pkg/client/client_test.go`:

```
Fetch federated identities from the keys endpoint

The endpoint already returns them; only auth keys and OAuth clients
were being read out. Their issuer, subject, audience and claim rules
are what the new AUTH-005 and AUTH-006 checks read.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 6: AUTH-005 — workload identity federation not in use

**Files:**
- Modify: `pkg/auditor/auth.go` (add to `authKeyChecks` at line 18, add check call in `Audit`, add check func)
- Modify: `pkg/types/registry.go` (registry entry — required, see Global Constraints)
- Test: `pkg/auditor/auth_test.go`

**Interfaces:**
- Consumes: `keyInfo` from `pkg/auditor/auth.go`, `client.GetFederatedIdentities` from Task 5.
- Produces: `(*AuthAuditor).checkFederationInUse(keys []keyInfo, identities []client.Key) types.Suggestion`.

A key is a **migration candidate** when it is reusable, non-ephemeral, tagged, and not expired — the shape of the credential that leaked at Hugging Face. "Covered" means some federated identity's `Tags` include a tag the candidate can mint.

| State | Result |
|---|---|
| No migration candidates | Pass |
| Candidates exist, zero federated identities | Fail, Medium |
| Candidates exist, some tags still uncovered | Fail, Low — name only the uncovered tags |

The severity is a factual statement that a leakable credential path exists where a non-leakable one is available. It is not a claim that the key is misconfigured.

- [ ] **Step 1: Write the failing test**

```go
func TestCheckFederationInUse(t *testing.T) {
	candidate := keyInfo{
		ID: "k1", Description: "ci-runner",
		Reusable: true, Ephemeral: false,
		Tags: []string{"tag:ci"}, DaysToExpiry: 341,
	}
	oneOff := keyInfo{ID: "k2", Reusable: false, Tags: []string{"tag:ci"}, DaysToExpiry: 7}
	untagged := keyInfo{ID: "k3", Reusable: true, DaysToExpiry: 30}
	expired := keyInfo{ID: "k4", Reusable: true, Tags: []string{"tag:old"}, DaysToExpiry: -3}

	a := &AuthAuditor{}

	t.Run("no candidates passes", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{oneOff, untagged, expired}, nil)
		if !f.Pass {
			t.Errorf("expected pass with no migration candidates, got %+v", f.Details)
		}
	})

	t.Run("candidates and no federation fails medium", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{candidate}, nil)
		if f.Pass {
			t.Error("expected fail when a reusable tagged key has no federation")
		}
		if f.Severity != types.Medium {
			t.Errorf("Severity = %s, want MEDIUM", f.Severity)
		}
	})

	t.Run("covered tag passes", func(t *testing.T) {
		identities := []client.Key{{ID: "f1", Tags: []string{"tag:ci"}}}
		f := a.checkFederationInUse([]keyInfo{candidate}, identities)
		if !f.Pass {
			t.Errorf("expected pass when the tag is covered, got %+v", f.Details)
		}
	})

	t.Run("uncovered tag fails low", func(t *testing.T) {
		identities := []client.Key{{ID: "f1", Tags: []string{"tag:other"}}}
		f := a.checkFederationInUse([]keyInfo{candidate}, identities)
		if f.Pass {
			t.Error("expected fail when the candidate's tag is not covered")
		}
		if f.Severity != types.Low {
			t.Errorf("Severity = %s, want LOW", f.Severity)
		}
	})

	t.Run("expired key is not a candidate", func(t *testing.T) {
		f := a.checkFederationInUse([]keyInfo{expired}, nil)
		if !f.Pass {
			t.Error("an expired key should not be a migration candidate")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestCheckFederationInUse -v`
Expected: FAIL — `undefined: checkFederationInUse`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/auth.go`:

```go
// isMigrationCandidate reports whether a key is the kind of long-lived workload
// credential that workload identity federation replaces: reusable, not
// ephemeral, carrying tags, and still valid.
func (k keyInfo) isMigrationCandidate() bool {
	return k.Reusable && !k.Ephemeral && len(k.Tags) > 0 && k.DaysToExpiry >= 0
}

func (a *AuthAuditor) checkFederationInUse(keys []keyInfo, identities []client.Key) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-005",
		Title:       "Workload identity federation not in use",
		Severity:    types.Medium,
		Category:    types.Authentication,
		Description: "Workload identity federation lets a CI job prove its cloud identity with a short-lived OIDC token, so there is no long-lived key to store or leak.",
		Remediation: "Create a trust credential for each CI workload and remove the static auth key it replaces. Pin the subject to a specific workload rather than a wildcard.",
		Source:      "https://tailscale.com/docs/features/workload-identity-federation",
		Pass:        true,
	}

	covered := make(map[string]bool)
	for _, id := range identities {
		for _, tag := range id.Tags {
			covered[tag] = true
		}
	}

	var details []string
	uncovered := false
	for _, key := range keys {
		if !key.isMigrationCandidate() {
			continue
		}
		var missing []string
		for _, tag := range key.Tags {
			if !covered[tag] {
				missing = append(missing, tag)
			}
		}
		if len(missing) == 0 {
			continue
		}
		uncovered = true
		details = append(details, fmt.Sprintf("%s: reusable, expires in %d days, mints %v with no trust credential",
			key.label(), key.DaysToExpiry, missing))
	}

	if !uncovered {
		return finding
	}

	finding.Pass = false
	finding.Details = details
	if len(identities) == 0 {
		finding.Description = fmt.Sprintf("Found %d reusable auth key(s) provisioning tagged workloads, and no trust credentials at all. A key like this is what an attacker reads out of a secret store and reuses to enroll nodes.", len(details))
	} else {
		finding.Severity = types.Low
		finding.Description = fmt.Sprintf("Trust credentials exist, but %d reusable auth key(s) still mint tags that none of them cover.", len(details))
	}
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Create a trust credential for these workloads, then delete the static key",
		AdminURL:    "https://login.tailscale.com/admin/settings/keys",
		DocURL:      "https://tailscale.com/docs/features/workload-identity-federation",
	}
	return finding
}
```

Wire it into `Audit`, after the AUTH-004 call. Federated identities come from the same endpoint, so a fetch failure is reported the same way:

```go
	identities, idErr := a.client.GetFederatedIdentities(ctx)
	if idErr != nil {
		findings = append(findings, types.NotEvaluated("AUTH-005",
			"The tailnet's federated identities could not be read. See AUTH-ERR for the error."))
	} else {
		findings = append(findings, a.checkFederationInUse(keys, identities))
	}
```

Add `"AUTH-005"` to `authKeyChecks` at `pkg/auditor/auth.go:18`.

Add to `pkg/types/registry.go` in the Auth block:

```go
{ID: "AUTH-005", Title: "Workload identity federation not in use", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2", "CC6.3"}},
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/auditor/ -run 'TestCheckFederationInUse|TestEveryEmittedCheckIDIsRegistered' -v`
Expected: PASS both

- [ ] **Step 5: Commit**

Commit `pkg/auditor/auth.go`, `pkg/auditor/auth_test.go`, `pkg/types/registry.go`:

```
Add AUTH-005 for workload identity federation

A reusable, non-ephemeral, tagged auth key is the credential shape that
federation replaces. The check reports one whose tags no trust
credential covers.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 7: AUTH-006 — federated identity subject breadth

**Files:**
- Modify: `pkg/auditor/auth.go`
- Modify: `pkg/types/registry.go`
- Test: `pkg/auditor/auth_test.go`

**Interfaces:**
- Produces: `subjectBreadth(subject string) breadth` and `(*AuthAuditor).checkFederatedIdentityConfig(identities []client.Key) types.Suggestion`.

Verdict logic is issuer-agnostic and classified by where the wildcard sits. A whole-subject wildcard means any principal the issuer vouches for can mint the tag — a boundary crossing, so it fails High. Narrower wildcards are reported without a verdict. Recognized issuers change the remediation wording only, never the verdict, so a provider changing its subject grammar cannot silently rot a verdict.

- [ ] **Step 1: Write the failing test**

```go
func TestSubjectBreadth(t *testing.T) {
	tests := []struct {
		subject string
		want    breadth
	}{
		{"", breadthAny},
		{"*", breadthAny},
		{"**", breadthAny},
		{"*:*", breadthAny},
		{"*/repo:ref:refs/heads/main", breadthLeadingWildcard},
		{"repo:org/*", breadthTrailingWildcard},
		{"repo:org/repo:*", breadthTrailingWildcard},
		{"repo:org/repo:ref:refs/heads/main", breadthPinned},
	}

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			if got := subjectBreadth(tt.subject); got != tt.want {
				t.Errorf("subjectBreadth(%q) = %v, want %v", tt.subject, got, tt.want)
			}
		})
	}
}

func TestCheckFederatedIdentityConfig(t *testing.T) {
	a := &AuthAuditor{}

	t.Run("no identities passes", func(t *testing.T) {
		if f := a.checkFederatedIdentityConfig(nil); !f.Pass {
			t.Error("expected pass with no federated identities")
		}
	})

	t.Run("pinned subject passes", func(t *testing.T) {
		ids := []client.Key{{
			ID: "f1", Issuer: "token.actions.githubusercontent.com",
			Subject: "repo:org/repo:ref:refs/heads/main", Audience: "tailscale",
		}}
		if f := a.checkFederatedIdentityConfig(ids); !f.Pass {
			t.Errorf("expected pass for a pinned subject, got %+v", f.Details)
		}
	})

	t.Run("wildcard subject fails high", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Issuer: "token.actions.githubusercontent.com", Subject: "*"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass {
			t.Error("expected fail for a whole-subject wildcard")
		}
		if f.Severity != types.High {
			t.Errorf("Severity = %s, want HIGH", f.Severity)
		}
	})

	t.Run("unknown issuer gets the same verdict", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Issuer: "oidc.example.invalid", Subject: "*"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Pass || f.Severity != types.High {
			t.Error("an unknown issuer must not change the verdict")
		}
	})

	t.Run("trailing wildcard reports without failing high", func(t *testing.T) {
		ids := []client.Key{{ID: "f1", Subject: "repo:org/*", Audience: "tailscale"}}
		f := a.checkFederatedIdentityConfig(ids)
		if f.Severity == types.High {
			t.Error("a trailing wildcard should not be rated HIGH")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run 'TestSubjectBreadth|TestCheckFederatedIdentityConfig' -v`
Expected: FAIL — `undefined: subjectBreadth`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/auth.go`:

```go
// breadth classifies how much a federated identity subject admits.
type breadth int

const (
	breadthPinned breadth = iota
	breadthTrailingWildcard
	breadthLeadingWildcard
	breadthAny
)

// issuerHints map a recognized issuer host to remediation wording. They shape
// the message only. The verdict is issuer-agnostic so that a provider changing
// its subject grammar cannot silently invalidate a check.
var issuerHints = map[string]string{
	"token.actions.githubusercontent.com": "Pin the subject to one repository and ref, for example repo:ORG/REPO:ref:refs/heads/main.",
	"accounts.google.com":                 "Pin the subject to the service account that runs the workload.",
	"sts.amazonaws.com":                   "Pin the subject to the specific role the workload assumes.",
}

// subjectBreadth classifies a subject by where its wildcard sits. A subject
// that is nothing but wildcards admits every principal the issuer vouches for.
func subjectBreadth(subject string) breadth {
	s := strings.TrimSpace(subject)
	if s == "" {
		return breadthAny
	}
	if strings.Trim(s, "*:/ ") == "" {
		return breadthAny
	}
	if !strings.Contains(s, "*") {
		return breadthPinned
	}
	if strings.HasPrefix(s, "*") {
		return breadthLeadingWildcard
	}
	return breadthTrailingWildcard
}

func (a *AuthAuditor) checkFederatedIdentityConfig(identities []client.Key) types.Suggestion {
	finding := types.Suggestion{
		ID:          "AUTH-006",
		Title:       "Federated identity subject admits unintended principals",
		Severity:    types.High,
		Category:    types.Authentication,
		Description: "A trust credential's subject decides which workloads can mint its tags. A wildcard subject widens that to everything the issuer will vouch for.",
		Remediation: "Pin each subject to one workload. Set an audience so a token minted for another relying party cannot be replayed, and add claim rules to tighten further.",
		Source:      "https://tailscale.com/docs/features/workload-identity-federation",
		Pass:        true,
	}

	var wideOpen, narrower, notes []string
	for _, id := range identities {
		label := id.ID
		if id.Description != "" {
			label = fmt.Sprintf("%s (%s)", id.Description, id.ID)
		}
		switch subjectBreadth(id.Subject) {
		case breadthAny:
			hint := "Pin the subject to a single workload."
			if h, ok := issuerHints[id.Issuer]; ok {
				hint = h
			}
			wideOpen = append(wideOpen, fmt.Sprintf("%s: subject %q accepts any principal issued by %s. %s",
				label, id.Subject, id.Issuer, hint))
		case breadthLeadingWildcard, breadthTrailingWildcard:
			narrower = append(narrower, fmt.Sprintf("%s: subject %q contains a wildcard", label, id.Subject))
		}

		// Supporting facts. Neither sets severity on its own; an empty audience
		// alongside a wildcard subject is the pairing that matters.
		if strings.TrimSpace(id.Audience) == "" {
			notes = append(notes, fmt.Sprintf("%s: no audience set, so a token minted for another relying party is not rejected", label))
		}
		if len(id.CustomClaimRules) == 0 && subjectBreadth(id.Subject) != breadthPinned {
			notes = append(notes, fmt.Sprintf("%s: wildcard subject with no claim rules to tighten it", label))
		}
	}

	if len(wideOpen) > 0 {
		finding.Pass = false
		finding.Details = append(append(wideOpen, narrower...), notes...)
		finding.Description = fmt.Sprintf("Found %d trust credential(s) whose subject accepts any principal the issuer vouches for.", len(wideOpen))
		finding.Fix = &types.FixInfo{
			Type:        types.FixTypeManual,
			Description: "Narrow each subject to a single workload",
			AdminURL:    "https://login.tailscale.com/admin/settings/keys",
			DocURL:      "https://tailscale.com/docs/features/workload-identity-federation",
		}
		return finding
	}

	if len(narrower) > 0 || len(notes) > 0 {
		finding.Pass = false
		finding.Severity = types.Low
		finding.Details = append(narrower, notes...)
		finding.Description = "Trust credentials are in use. These carry a wildcard subject or no audience, which may be intended but is worth confirming."
		return finding
	}

	if len(identities) > 0 {
		finding.Description = fmt.Sprintf("All %d trust credential(s) pin their subject.", len(identities))
	} else {
		finding.Description = "No trust credentials are configured."
	}
	return finding
}
```

Wire into `Audit` next to AUTH-005, sharing the same `identities` and `idErr`. Add `"AUTH-006"` to `authKeyChecks`.

Add to `pkg/types/registry.go`:

```go
{ID: "AUTH-006", Title: "Federated identity subject admits unintended principals", Category: Authentication, CCMappings: []string{"CC6.1", "CC6.2"}},
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/auditor/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

Commit `pkg/auditor/auth.go`, `pkg/auditor/auth_test.go`, `pkg/types/registry.go`:

```
Add AUTH-006 for federated identity subject breadth

A subject that is only a wildcard admits every principal its issuer
vouches for. Verdicts read the wildcard position rather than a
provider's subject grammar, so a grammar change cannot rot them; the
issuer only shapes the remediation wording.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 8: Share the device inventory with the ACL and Auth auditors

**Files:**
- Modify: `pkg/auditor/auditor.go:113-160`
- Modify: `pkg/auditor/acl.go:95` (signature)
- Modify: `pkg/auditor/auth.go:66` (signature)

**Interfaces:**
- Produces: `(*ACLAuditor).Audit(ctx, devices []*client.Device, devErr error)` and `(*AuthAuditor).Audit(ctx, policy ACLPolicy, policyParsed bool, devices []*client.Device)`.

ACL-011 and the AUTH enrichment both need the device inventory, and the Network auditor already receives pre-fetched policy the same way at `pkg/auditor/auditor.go:156`. Fetch devices once in `Run` rather than having three auditors each call `GetDevices`.

Pass `devErr` through rather than swallowing it: a check that could not read devices must report `NotEvaluated`, not pass.

- [ ] **Step 1: Fetch devices once in Run**

In `pkg/auditor/auditor.go`, just after `tailnetCtx := FetchTailnetContext(ctx, a.client)`:

```go
	// Shared with the ACL and Auth auditors so they do not each re-request it.
	devices, devErr := a.client.GetDevices(ctx)
```

- [ ] **Step 2: Widen the two auditor signatures**

```go
	// ACL auditor
	g.Go(func() error {
		auditor := NewACLAuditor(a.client)
		findings, err := auditor.Audit(gctx, devices, devErr)
		appendResult(auditorResult{name: "ACL", findings: findings, err: err})
		return nil
	})

	// Auth auditor
	g.Go(func() error {
		auditor := NewAuthAuditor(a.client)
		findings, err := auditor.Audit(gctx, policy, policyParsed, devices)
		appendResult(auditorResult{name: "Auth", findings: findings, err: err})
		return nil
	})
```

Update both `Audit` methods to accept the new parameters and ignore them for now, so the tree compiles.

- [ ] **Step 3: Run the full suite**

Run: `go test ./...`
Expected: PASS — no behaviour change yet. Fix any test that constructs these auditors directly.

- [ ] **Step 4: Build**

Run: `make build`
Expected: builds clean

- [ ] **Step 5: Commit**

```
Fetch the device inventory once for the ACL and Auth auditors

Both new checks need it, and the Network auditor already takes
pre-fetched policy the same way. The fetch error travels with it so a
check that could not read devices reports as not evaluated.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 9: ACL-011 — tag reach

**Files:**
- Modify: `pkg/auditor/acl.go` (check func, add to `aclPolicyChecks`)
- Modify: `pkg/types/registry.go`
- Test: `pkg/auditor/acl_test.go`

**Interfaces:**
- Consumes: `AllTagReach` from Task 4; `client.GetAuthKeys`.
- Produces: `mintableTags(keys []client.Key) map[string]bool`, `reusablyMintableTags(keys []client.Key) map[string]bool`, `(*ACLAuditor).checkTagReach(policy ACLPolicy, devices []*client.Device, keys []client.Key, keysErr error) types.Suggestion`.

A tag is **mintable** when it appears in `Capabilities.Devices.Create.Tags` of a live, unexpired auth key. Fails only on a structural fact, and only for mintable tags:

| Condition | Severity |
|---|---|
| Mintable tag reaches `*:*` | High if a reusable key mints it, else Medium |
| Mintable tag reaches a routed CIDR or exit-node egress | High if a reusable key mints it, else Medium |
| Neither | Informational — reach table only |

Reusable versus one-off is a structural property of the credential, so it may move severity. A device count may not.

When auth keys cannot be read, mintability is unknown: report the reach table as informational and say so. Do not pass.

- [ ] **Step 1: Write the failing test**

```go
func TestCheckTagReach(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}
	gw := dev("prod-gw", []string{"10.0.0.0/8"}, nil)
	devices := []*client.Device{web, gw}

	reusableCIKey := client.Key{ID: "k1", KeyType: client.KeyTypeAuth}
	reusableCIKey.Capabilities.Devices.Create.Reusable = true
	reusableCIKey.Capabilities.Devices.Create.Tags = []string{"tag:ci"}

	a := &ACLAuditor{}

	t.Run("mintable tag reaching wildcard fails high", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if f.Pass || f.Severity != types.High {
			t.Errorf("want fail HIGH, got pass=%v severity=%s", f.Pass, f.Severity)
		}
	})

	t.Run("broad tag no key can mint stays informational", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:monitoring": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:monitoring"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if !f.Pass {
			t.Error("a broad tag that no auth key can mint must not fail")
		}
	})

	t.Run("mintable tag reaching a routed cidr fails", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"10.1.0.0/16:*"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if f.Pass {
			t.Error("reaching a routed subnet crosses the tailnet boundary and must fail")
		}
	})

	t.Run("narrow mintable tag passes", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
		}
		f := a.checkTagReach(policy, devices, []client.Key{reusableCIKey}, nil)
		if !f.Pass {
			t.Errorf("a tag reaching two devices on one port should not fail: %+v", f.Details)
		}
	})

	t.Run("unreadable keys degrade to informational, not pass", func(t *testing.T) {
		policy := ACLPolicy{
			TagOwners: map[string][]string{"tag:ci": nil},
			ACLs:      []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"*:*"}}},
		}
		f := a.checkTagReach(policy, devices, nil, errors.New("403"))
		if f.Pass {
			t.Error("mintability unknown must not report as a satisfied control")
		}
		if f.Severity != types.Informational {
			t.Errorf("Severity = %s, want INFO when mintability is unknown", f.Severity)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestCheckTagReach -v`
Expected: FAIL — `undefined: checkTagReach`

- [ ] **Step 3: Implement**

Add to `pkg/auditor/acl.go`:

```go
// mintableTags returns the tags any live auth key can assign to a new node.
func mintableTags(keys []client.Key) map[string]bool {
	tags := make(map[string]bool)
	for _, key := range keys {
		if !key.Expires.IsZero() && time.Until(key.Expires) < 0 {
			continue
		}
		for _, tag := range key.Capabilities.Devices.Create.Tags {
			tags[tag] = true
		}
	}
	return tags
}

// reusablyMintableTags returns the tags a reusable auth key can assign. A
// reusable key keeps working after it leaks, which is a property of the
// credential rather than a judgement about the environment, so it may raise
// severity.
func reusablyMintableTags(keys []client.Key) map[string]bool {
	tags := make(map[string]bool)
	for _, key := range keys {
		if !key.Capabilities.Devices.Create.Reusable {
			continue
		}
		if !key.Expires.IsZero() && time.Until(key.Expires) < 0 {
			continue
		}
		for _, tag := range key.Capabilities.Devices.Create.Tags {
			tags[tag] = true
		}
	}
	return tags
}

// describeReach renders one tag's reach as report lines.
func describeReach(r Reach, mintable, reusable bool) []string {
	var lines []string
	switch {
	case r.Wildcard:
		lines = append(lines, fmt.Sprintf("%s: reaches every device in the tailnet (a rule grants *:*)", r.Tag))
	default:
		allPortsCount := 0
		for _, d := range r.Devices {
			if d.AllPorts {
				allPortsCount++
			}
		}
		lines = append(lines, fmt.Sprintf("%s: reaches %d of %d devices, %d of them on all ports",
			r.Tag, len(r.Devices), r.TotalDevices, allPortsCount))
	}
	for _, routed := range r.Routed {
		lines = append(lines, fmt.Sprintf("    routes to %s via %s", routed.CIDR, routed.Router.Name))
	}
	for _, e := range r.Egress {
		lines = append(lines, fmt.Sprintf("    egress to the internet via exit node %s", e.Name))
	}
	for _, u := range r.Unresolved {
		lines = append(lines, fmt.Sprintf("    unresolved destination, not counted: %s", u))
	}
	if mintable {
		how := "an auth key"
		if reusable {
			how = "a reusable auth key"
		}
		lines = append(lines, fmt.Sprintf("    %s can assign this tag", how))
	}
	return lines
}

func (a *ACLAuditor) checkTagReach(policy ACLPolicy, devices []*client.Device, keys []client.Key, keysErr error) types.Suggestion {
	finding := types.Suggestion{
		ID:          "ACL-011",
		Title:       "Tag reach",
		Severity:    types.Informational,
		Category:    types.AccessControl,
		Description: "What a tag can reach is what a node carrying that tag can reach. A tag an auth key can assign is reachable by anyone holding that key.",
		Remediation: "Narrow the rules that name this tag as a source, or replace the auth key that assigns it with a trust credential so there is no key to steal.",
		Source:      "https://tailscale.com/docs/features/tags",
		Pass:        true,
	}

	reaches := AllTagReach(policy, devices)
	if len(reaches) == 0 {
		finding.Description = "The policy defines no tags."
		return finding
	}

	mintable := mintableTags(keys)
	reusable := reusablyMintableTags(keys)

	var details []string
	var offenders []string
	worst := types.Informational

	for _, r := range reaches {
		isMintable := keysErr == nil && mintable[r.Tag]
		isReusable := keysErr == nil && reusable[r.Tag]
		details = append(details, describeReach(r, isMintable, isReusable)...)

		if !isMintable {
			continue
		}
		crossings := []string{}
		if r.Wildcard {
			crossings = append(crossings, "reaches every device")
		}
		if len(r.Routed) > 0 {
			crossings = append(crossings, "routes past the tailnet edge")
		}
		if len(r.Egress) > 0 {
			crossings = append(crossings, "carries internet egress")
		}
		if len(crossings) == 0 {
			continue
		}
		offenders = append(offenders, fmt.Sprintf("%s: %s", r.Tag, strings.Join(crossings, ", ")))
		sev := types.Medium
		if isReusable {
			sev = types.High
		}
		if sev.Order() < worst.Order() {
			worst = sev
		}
	}

	if keysErr != nil {
		finding.Pass = false
		finding.Description = "Tag reach was computed, but the auth keys could not be read, so it is unknown which tags a key can assign."
		finding.Details = append([]string{
			fmt.Sprintf("Could not read auth keys: %v", keysErr),
			"MANUAL CHECK REQUIRED: confirm which of these tags an auth key can assign.",
		}, details...)
		return finding
	}

	if len(offenders) == 0 {
		finding.Details = details
		finding.Description = fmt.Sprintf("Reach computed for %d tag(s). No tag that an auth key can assign crosses a trust boundary.", len(reaches))
		return finding
	}

	finding.Pass = false
	finding.Severity = worst
	finding.Description = fmt.Sprintf("%d tag(s) that an auth key can assign cross a trust boundary.", len(offenders))
	finding.Details = append(append([]string{"Tags crossing a boundary:"}, offenders...), append([]string{"", "Reach for every tag:"}, details...)...)
	finding.Fix = &types.FixInfo{
		Type:        types.FixTypeManual,
		Description: "Narrow these tags' rules, or replace the auth key that assigns them",
		AdminURL:    "https://login.tailscale.com/admin/acls",
		DocURL:      "https://tailscale.com/docs/features/tags",
	}
	return finding
}
```

Call it from `ACLAuditor.Audit` after ACL-010, fetching keys through the client:

```go
	keys, keysErr := a.client.GetAuthKeys(ctx)
	if devErr != nil {
		findings = append(findings, types.NotEvaluated("ACL-011",
			fmt.Sprintf("The device inventory could not be read: %v", devErr)))
	} else {
		findings = append(findings, a.checkTagReach(policy, devices, keys, keysErr))
	}
```

Add `"ACL-011"` to `aclPolicyChecks` at `pkg/auditor/acl.go:175`, and to `pkg/types/registry.go`:

```go
{ID: "ACL-011", Title: "Tag reach", Category: AccessControl, CCMappings: []string{"CC6.1", "CC6.2"}},
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/auditor/ -v`
Expected: PASS, including `TestEveryEmittedCheckIDIsRegistered`

- [ ] **Step 5: Commit**

```
Add ACL-011 for tag reach

Reach is reported for every tag but only fails on a boundary crossing
by a tag an auth key can assign: a wildcard destination, a routed
subnet, or internet egress. A device count never sets severity, because
the tool cannot know whether 47 reachable devices is correct here.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 10: Cite reach in AUTH-001, AUTH-002 and AUTH-003

**Files:**
- Modify: `pkg/auditor/auth.go`
- Test: `pkg/auditor/auth_test.go`

**Interfaces:**
- Consumes: `ComputeReach` from Task 4, plus the `policy`/`devices` parameters added in Task 8.
- Produces: `reachNote(tags []string, policy ACLPolicy, policyParsed bool, devices []*client.Device) string`.

Severity does not change. Whether a given reach is appropriate is the judgement the tool has no grounds to make; it supplies the fact and lets a reader who has the context decide. If the policy did not parse or devices are unavailable, return an empty string — never print a figure that was not computed.

- [ ] **Step 1: Write the failing test**

```go
func TestReachNote(t *testing.T) {
	web := &client.Device{}
	web.Name = "web-01"
	web.Tags = []string{"tag:prod"}
	devices := []*client.Device{web}
	policy := ACLPolicy{
		ACLs: []ACLRule{{Action: "accept", Src: []string{"tag:ci"}, Dst: []string{"tag:prod:22"}}},
	}

	t.Run("unparsed policy yields no note", func(t *testing.T) {
		if got := reachNote([]string{"tag:ci"}, policy, false, devices); got != "" {
			t.Errorf("reachNote = %q, want empty when the policy did not parse", got)
		}
	})

	t.Run("no devices yields no note", func(t *testing.T) {
		if got := reachNote([]string{"tag:ci"}, policy, true, nil); got != "" {
			t.Errorf("reachNote = %q, want empty with no device inventory", got)
		}
	})

	t.Run("reach is described", func(t *testing.T) {
		got := reachNote([]string{"tag:ci"}, policy, true, devices)
		if !strings.Contains(got, "tag:ci") || !strings.Contains(got, "1 of 1") {
			t.Errorf("reachNote = %q, want it to name the tag and the count", got)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestReachNote -v`
Expected: FAIL — `undefined: reachNote`

- [ ] **Step 3: Implement**

```go
// reachNote describes what a key's tags reach, for readers deciding whether a
// flagged key matters. It returns an empty string when reach could not be
// computed, so a figure is never printed that was not derived from real data.
func reachNote(tags []string, policy ACLPolicy, policyParsed bool, devices []*client.Device) string {
	if !policyParsed || len(devices) == 0 || len(tags) == 0 {
		return ""
	}
	var parts []string
	for _, tag := range tags {
		r := ComputeReach(tag, policy, devices)
		switch {
		case r.Wildcard:
			parts = append(parts, fmt.Sprintf("%s reaches every device", tag))
		default:
			part := fmt.Sprintf("%s reaches %d of %d devices", tag, len(r.Devices), r.TotalDevices)
			if len(r.Routed) > 0 {
				part += fmt.Sprintf(" and routes to %s", r.Routed[0].CIDR)
			}
			parts = append(parts, part)
		}
	}
	return "Reach: " + strings.Join(parts, "; ") + " (see ACL-011)"
}
```

Store `policy`, `policyParsed` and `devices` on `AuthAuditor` in `Audit`, then in `checkReusableKeys`, `checkLongExpiryKeys` and `checkPreauthorizedKeys` append the note to each key's detail line when it is non-empty. For example in `checkReusableKeys`:

```go
			line := fmt.Sprintf("%s (expires in %d days)", key.label(), key.DaysToExpiry)
			if note := reachNote(key.Tags, a.policy, a.policyParsed, a.devices); note != "" {
				line += " — " + note
			}
			reusableKeys = append(reusableKeys, line)
```

- [ ] **Step 4: Run tests**

Run: `go test ./... `
Expected: PASS

- [ ] **Step 5: Commit**

```
Cite tag reach in the auth key findings

A reusable key reaching two hosts and one reaching everything are not
the same finding. Severity stays put, because whether that reach is
appropriate needs context the tool does not have.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 11: Per-item ignore

**Files:**
- Modify: `pkg/types/ignore.go`
- Test: `pkg/types/ignore_test.go`

**Interfaces:**
- Produces: `(*IgnoreList).IsItemIgnored(checkID, item string) bool` and `(*IgnoreList).ItemsFor(checkID string) []string`.

ACL-011 will legitimately fire on a tag that is broad by design. Today the ignore file holds one check ID per line and `IsIgnored` matches the whole check, so silencing `tag:monitoring` also silences `tag:ci`.

Extend the format to `CHECK-ID:item`. What counts as an *item* is per-check: for ACL-011 it is the tag name; for a check carrying a `FixInfo` it is `FixableItem.ID`; a check with no item notion ignores the suffix.

Split on the **first** colon only — the item itself contains one.

Suppressing every item of a check does not make the check pass. The finding stays, with the suppressed items removed from its details; if nothing remains it reports as informational, not as a satisfied control. Otherwise an ignore file quietly turns a real gap green, which is exactly what commit `d6ef2f5` set out to stop.

- [ ] **Step 1: Write the failing test**

```go
func TestPerItemIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".tailsnitch-ignore")
	content := `# comment
ACL-011:tag:monitoring   # backup agent, broad by design
ACL-011:tag:backup
AUTH-001
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	il, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("whole-id ignore still works", func(t *testing.T) {
		if !il.IsIgnored("AUTH-001") {
			t.Error("AUTH-001 should be ignored")
		}
	})

	t.Run("per-item line does not mute the whole check", func(t *testing.T) {
		if il.IsIgnored("ACL-011") {
			t.Error("a per-item line must not mute the entire check")
		}
	})

	t.Run("item is matched", func(t *testing.T) {
		if !il.IsItemIgnored("ACL-011", "tag:monitoring") {
			t.Error("tag:monitoring should be ignored for ACL-011")
		}
		if !il.IsItemIgnored("ACL-011", "tag:backup") {
			t.Error("tag:backup should be ignored for ACL-011")
		}
	})

	t.Run("other items are not ignored", func(t *testing.T) {
		if il.IsItemIgnored("ACL-011", "tag:ci") {
			t.Error("tag:ci must not be ignored")
		}
		if il.IsItemIgnored("AUTH-002", "tag:monitoring") {
			t.Error("an item is scoped to its own check")
		}
	})

	t.Run("split is on the first colon", func(t *testing.T) {
		items := il.ItemsFor("ACL-011")
		for _, item := range items {
			if !strings.HasPrefix(item, "tag:") {
				t.Errorf("item %q lost its colon; the split must be on the first colon only", item)
			}
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/types/ -run TestPerItemIgnore -v`
Expected: FAIL — `undefined: IsItemIgnored`

- [ ] **Step 3: Implement**

In `pkg/types/ignore.go`, add an items map to `IgnoreList`:

```go
type IgnoreList struct {
	ids   map[string]bool
	items map[string]map[string]bool // check ID -> item -> ignored
}
```

Initialise `items` everywhere `ids` is initialised (`LoadIgnoreFile` and `LoadIgnoreFiles`). In the scanner loop, replace the single `il.ids[...] = true` line with:

```go
		// A line may name a whole check ("ACL-011") or one item within it
		// ("ACL-011:tag:monitoring"). The item can itself contain colons, so
		// the split is on the first colon only.
		if idx := strings.Index(line, ":"); idx > 0 {
			checkID := strings.ToUpper(strings.TrimSpace(line[:idx]))
			item := strings.TrimSpace(line[idx+1:])
			if item != "" {
				if il.items[checkID] == nil {
					il.items[checkID] = make(map[string]bool)
				}
				il.items[checkID][item] = true
				continue
			}
		}
		il.ids[strings.ToUpper(line)] = true
```

Add the accessors:

```go
// IsItemIgnored reports whether one item within a check is ignored. What counts
// as an item is per-check: for ACL-011 it is the tag name, and for a check
// carrying a FixInfo it is the FixableItem ID.
func (il *IgnoreList) IsItemIgnored(checkID, item string) bool {
	items := il.items[strings.ToUpper(checkID)]
	if items == nil {
		return false
	}
	return items[item]
}

// ItemsFor returns the ignored items for a check, for reporting what was
// suppressed.
func (il *IgnoreList) ItemsFor(checkID string) []string {
	items := il.items[strings.ToUpper(checkID)]
	out := make([]string, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
```

Update `Count` to include per-item rules so `cmd/root.go:190` still enters the filter branch:

```go
func (il *IgnoreList) Count() int {
	return len(il.ids) + len(il.items)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/types/ -v`
Expected: PASS, including the existing ignore tests

- [ ] **Step 5: Commit**

```
Allow ignoring one item within a check

ACL-011 will fire on a tag that is broad by design, and muting the
whole check would take every other tag with it. A suppressed item is
removed from the finding's details rather than making the check pass.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 12: LOG-001 severity on a confirmed gap

**Files:**
- Modify: `pkg/auditor/logging.go:115-126`
- Test: `pkg/auditor/logging_test.go` (create if absent)

Flow logs are the detection line that catches a node whose own telemetry is suppressed, because the peers it connects to still report the traffic. When the API confirms the setting is off, that is a confirmed gap and should read as `Low`, matching how LOG-012 already treats one. The unavailable and unknown paths are unchanged — those stay informational because nothing was confirmed.

- [ ] **Step 1: Write the failing test**

```go
func TestFlowLogsDisabledIsLow(t *testing.T) {
	l := &LoggingAuditor{}
	tc := &TailnetContext{Settings: &client.TailnetSettings{NetworkFlowLoggingOn: false}}

	f := l.checkNetworkFlowLogs(tc)
	if f.Pass {
		t.Error("expected fail when flow logging is confirmed off")
	}
	if f.Severity != types.Low {
		t.Errorf("Severity = %s, want LOW for a confirmed gap", f.Severity)
	}
}

func TestFlowLogsEnabledPasses(t *testing.T) {
	l := &LoggingAuditor{}
	tc := &TailnetContext{Settings: &client.TailnetSettings{NetworkFlowLoggingOn: true}}

	if f := l.checkNetworkFlowLogs(tc); !f.Pass {
		t.Error("expected pass when flow logging is on")
	}
}
```

Check the real field and constructor names on `TailnetContext` in `pkg/auditor/auditor.go` before writing this — use whatever the `settings()` accessor reads.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/auditor/ -run TestFlowLogs -v`
Expected: FAIL — severity is INFO

- [ ] **Step 3: Implement**

In the `if !settings.NetworkFlowLoggingOn` branch at `pkg/auditor/logging.go:115`, add one line alongside the existing `finding.Pass = false`:

```go
		finding.Severity = types.Low
```

Extend the description to carry the asymmetry point, since it is the reason the setting matters:

```go
		finding.Description = "Network flow logs are disabled. Connections between devices are not recorded, leaving no audit trail of tailnet traffic. Flow logs are reported by both ends of a connection, so they still record a node that suppresses its own telemetry."
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/auditor/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
Rate confirmed-off flow logs as low rather than informational

LOG-012 already treats a confirmed gap this way. Both ends of a
connection report flow logs, so they record a node that suppresses its
own telemetry — which is what makes the setting worth flagging.

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/CHECKS.md`
- Modify: `README.md`

- [ ] **Step 1: Add the three checks to docs/CHECKS.md**

Match the existing entry format exactly — see DEV-014 at `docs/CHECKS.md:500` for the shape: `### ID: Title`, then `**Severity:**`, `**Description:**`, `**What it checks:**` as a bullet list, `**Remediation:**`, `**Admin Console:**`, `**Documentation:**`, then `---`.

Add `AUTH-005` and `AUTH-006` after AUTH-004, and `ACL-011` after ACL-010. For ACL-011 the severity line should read `INFO, or MEDIUM/HIGH when a tag an auth key can assign crosses a trust boundary`.

For ACL-011 also document the per-item ignore, since that is the escape valve a reader will need:

```markdown
**Suppressing a tag that is broad by design:**

    # .tailsnitch-ignore
    ACL-011:tag:monitoring   # backup agent, reaches everything by design

The rest of the check still runs. Suppressing every tag does not make
the check pass.
```

- [ ] **Step 2: Update the README scope table**

Add a row for the new checks. The federated identities arrive from the same `/keys` endpoint as auth keys, so `auth_keys:read` is the expected scope — **verify this against a real tailnet before stating it as fact.** If it cannot be verified, write that the scope is believed to be `auth_keys:read` and unconfirmed rather than asserting it.

Update the "50+ misconfigurations" claim in the README opening line if the count is now stated too low.

- [ ] **Step 3: Verify the docs match the code**

Run: `go test ./... `
Expected: PASS

Then read back each new CHECKS.md entry against its implementation and confirm the severity and trigger conditions agree.

- [ ] **Step 4: Commit**

```
Document AUTH-005, AUTH-006 and ACL-011

Claude-Session: https://claude.ai/code/session_017WyHLrTddjbGjTimiHxQKi
```

- [ ] **Step 5: Final verification**

Run: `go test ./...`
Run: `make build`
Run: `go vet ./...`

All three must pass before the branch is considered done.

---

## Notes for the executor

- `HARDENING_TAILSCALE.md` was updated separately and is already staged in this worktree. Do not edit it.
- The spec is `docs/superpowers/specs/2026-09-02-wif-and-tag-blast-radius-design.md`. Read it alongside this plan; it carries the reasoning behind why severity never comes from a device count.
- Burst-enrollment detection, TPM node state storage, and credential-injecting proxies are explicitly out of scope. Do not add them.
