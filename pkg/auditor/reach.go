package auditor

import (
	"net/netip"
	"sort"
	"strings"

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
// tag. Three selectors match: the wildcard, the tag itself, and
// autogroup:tagged, which means every tagged device and so covers any tag.
// Named groups and the user autogroups (autogroup:member, autogroup:admin,
// autogroup:self) contain users, and a tagged device is not a user, so they
// never match.
func tagMatchesSource(tag string, src []string) bool {
	for _, s := range src {
		if s == "*" || s == tag || s == "autogroup:tagged" {
			return true
		}
	}
	return false
}

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

// allPorts reports whether a port spec leaves every port open. An empty spec
// comes from a grant with no ip restriction, which is unrestricted.
func allPorts(ports string) bool {
	return ports == "" || ports == "*"
}

// addDevice records reach to one device, merging with an existing entry so a
// device reachable through two rules is counted once. Once a device is known
// to be reachable on all ports, any specific ports recorded for it are stale
// and are cleared rather than left to understate the reach.
func (r *Reach) addDevice(d *client.Device, ports string) {
	for i := range r.Devices {
		if r.Devices[i].Device == d {
			if allPorts(ports) {
				r.Devices[i].AllPorts = true
				r.Devices[i].Ports = nil
			} else if !r.Devices[i].AllPorts {
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

// addEgress records reach to autogroup:internet via one exit node, merging
// with an existing entry so a node reachable through two rules is counted
// once.
func (r *Reach) addEgress(node *client.Device) {
	for _, existing := range r.Egress {
		if existing == node {
			return
		}
	}
	r.Egress = append(r.Egress, node)
}

// addRouted records routed reach to a CIDR via one router, merging with an
// existing entry so a CIDR-router pair reachable through two rules is
// counted once.
func (r *Reach) addRouted(cidr string, router *client.Device) {
	for _, existing := range r.Routed {
		if existing.CIDR == cidr && existing.Router == router {
			return
		}
	}
	r.Routed = append(r.Routed, RoutedReach{CIDR: cidr, Router: router})
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
		for _, node := range exitNodes(devices) {
			r.addEgress(node)
		}
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
			r.addRouted(target, router)
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
