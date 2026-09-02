package auditor

import (
	"net/netip"
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
