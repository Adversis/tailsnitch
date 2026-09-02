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
