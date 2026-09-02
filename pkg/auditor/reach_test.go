package auditor

import (
	"testing"

	"github.com/Adversis/tailsnitch/pkg/client"
)

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
