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
