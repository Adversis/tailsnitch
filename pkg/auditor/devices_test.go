package auditor

import (
	"regexp"
	"testing"
	"time"

	"tailsnitch/pkg/client"
	"tailsnitch/pkg/types"
)

func TestCheckTaggedDevicesKeyExpiry(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "tagged device with expiry enabled - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Tags: []string{"tag:server"}, KeyExpiryDisabled: false},
			},
			wantPass: true,
		},
		{
			name: "untagged device with expiry disabled - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "laptop1", Tags: nil, KeyExpiryDisabled: true},
			},
			wantPass: true,
		},
		{
			name: "tagged device with expiry disabled - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Hostname: "server1.local", Tags: []string{"tag:server"}, KeyExpiryDisabled: true},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "multiple tagged devices with expiry disabled",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Tags: []string{"tag:server"}, KeyExpiryDisabled: true},
				{DeviceID: "2", Name: "server2", Tags: []string{"tag:db"}, KeyExpiryDisabled: true},
				{DeviceID: "3", Name: "server3", Tags: []string{"tag:web"}, KeyExpiryDisabled: false},
			},
			wantPass:  false,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkTaggedDevicesKeyExpiry(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-001" {
				t.Errorf("ID = %q, want DEV-001", result.ID)
			}

			if !tt.wantPass {
				if details, ok := result.Details.([]string); ok {
					if len(details) != tt.wantCount {
						t.Errorf("Details count = %d, want %d", len(details), tt.wantCount)
					}
				}
			}
		})
	}
}

func TestCheckUserDevicesWithTags(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "server with tags - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Hostname: "server1", OS: "linux", Tags: []string{"tag:server"}},
			},
			wantPass: true,
		},
		{
			name: "macbook with tags - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "alice-macbook", Hostname: "alice-macbook-pro", OS: "macOS", Tags: []string{"tag:dev"}},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "iphone with tags - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "alice-iphone", Hostname: "alice-iphone", OS: "iOS", Tags: []string{"tag:mobile"}},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "windows laptop with tags - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "bob-laptop", Hostname: "bob-laptop", OS: "windows", Tags: []string{"tag:dev"}},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "android device with tags - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "pixel", Hostname: "pixel-7", OS: "android", Tags: []string{"tag:mobile"}},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "user device without tags - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "alice-macbook", Hostname: "alice-macbook-pro", OS: "macOS", Tags: nil},
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkUserDevicesWithTags(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-002" {
				t.Errorf("ID = %q, want DEV-002", result.ID)
			}

			if !tt.wantPass {
				if result.Severity != types.High {
					t.Errorf("Severity = %v, want High", result.Severity)
				}
			}
		})
	}
}

func TestCheckStaleDevices(t *testing.T) {
	d := &DeviceAuditor{}

	now := time.Now()
	thirtyOneDaysAgo := now.AddDate(0, 0, -31).Format(time.RFC3339)
	tenDaysAgo := now.AddDate(0, 0, -10).Format(time.RFC3339)

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "recently seen device - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Hostname: "server1", LastSeen: tenDaysAgo},
			},
			wantPass: true,
		},
		{
			name: "stale device - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "old-server", Hostname: "old-server", LastSeen: thirtyOneDaysAgo},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "device with empty LastSeen - skip",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Hostname: "server1", LastSeen: ""},
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkStaleDevices(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-004" {
				t.Errorf("ID = %q, want DEV-004", result.ID)
			}

			if !tt.wantPass {
				if result.Fix == nil {
					t.Error("Fix should not be nil for failed check")
				} else if result.Fix.Type != types.FixTypeAPI {
					t.Errorf("Fix.Type = %v, want %v", result.Fix.Type, types.FixTypeAPI)
				}
			}
		})
	}
}

func TestCheckUnauthorizedDevices(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "all authorized - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Authorized: true},
				{DeviceID: "2", Name: "server2", Authorized: true},
			},
			wantPass: true,
		},
		{
			name: "one unauthorized - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", Authorized: true},
				{DeviceID: "2", Name: "pending", Hostname: "pending", User: "alice@example.com", Authorized: false},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkUnauthorizedDevices(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-005" {
				t.Errorf("ID = %q, want DEV-005", result.ID)
			}
		})
	}
}

func TestCheckExternalDevices(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "no external devices - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server1", IsExternal: false},
			},
			wantPass: true,
		},
		{
			name: "external device - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "external-server", Hostname: "ext", User: "external@other.com", IsExternal: true},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkExternalDevices(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-006" {
				t.Errorf("ID = %q, want DEV-006", result.ID)
			}
		})
	}
}

func TestCheckSensitiveMachineNames(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name      string
		devices   []*client.Device
		wantPass  bool
		wantCount int
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "normal names - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "web-server-1", Hostname: "web-1"},
				{DeviceID: "2", Name: "api-gateway", Hostname: "api"},
			},
			wantPass: true,
		},
		{
			name: "name with password - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server-password-backup", Hostname: "backup"},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "name with prod-db - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "prod-database-primary", Hostname: "db1"},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "name with IP address - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server-192.168.1.100", Hostname: "srv"},
			},
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "hostname with internal - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server", Hostname: "internal-api-server"},
			},
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkSensitiveMachineNames(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-007" {
				t.Errorf("ID = %q, want DEV-007", result.ID)
			}
		})
	}
}

func TestIsDevDevice(t *testing.T) {
	tests := []struct {
		name   string
		device *client.Device
		want   bool
	}{
		{
			name:   "tagged device - not dev device",
			device: &client.Device{Name: "macbook", OS: "macOS", Tags: []string{"tag:server"}},
			want:   false,
		},
		{
			name:   "macOS device - dev device",
			device: &client.Device{Name: "laptop", OS: "macOS"},
			want:   true,
		},
		{
			name:   "iOS device - dev device",
			device: &client.Device{Name: "iphone", OS: "iOS"},
			want:   true,
		},
		{
			name:   "windows device - dev device",
			device: &client.Device{Name: "desktop", OS: "windows"},
			want:   true,
		},
		{
			name:   "android device - dev device",
			device: &client.Device{Name: "pixel", OS: "android"},
			want:   true,
		},
		{
			name:   "linux server - not dev device",
			device: &client.Device{Name: "server", OS: "linux", Hostname: "server1"},
			want:   false,
		},
		{
			name:   "macbook hostname pattern - dev device",
			device: &client.Device{Name: "work", OS: "linux", Hostname: "alice-macbook-pro"},
			want:   true,
		},
		{
			name:   "laptop hostname pattern - dev device",
			device: &client.Device{Name: "work", OS: "linux", Hostname: "bob-laptop"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDevDevice(tt.device)
			if got != tt.want {
				t.Errorf("isDevDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckUniqueUsers(t *testing.T) {
	d := &DeviceAuditor{}

	tests := []struct {
		name     string
		devices  []*client.Device
		wantPass bool
	}{
		{
			name:     "no devices",
			devices:  nil,
			wantPass: true,
		},
		{
			name: "few devices per user - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "laptop", User: "alice@example.com"},
				{DeviceID: "2", Name: "phone", User: "alice@example.com"},
				{DeviceID: "3", Name: "laptop", User: "bob@example.com"},
			},
			wantPass: true,
		},
		{
			name: "user with many devices - fail",
			devices: func() []*client.Device {
				var devices []*client.Device
				for i := 0; i < 15; i++ {
					devices = append(devices, &client.Device{
						DeviceID: string(rune(i)),
						Name:     "device",
						User:     "alice@example.com",
					})
				}
				return devices
			}(),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkUniqueUsers(tt.devices)

			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, tt.wantPass)
			}

			if result.ID != "DEV-011" {
				t.Errorf("ID = %q, want DEV-011", result.ID)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	versionRegex := regexp.MustCompile(`v?(\d+)\.(\d+)`)

	tests := []struct {
		name      string
		version   string
		wantMajor int
		wantMinor int
		wantOk    bool
	}{
		{
			name:      "standard version",
			version:   "v1.76.6",
			wantMajor: 1,
			wantMinor: 76,
			wantOk:    true,
		},
		{
			name:      "version without v prefix",
			version:   "1.74.0",
			wantMajor: 1,
			wantMinor: 74,
			wantOk:    true,
		},
		{
			name:      "invalid version",
			version:   "invalid",
			wantMajor: 0,
			wantMinor: 0,
			wantOk:    false,
		},
		{
			name:      "empty version",
			version:   "",
			wantMajor: 0,
			wantMinor: 0,
			wantOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, ok := parseVersion(tt.version, versionRegex)
			if major != tt.wantMajor {
				t.Errorf("major = %d, want %d", major, tt.wantMajor)
			}
			if minor != tt.wantMinor {
				t.Errorf("minor = %d, want %d", minor, tt.wantMinor)
			}
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}
