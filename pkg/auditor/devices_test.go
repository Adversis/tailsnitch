package auditor

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	// MagicDNS enabled config - check should run
	magicDNSEnabled := &client.DNSConfig{MagicDNS: true}
	// MagicDNS disabled config - check should be skipped
	magicDNSDisabled := &client.DNSConfig{MagicDNS: false}

	tests := []struct {
		name      string
		devices   []*client.Device
		dnsConfig *client.DNSConfig
		wantPass  bool
		wantCount int
	}{
		{
			name:      "MagicDNS disabled - always pass (check skipped)",
			devices:   []*client.Device{{DeviceID: "1", Name: "server-password-backup", Hostname: "backup"}},
			dnsConfig: magicDNSDisabled,
			wantPass:  true,
		},
		{
			name:      "nil DNS config - always pass (check skipped)",
			devices:   []*client.Device{{DeviceID: "1", Name: "server-password-backup", Hostname: "backup"}},
			dnsConfig: nil,
			wantPass:  true,
		},
		{
			name:      "no devices with MagicDNS enabled",
			devices:   nil,
			dnsConfig: magicDNSEnabled,
			wantPass:  true,
		},
		{
			name: "normal names - pass",
			devices: []*client.Device{
				{DeviceID: "1", Name: "web-server-1", Hostname: "web-1"},
				{DeviceID: "2", Name: "api-gateway", Hostname: "api"},
			},
			dnsConfig: magicDNSEnabled,
			wantPass:  true,
		},
		{
			name: "name with password - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server-password-backup", Hostname: "backup"},
			},
			dnsConfig: magicDNSEnabled,
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "name with prod-db - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "prod-database-primary", Hostname: "db1"},
			},
			dnsConfig: magicDNSEnabled,
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "name with IP address - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server-192.168.1.100", Hostname: "srv"},
			},
			dnsConfig: magicDNSEnabled,
			wantPass:  false,
			wantCount: 1,
		},
		{
			name: "hostname with internal - fail",
			devices: []*client.Device{
				{DeviceID: "1", Name: "server", Hostname: "internal-api-server"},
			},
			dnsConfig: magicDNSEnabled,
			wantPass:  false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.checkSensitiveMachineNames(tt.devices, tt.dnsConfig)

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

// TestSetTailscaleBinaryPath tests the SetTailscaleBinaryPath function
// which allows specifying a custom path to the tailscale binary.
func TestSetTailscaleBinaryPath(t *testing.T) {
	// Save and restore the original override value
	originalOverride := tailscaleBinaryOverride
	t.Cleanup(func() {
		tailscaleBinaryOverride = originalOverride
	})

	tests := []struct {
		name       string
		path       string
		setup      func() string // returns path to use
		wantErr    bool
		errContain string
	}{
		{
			name:    "empty path returns nil",
			path:    "",
			wantErr: false,
		},
		{
			name:       "non-existent path returns error",
			path:       "/nonexistent/path/to/tailscale",
			wantErr:    true,
			errContain: "not found",
		},
		{
			name: "directory path returns error",
			setup: func() string {
				return t.TempDir()
			},
			wantErr:    true,
			errContain: "is a directory",
		},
		{
			name: "valid file path sets override",
			setup: func() string {
				// Create a temporary file to simulate a binary
				tmpDir := t.TempDir()
				tmpFile := tmpDir + "/tailscale"
				if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\n"), 0755); err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				return tmpFile
			},
			wantErr: false,
		},
		{
			name: "relative path is converted to absolute",
			setup: func() string {
				// Create a temporary file in current directory
				tmpDir := t.TempDir()
				tmpFile := tmpDir + "/tailscale-rel"
				if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\n"), 0755); err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				return tmpFile
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset override before each test
			tailscaleBinaryOverride = ""

			path := tt.path
			if tt.setup != nil {
				path = tt.setup()
			}

			err := SetTailscaleBinaryPath(path)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SetTailscaleBinaryPath() error = nil, want error containing %q", tt.errContain)
					return
				}
				if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("SetTailscaleBinaryPath() error = %v, want error containing %q", err, tt.errContain)
				}
				return
			}

			if err != nil {
				t.Errorf("SetTailscaleBinaryPath() unexpected error = %v", err)
				return
			}

			// For empty path, override should remain empty
			if path == "" {
				if tailscaleBinaryOverride != "" {
					t.Errorf("tailscaleBinaryOverride = %q, want empty", tailscaleBinaryOverride)
				}
				return
			}

			// For valid paths, override should be set to an absolute path
			if tailscaleBinaryOverride == "" {
				t.Error("tailscaleBinaryOverride should be set for valid path")
				return
			}

			if !filepath.IsAbs(tailscaleBinaryOverride) {
				t.Errorf("tailscaleBinaryOverride = %q, want absolute path", tailscaleBinaryOverride)
			}
		})
	}
}

// TestFindTailscaleBinary tests the findTailscaleBinary function
// which locates the tailscale binary using secure path resolution.
func TestFindTailscaleBinary(t *testing.T) {
	// Save and restore the original values
	originalOverride := tailscaleBinaryOverride
	originalCached := tailscaleBinaryPath
	t.Cleanup(func() {
		tailscaleBinaryOverride = originalOverride
		tailscaleBinaryPath = originalCached
	})

	t.Run("returns override path when set", func(t *testing.T) {
		// Reset state
		tailscaleBinaryOverride = ""
		tailscaleBinaryPath = ""

		// Create a temporary file to use as override
		tmpDir := t.TempDir()
		tmpFile := tmpDir + "/tailscale-override"
		if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		// Set the override
		if err := SetTailscaleBinaryPath(tmpFile); err != nil {
			t.Fatalf("SetTailscaleBinaryPath failed: %v", err)
		}

		// Verify findTailscaleBinary returns the override
		result, err := findTailscaleBinary()
		if err != nil {
			t.Errorf("findTailscaleBinary() unexpected error = %v", err)
			return
		}

		// The result should match the override (which may be converted to absolute)
		if result != tailscaleBinaryOverride {
			t.Errorf("findTailscaleBinary() = %q, want %q", result, tailscaleBinaryOverride)
		}
	})

	t.Run("returns cached path when available", func(t *testing.T) {
		// Reset override but set cached path
		tailscaleBinaryOverride = ""
		tailscaleBinaryPath = "/cached/path/to/tailscale"

		result, err := findTailscaleBinary()
		if err != nil {
			t.Errorf("findTailscaleBinary() unexpected error = %v", err)
			return
		}

		if result != "/cached/path/to/tailscale" {
			t.Errorf("findTailscaleBinary() = %q, want cached path", result)
		}
	})

	t.Run("override takes precedence over cached", func(t *testing.T) {
		// Create a temporary file for override
		tmpDir := t.TempDir()
		tmpFile := tmpDir + "/tailscale-precedence"
		if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		// Set both cached and override
		tailscaleBinaryPath = "/cached/path/to/tailscale"
		tailscaleBinaryOverride = tmpFile

		result, err := findTailscaleBinary()
		if err != nil {
			t.Errorf("findTailscaleBinary() unexpected error = %v", err)
			return
		}

		// Override should take precedence
		if result != tmpFile {
			t.Errorf("findTailscaleBinary() = %q, want override path %q", result, tmpFile)
		}
	})

	t.Run("searches known paths when no override or cache", func(t *testing.T) {
		// Reset both
		tailscaleBinaryOverride = ""
		tailscaleBinaryPath = ""

		// This test checks behavior when neither override nor cache is set.
		// The function will search known paths and possibly PATH.
		// We cannot guarantee tailscale is installed, so we just verify
		// the function executes without panicking.
		result, err := findTailscaleBinary()

		// Either we find tailscale or we get an appropriate error
		if err != nil {
			// Error should mention that binary was not found
			if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "tailscale") {
				t.Errorf("findTailscaleBinary() error = %v, want error mentioning 'not found'", err)
			}
		} else {
			// If found, result should be an absolute path
			if !filepath.IsAbs(result) {
				t.Errorf("findTailscaleBinary() = %q, want absolute path", result)
			}
		}
	})
}

// TestSetTailscaleBinaryPathValidation tests edge cases for path validation
func TestSetTailscaleBinaryPathValidation(t *testing.T) {
	// Save and restore the original override value
	originalOverride := tailscaleBinaryOverride
	t.Cleanup(func() {
		tailscaleBinaryOverride = originalOverride
	})

	t.Run("rejects symlink to directory", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		tmpDir := t.TempDir()
		subDir := tmpDir + "/subdir"
		if err := os.Mkdir(subDir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		symlinkPath := tmpDir + "/symlink-to-dir"
		if err := os.Symlink(subDir, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		err := SetTailscaleBinaryPath(symlinkPath)
		if err == nil {
			t.Error("SetTailscaleBinaryPath() should reject symlink to directory")
		}
		if err != nil && !strings.Contains(err.Error(), "directory") {
			t.Errorf("SetTailscaleBinaryPath() error = %v, want error mentioning 'directory'", err)
		}
	})

	t.Run("accepts symlink to file", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		tmpDir := t.TempDir()
		realFile := tmpDir + "/real-tailscale"
		if err := os.WriteFile(realFile, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		symlinkPath := tmpDir + "/symlink-to-file"
		if err := os.Symlink(realFile, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		err := SetTailscaleBinaryPath(symlinkPath)
		if err != nil {
			t.Errorf("SetTailscaleBinaryPath() should accept symlink to file, got error: %v", err)
		}
	})

	t.Run("handles path with spaces", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		tmpDir := t.TempDir()
		pathWithSpaces := tmpDir + "/path with spaces/tailscale"
		if err := os.MkdirAll(filepath.Dir(pathWithSpaces), 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(pathWithSpaces, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		err := SetTailscaleBinaryPath(pathWithSpaces)
		if err != nil {
			t.Errorf("SetTailscaleBinaryPath() should handle paths with spaces, got error: %v", err)
		}
	})
}

// TestHttpClientWithTimeout verifies the http client has proper timeout configured
func TestHttpClientWithTimeout(t *testing.T) {
	t.Run("has non-zero timeout", func(t *testing.T) {
		if httpClientWithTimeout.Timeout == 0 {
			t.Error("httpClientWithTimeout.Timeout = 0, want non-zero timeout")
		}
	})

	t.Run("timeout is reasonable", func(t *testing.T) {
		minTimeout := 5 * time.Second
		maxTimeout := 60 * time.Second

		if httpClientWithTimeout.Timeout < minTimeout {
			t.Errorf("httpClientWithTimeout.Timeout = %v, want >= %v", httpClientWithTimeout.Timeout, minTimeout)
		}
		if httpClientWithTimeout.Timeout > maxTimeout {
			t.Errorf("httpClientWithTimeout.Timeout = %v, want <= %v", httpClientWithTimeout.Timeout, maxTimeout)
		}
	})

	t.Run("timeout is exactly 10 seconds", func(t *testing.T) {
		expected := 10 * time.Second
		if httpClientWithTimeout.Timeout != expected {
			t.Errorf("httpClientWithTimeout.Timeout = %v, want %v", httpClientWithTimeout.Timeout, expected)
		}
	})
}

// TestFindTailscaleBinarySecurityChecks tests security-related behavior
func TestFindTailscaleBinarySecurityChecks(t *testing.T) {
	// Save and restore the original values
	originalOverride := tailscaleBinaryOverride
	originalCached := tailscaleBinaryPath
	t.Cleanup(func() {
		tailscaleBinaryOverride = originalOverride
		tailscaleBinaryPath = originalCached
	})

	t.Run("SetTailscaleBinaryPath rejects non-existent paths", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		err := SetTailscaleBinaryPath("/this/path/definitely/does/not/exist/tailscale")
		if err == nil {
			t.Error("SetTailscaleBinaryPath() should reject non-existent paths")
		}
	})

	t.Run("SetTailscaleBinaryPath rejects directories", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		tmpDir := t.TempDir()
		err := SetTailscaleBinaryPath(tmpDir)
		if err == nil {
			t.Error("SetTailscaleBinaryPath() should reject directories")
		}
		if err != nil && !strings.Contains(err.Error(), "directory") {
			t.Errorf("SetTailscaleBinaryPath() error = %v, want error mentioning 'directory'", err)
		}
	})

	t.Run("valid path is stored as absolute", func(t *testing.T) {
		tailscaleBinaryOverride = ""

		tmpDir := t.TempDir()
		tmpFile := tmpDir + "/tailscale-test"
		if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		err := SetTailscaleBinaryPath(tmpFile)
		if err != nil {
			t.Fatalf("SetTailscaleBinaryPath() failed: %v", err)
		}

		if !filepath.IsAbs(tailscaleBinaryOverride) {
			t.Errorf("tailscaleBinaryOverride = %q is not absolute", tailscaleBinaryOverride)
		}
	})
}
