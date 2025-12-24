package client

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
)

// Client wraps the Tailscale API client
type Client struct {
	ts      *tailscale.Client
	tailnet string
}

// New creates a new Tailscale API client.
// It supports two authentication methods:
//   - API Key: Set the TSKEY environment variable
//   - OAuth: Set TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET environment variables
//
// OAuth is preferred when both are set.
func New(tailnet string) (*Client, error) {
	// If tailnet not specified, use "-" to indicate the default tailnet for the API key
	if tailnet == "" {
		tailnet = "-"
	}

	// Enable the unstable API acknowledgment
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	// Check for OAuth credentials first (preferred)
	oauthClientID := os.Getenv("TS_OAUTH_CLIENT_ID")
	oauthClientSecret := os.Getenv("TS_OAUTH_CLIENT_SECRET")

	if oauthClientID != "" && oauthClientSecret != "" {
		return newWithOAuth(tailnet, oauthClientID, oauthClientSecret)
	}

	// Fall back to API key
	apiKey := os.Getenv("TSKEY")
	if apiKey == "" {
		return nil, fmt.Errorf("authentication required: set TSKEY or TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET")
	}

	ts := tailscale.NewClient(tailnet, tailscale.APIKey(apiKey))

	return &Client{
		ts:      ts,
		tailnet: tailnet,
	}, nil
}

// newWithOAuth creates a client using OAuth client credentials
func newWithOAuth(tailnet, clientID, clientSecret string) (*Client, error) {
	oauthConfig := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
	}

	// Create an HTTP client that handles OAuth token management
	httpClient := oauthConfig.Client(context.Background())

	// Create Tailscale client with a dummy API key (won't be used since we override HTTPClient)
	ts := tailscale.NewClient(tailnet, tailscale.APIKey("oauth"))
	ts.HTTPClient = httpClient

	return &Client{
		ts:      ts,
		tailnet: tailnet,
	}, nil
}

// Tailnet returns the tailnet name
func (c *Client) Tailnet() string {
	return c.tailnet
}

// GetACL fetches the current ACL policy
func (c *Client) GetACL(ctx context.Context) (*tailscale.ACL, error) {
	return c.ts.ACL(ctx)
}

// GetACLHuJSON fetches the ACL policy in HuJSON format
func (c *Client) GetACLHuJSON(ctx context.Context) (*tailscale.ACLHuJSON, error) {
	return c.ts.ACLHuJSON(ctx)
}

// GetDevices fetches all devices in the tailnet
func (c *Client) GetDevices(ctx context.Context) ([]*tailscale.Device, error) {
	return c.ts.Devices(ctx, nil)
}

// GetDevice fetches a specific device by ID
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*tailscale.Device, error) {
	return c.ts.Device(ctx, deviceID, nil)
}

// GetKeys fetches all auth key IDs
func (c *Client) GetKeys(ctx context.Context) ([]string, error) {
	return c.ts.Keys(ctx)
}

// GetKey fetches details for a specific auth key
func (c *Client) GetKey(ctx context.Context, keyID string) (*tailscale.Key, error) {
	return c.ts.Key(ctx, keyID)
}

// GetDNSConfig fetches the DNS configuration
func (c *Client) GetDNSConfig(ctx context.Context) (*DNSConfig, error) {
	prefs, err := c.ts.DNSPreferences(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS preferences: %w", err)
	}

	nameservers, err := c.ts.NameServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get nameservers: %w", err)
	}

	searchPaths, err := c.ts.SearchPaths(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get search paths: %w", err)
	}

	return &DNSConfig{
		MagicDNS:    prefs.MagicDNS,
		NameServers: nameservers,
		SearchPaths: searchPaths,
	}, nil
}

// GetDeviceRoutes fetches routes for a specific device
func (c *Client) GetDeviceRoutes(ctx context.Context, deviceID string) (*tailscale.Routes, error) {
	return c.ts.Routes(ctx, deviceID)
}

// DNSConfig represents the DNS configuration
type DNSConfig struct {
	MagicDNS    bool
	NameServers []string
	SearchPaths []string
}

// Device is an alias for tailscale.Device
type Device = tailscale.Device

// DeleteKey deletes an auth key by ID
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	return c.ts.DeleteKey(ctx, keyID)
}

// DeleteDevice deletes a device from the tailnet
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) error {
	return c.ts.DeleteDevice(ctx, deviceID)
}

// AuthorizeDevice marks a device as authorized
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error {
	return c.ts.AuthorizeDevice(ctx, deviceID)
}

// SetDeviceTags updates tags on a device
func (c *Client) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error {
	return c.ts.SetTags(ctx, deviceID, tags)
}

// CreateKey creates a new auth key with the specified capabilities
func (c *Client) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error) {
	return c.ts.CreateKey(ctx, caps)
}

// CreateKeyWithExpiry creates a new auth key with custom expiration
func (c *Client) CreateKeyWithExpiry(ctx context.Context, caps tailscale.KeyCapabilities, expiry time.Duration) (string, *tailscale.Key, error) {
	return c.ts.CreateKeyWithExpiry(ctx, caps, expiry)
}

// SetACLHuJSON updates the ACL policy using HuJSON format
func (c *Client) SetACLHuJSON(ctx context.Context, acl *tailscale.ACLHuJSON) (*tailscale.ACLHuJSON, error) {
	return c.ts.SetACLHuJSON(ctx, *acl, false)
}

// SetACLHuJSONWithCollisionCheck updates ACL with ETag collision detection
func (c *Client) SetACLHuJSONWithCollisionCheck(ctx context.Context, acl *tailscale.ACLHuJSON) (*tailscale.ACLHuJSON, error) {
	return c.ts.SetACLHuJSON(ctx, *acl, true)
}

// KeyCapabilities is an alias for tailscale.KeyCapabilities
type KeyCapabilities = tailscale.KeyCapabilities

// ACLHuJSON is an alias for tailscale.ACLHuJSON
type ACLHuJSON = tailscale.ACLHuJSON
