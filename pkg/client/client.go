package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/time/rate"
	"tailscale.com/client/tailscale"
)

const (
	// DefaultRateLimit is the default number of requests per second
	DefaultRateLimit = 10
	// DefaultBurstSize is the default burst size for rate limiting
	DefaultBurstSize = 20
)

// Error types for classification
var (
	// ErrAuthentication indicates an authentication failure (401, 403)
	ErrAuthentication = errors.New("authentication failed")

	// ErrRateLimit indicates the API rate limit was exceeded (429)
	ErrRateLimit = errors.New("rate limit exceeded")

	// ErrNotFound indicates the requested resource was not found (404)
	ErrNotFound = errors.New("resource not found")

	// ErrPermission indicates insufficient permissions for the operation
	ErrPermission = errors.New("insufficient permissions")

	// ErrNetwork indicates a network connectivity issue
	ErrNetwork = errors.New("network error")

	// ErrTimeout indicates the request timed out
	ErrTimeout = errors.New("request timed out")
)

// APIError wraps an API error with classification and context
type APIError struct {
	Op         string // Operation that failed (e.g., "GetDevices", "GetACL")
	Resource   string // Resource type (e.g., "devices", "acl", "keys")
	Err        error  // Underlying error
	Kind       error  // Error classification (ErrAuthentication, ErrRateLimit, etc.)
	StatusCode int    // HTTP status code if available
	Suggestion string // User-friendly suggestion for fixing the error
}

func (e *APIError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s: %v\n  → %s", e.Op, e.Err, e.Suggestion)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *APIError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for error classification
func (e *APIError) Is(target error) bool {
	return errors.Is(e.Kind, target)
}

// classifyError analyzes an error and returns appropriate classification
func classifyError(err error, op, resource string) *APIError {
	if err == nil {
		return nil
	}

	apiErr := &APIError{
		Op:       op,
		Resource: resource,
		Err:      err,
	}

	errStr := strings.ToLower(err.Error())

	// Check for rate limiting
	if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "too many requests") {
		apiErr.Kind = ErrRateLimit
		apiErr.StatusCode = 429
		apiErr.Suggestion = "Wait a few minutes and try again. Consider reducing request frequency."
		return apiErr
	}

	// Check for authentication errors
	if strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "api token invalid") {
		apiErr.Kind = ErrAuthentication
		apiErr.StatusCode = 401
		apiErr.Suggestion = "Check your TSKEY or OAuth credentials. Generate a new key at: https://login.tailscale.com/admin/settings/keys"
		return apiErr
	}

	// Check for permission errors
	if strings.Contains(errStr, "403") || strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "permission") {
		apiErr.Kind = ErrPermission
		apiErr.StatusCode = 403
		apiErr.Suggestion = fmt.Sprintf("Your API key lacks permission to access %s. Verify key scopes at: https://login.tailscale.com/admin/settings/keys", resource)
		return apiErr
	}

	// Check for not found errors
	if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") {
		apiErr.Kind = ErrNotFound
		apiErr.StatusCode = 404
		apiErr.Suggestion = fmt.Sprintf("The requested %s was not found. Verify it exists and you have access.", resource)
		return apiErr
	}

	// Check for timeout errors
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errStr, "timeout") {
		apiErr.Kind = ErrTimeout
		apiErr.Suggestion = "Request timed out. Check your network connection or try again."
		return apiErr
	}

	// Check for network errors
	var netErr net.Error
	if errors.As(err, &netErr) || strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") || strings.Contains(errStr, "network is unreachable") {
		apiErr.Kind = ErrNetwork
		apiErr.Suggestion = "Network error. Check your internet connection and firewall settings."
		return apiErr
	}

	// Unknown error - no classification
	return apiErr
}

// Client wraps the Tailscale API client
type Client struct {
	ts      *tailscale.Client
	tailnet string
	limiter *rate.Limiter
}

// wait blocks until the rate limiter allows a request or context is cancelled
func (c *Client) wait(ctx context.Context) error {
	if c.limiter == nil {
		return nil
	}
	if err := c.limiter.Wait(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &APIError{
				Op:         "RateLimit",
				Err:        err,
				Kind:       ErrTimeout,
				Suggestion: "Request timed out waiting for rate limit. Try again or increase timeout.",
			}
		}
		return err
	}
	return nil
}

// New creates a new Tailscale API client.
// It supports two authentication methods:
//   - API Key: Set the TSKEY environment variable
//   - OAuth: Set TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET environment variables
//
// OAuth is preferred when both are set.
// The client includes built-in rate limiting to prevent API throttling.
func New(tailnet string) (*Client, error) {
	// If tailnet not specified, use "-" to indicate the default tailnet for the API key
	if tailnet == "" {
		tailnet = "-"
	}

	// Enable the unstable API acknowledgment
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	// Create rate limiter: allows DefaultRateLimit requests/sec with burst of DefaultBurstSize
	limiter := rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultBurstSize)

	// Check for OAuth credentials first (preferred)
	oauthClientID := os.Getenv("TS_OAUTH_CLIENT_ID")
	oauthClientSecret := os.Getenv("TS_OAUTH_CLIENT_SECRET")

	if oauthClientID != "" && oauthClientSecret != "" {
		return newWithOAuth(tailnet, oauthClientID, oauthClientSecret, limiter)
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
		limiter: limiter,
	}, nil
}

// newWithOAuth creates a client using OAuth client credentials
func newWithOAuth(tailnet, clientID, clientSecret string, limiter *rate.Limiter) (*Client, error) {
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
		limiter: limiter,
	}, nil
}

// Tailnet returns the tailnet name
func (c *Client) Tailnet() string {
	return c.tailnet
}

// GetACL fetches the current ACL policy
func (c *Client) GetACL(ctx context.Context) (*tailscale.ACL, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	acl, err := c.ts.ACL(ctx)
	if err != nil {
		return nil, classifyError(err, "GetACL", "ACL policy")
	}
	return acl, nil
}

// GetACLHuJSON fetches the ACL policy in HuJSON format
func (c *Client) GetACLHuJSON(ctx context.Context) (*tailscale.ACLHuJSON, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	acl, err := c.ts.ACLHuJSON(ctx)
	if err != nil {
		return nil, classifyError(err, "GetACLHuJSON", "ACL policy")
	}
	return acl, nil
}

// GetDevices fetches all devices in the tailnet
func (c *Client) GetDevices(ctx context.Context) ([]*tailscale.Device, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	devices, err := c.ts.Devices(ctx, nil)
	if err != nil {
		return nil, classifyError(err, "GetDevices", "devices")
	}
	return devices, nil
}

// GetDevice fetches a specific device by ID
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*tailscale.Device, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	device, err := c.ts.Device(ctx, deviceID, nil)
	if err != nil {
		return nil, classifyError(err, "GetDevice", fmt.Sprintf("device %s", deviceID))
	}
	return device, nil
}

// GetKeys fetches all auth key IDs
func (c *Client) GetKeys(ctx context.Context) ([]string, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	keys, err := c.ts.Keys(ctx)
	if err != nil {
		return nil, classifyError(err, "GetKeys", "auth keys")
	}
	return keys, nil
}

// GetKey fetches details for a specific auth key
func (c *Client) GetKey(ctx context.Context, keyID string) (*tailscale.Key, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	key, err := c.ts.Key(ctx, keyID)
	if err != nil {
		return nil, classifyError(err, "GetKey", fmt.Sprintf("auth key %s", keyID))
	}
	return key, nil
}

// GetDNSConfig fetches the DNS configuration
func (c *Client) GetDNSConfig(ctx context.Context) (*DNSConfig, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	prefs, err := c.ts.DNSPreferences(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "DNS preferences")
	}

	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	nameservers, err := c.ts.NameServers(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "nameservers")
	}

	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	searchPaths, err := c.ts.SearchPaths(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "search paths")
	}

	return &DNSConfig{
		MagicDNS:    prefs.MagicDNS,
		NameServers: nameservers,
		SearchPaths: searchPaths,
	}, nil
}

// GetDeviceRoutes fetches routes for a specific device
func (c *Client) GetDeviceRoutes(ctx context.Context, deviceID string) (*tailscale.Routes, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	routes, err := c.ts.Routes(ctx, deviceID)
	if err != nil {
		return nil, classifyError(err, "GetDeviceRoutes", fmt.Sprintf("routes for device %s", deviceID))
	}
	return routes, nil
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
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.DeleteKey(ctx, keyID); err != nil {
		return classifyError(err, "DeleteKey", fmt.Sprintf("auth key %s", keyID))
	}
	return nil
}

// DeleteDevice deletes a device from the tailnet
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.DeleteDevice(ctx, deviceID); err != nil {
		return classifyError(err, "DeleteDevice", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// AuthorizeDevice marks a device as authorized
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.AuthorizeDevice(ctx, deviceID); err != nil {
		return classifyError(err, "AuthorizeDevice", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// SetDeviceTags updates tags on a device
func (c *Client) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.SetTags(ctx, deviceID, tags); err != nil {
		return classifyError(err, "SetDeviceTags", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// CreateKey creates a new auth key with the specified capabilities
func (c *Client) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error) {
	if err := c.wait(ctx); err != nil {
		return "", nil, err
	}
	id, key, err := c.ts.CreateKey(ctx, caps)
	if err != nil {
		return "", nil, classifyError(err, "CreateKey", "auth key")
	}
	return id, key, nil
}

// CreateKeyWithExpiry creates a new auth key with custom expiration
func (c *Client) CreateKeyWithExpiry(ctx context.Context, caps tailscale.KeyCapabilities, expiry time.Duration) (string, *tailscale.Key, error) {
	if err := c.wait(ctx); err != nil {
		return "", nil, err
	}
	id, key, err := c.ts.CreateKeyWithExpiry(ctx, caps, expiry)
	if err != nil {
		return "", nil, classifyError(err, "CreateKeyWithExpiry", "auth key")
	}
	return id, key, nil
}

// SetACLHuJSON updates the ACL policy using HuJSON format
func (c *Client) SetACLHuJSON(ctx context.Context, acl *tailscale.ACLHuJSON) (*tailscale.ACLHuJSON, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	result, err := c.ts.SetACLHuJSON(ctx, *acl, false)
	if err != nil {
		return nil, classifyError(err, "SetACLHuJSON", "ACL policy")
	}
	return result, nil
}

// SetACLHuJSONWithCollisionCheck updates ACL with ETag collision detection
func (c *Client) SetACLHuJSONWithCollisionCheck(ctx context.Context, acl *tailscale.ACLHuJSON) (*tailscale.ACLHuJSON, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	result, err := c.ts.SetACLHuJSON(ctx, *acl, true)
	if err != nil {
		return nil, classifyError(err, "SetACLHuJSONWithCollisionCheck", "ACL policy")
	}
	return result, nil
}

// KeyCapabilities is an alias for tailscale.KeyCapabilities
type KeyCapabilities = tailscale.KeyCapabilities

// ACLHuJSON is an alias for tailscale.ACLHuJSON
type ACLHuJSON = tailscale.ACLHuJSON
