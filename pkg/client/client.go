package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
	tsapi "tailscale.com/client/tailscale/v2"
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

	// ErrProjectedResponse indicates the API returned records carrying only
	// their identifiers, so the fields the checks read are absent. The checks
	// cannot tell an absent field from a benign value, so the read fails
	// rather than handing them a listing that looks clean because it is empty.
	ErrProjectedResponse = errors.New("API returned identifiers only")
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

// classifyError analyzes an error and returns appropriate classification.
//
// The v2 API client returns a typed tsapi.APIError carrying the HTTP status, so
// that is consulted first. String matching remains as a fallback for transport
// errors and for anything that does not surface a status code.
func classifyError(err error, op, resource string) *APIError {
	if err == nil {
		return nil
	}

	apiErr := &APIError{
		Op:       op,
		Resource: resource,
		Err:      err,
	}

	// Prefer the typed error from the API client, which carries a real status code.
	var tsErr tsapi.APIError
	if errors.As(err, &tsErr) && tsErr.Status != 0 {
		apiErr.StatusCode = tsErr.Status
		if classifyStatus(apiErr, resource) {
			return apiErr
		}
	}

	errStr := strings.ToLower(err.Error())

	// Check for rate limiting
	if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "too many requests") {
		apiErr.StatusCode = http.StatusTooManyRequests
		classifyStatus(apiErr, resource)
		return apiErr
	}

	// Check for authentication errors
	if strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "api token invalid") {
		apiErr.StatusCode = http.StatusUnauthorized
		classifyStatus(apiErr, resource)
		return apiErr
	}

	// Check for permission errors
	if strings.Contains(errStr, "403") || strings.Contains(errStr, "forbidden") || strings.Contains(errStr, "permission") {
		apiErr.StatusCode = http.StatusForbidden
		classifyStatus(apiErr, resource)
		return apiErr
	}

	// Check for not found errors
	if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") {
		apiErr.StatusCode = http.StatusNotFound
		classifyStatus(apiErr, resource)
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

// classifyStatus fills in Kind and Suggestion from apiErr.StatusCode.
// It reports whether the status was recognized.
func classifyStatus(apiErr *APIError, resource string) bool {
	switch apiErr.StatusCode {
	case http.StatusTooManyRequests:
		apiErr.Kind = ErrRateLimit
		apiErr.Suggestion = "Wait a few minutes and try again. Consider reducing request frequency."
	case http.StatusUnauthorized:
		apiErr.Kind = ErrAuthentication
		apiErr.Suggestion = "Check your TS_API_KEY or OAuth credentials. Generate a new key at: https://login.tailscale.com/admin/settings/keys"
	case http.StatusForbidden:
		apiErr.Kind = ErrPermission
		apiErr.Suggestion = fmt.Sprintf("Your credential lacks the scope needed to read %s. Review scopes at: https://login.tailscale.com/admin/settings/keys", resource)
	case http.StatusNotFound:
		apiErr.Kind = ErrNotFound
		apiErr.Suggestion = fmt.Sprintf("The requested %s was not found. Verify it exists and you have access.", resource)
	default:
		apiErr.StatusCode = 0
		return false
	}
	return true
}

// Client wraps the Tailscale API client
type Client struct {
	ts      *tsapi.Client
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
//   - API Key: Set the TS_API_KEY environment variable
//   - OAuth: Set TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET environment variables
//
// OAuth is preferred when both are set.
// The client includes built-in rate limiting to prevent API throttling.
func New(tailnet string) (*Client, error) {
	// If tailnet not specified, use "-" to indicate the default tailnet for the credential.
	if tailnet == "" {
		tailnet = "-"
	}

	// Create rate limiter: allows DefaultRateLimit requests/sec with burst of DefaultBurstSize
	limiter := rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultBurstSize)

	ts := &tsapi.Client{Tailnet: tailnet}

	// Check for OAuth credentials first (preferred)
	oauthClientID := os.Getenv("TS_OAUTH_CLIENT_ID")
	oauthClientSecret := os.Getenv("TS_OAUTH_CLIENT_SECRET")

	switch {
	case oauthClientID != "" && oauthClientSecret != "":
		// The token URL is derived from the client's BaseURL
		// (https://api.tailscale.com/api/v2/oauth/token).
		ts.Auth = &tsapi.OAuth{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
		}
	default:
		apiKey := os.Getenv("TS_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("TSKEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("authentication required: set TS_API_KEY or TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET")
		}
		ts.APIKey = apiKey
	}

	// Touch a resource so the client finishes initialization (BaseURL, HTTP,
	// and the OAuth-wrapped transport) before rawGet reaches for those fields.
	_ = ts.Devices()

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

// Device is the API device model plus fields the typed client does not model yet.
type Device struct {
	tsapi.Device

	// MultipleConnections reports that several devices are currently connected
	// using this node key, which usually means node state was copied between
	// machines. The field is omitted by the API when only one connection is live.
	MultipleConnections bool `json:"multipleConnections"`
}

// LastSeenTime returns the device's last-seen timestamp and whether one is set.
// The API omits lastSeen for devices that are currently connected to control.
func (d *Device) LastSeenTime() (time.Time, bool) {
	if d.LastSeen == nil || d.LastSeen.IsZero() {
		return time.Time{}, false
	}
	return d.LastSeen.Time, true
}

// DNSConfig represents the DNS configuration
type DNSConfig struct {
	MagicDNS    bool
	NameServers []string
	SearchPaths []string
}

// Type aliases so callers do not need to import the API client directly.
type (
	Key                     = tsapi.Key
	KeyCapabilities         = tsapi.KeyCapabilities
	CreateKeyRequest        = tsapi.CreateKeyRequest
	RawACL                  = tsapi.RawACL
	ACL                     = tsapi.ACL
	TailnetSettings         = tsapi.TailnetSettings
	User                    = tsapi.User
	UserRole                = tsapi.UserRole
	UserStatus              = tsapi.UserStatus
	UserType                = tsapi.UserType
	Webhook                 = tsapi.Webhook
	WebhookSubscriptionType = tsapi.WebhookSubscriptionType
	Contacts                = tsapi.Contacts
	PostureIntegration      = tsapi.PostureIntegration
	DeviceRoutes            = tsapi.DeviceRoutes
	LogType                 = tsapi.LogType
)

// User statuses and roles reported by the users endpoint.
const (
	UserStatusSuspended     = tsapi.UserStatusSuspended
	UserStatusActive        = tsapi.UserStatusActive
	UserStatusNeedsApproval = tsapi.UserStatusNeedsApproval

	UserTypeShared = tsapi.UserTypeShared

	UserRoleOwner        = tsapi.UserRoleOwner
	UserRoleAdmin        = tsapi.UserRoleAdmin
	UserRoleITAdmin      = tsapi.UserRoleITAdmin
	UserRoleNetworkAdmin = tsapi.UserRoleNetworkAdmin
)

// Webhook subscription types this tool treats as security-critical.
const (
	WebhookCategoryTailnetManagement = tsapi.WebhookCategoryTailnetManagement
	WebhookNodeCreated               = tsapi.WebhookNodeCreated
	WebhookNodeDeleted               = tsapi.WebhookNodeDeleted
	WebhookNodeApproved              = tsapi.WebhookNodeApproved
	WebhookNodeNeedsApproval         = tsapi.WebhookNodeNeedsApproval
	WebhookPolicyUpdate              = tsapi.WebhookPolicyUpdate
	WebhookUserCreated               = tsapi.WebhookUserCreated
	WebhookUserDeleted               = tsapi.WebhookUserDeleted
	WebhookUserSuspended             = tsapi.WebhookUserSuspended
	WebhookUserRoleUpdated           = tsapi.WebhookUserRoleUpdated
)

// Log types for logstream configuration lookups.
const (
	LogTypeConfiguration = tsapi.LogTypeConfig
	LogTypeNetwork       = tsapi.LogTypeNetwork
)

// Auth key types returned by the keys endpoint. Only KeyTypeAuth entries are
// machine auth keys; the same endpoint also returns API access tokens, OAuth
// clients and federated identities.
const (
	KeyTypeAuth      = "auth"
	KeyTypeAPI       = "api"
	KeyTypeClient    = "client"
	KeyTypeFederated = "federated"
)

// rawGet performs a GET against the API and decodes the JSON response into out.
//
// The typed client covers almost everything tailsnitch needs, but a few response
// fields (notably multipleConnections) are not modelled by it yet. This mirrors
// the client's own auth handling: OAuth and identity federation are applied by
// the wrapped HTTP client, and an API key is sent as basic auth.
func (c *Client) rawGet(ctx context.Context, out any, query url.Values, pathElements ...string) error {
	u := *c.ts.BaseURL
	u.Path = "/api/v2/" + strings.Join(pathElements, "/")
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.ts.UserAgent != "" {
		req.Header.Set("User-Agent", c.ts.UserAgent)
	}
	if c.ts.APIKey != "" {
		req.SetBasicAuth(c.ts.APIKey, "")
	}

	resp, err := c.ts.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		apiErr := tsapi.APIError{Status: resp.StatusCode}
		// Best effort: the API returns a JSON body with a message on errors.
		_ = json.Unmarshal(body, &apiErr)
		apiErr.Status = resp.StatusCode
		if apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(body))
		}
		return apiErr
	}

	return json.Unmarshal(body, out)
}

// allFields requests the API's full field set rather than its limited default.
var allFields = url.Values{"fields": []string{"all"}}

// GetACL fetches the current ACL policy in parsed form
func (c *Client) GetACL(ctx context.Context) (*ACL, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	acl, err := c.ts.PolicyFile().Get(ctx)
	if err != nil {
		return nil, classifyError(err, "GetACL", "ACL policy")
	}
	return acl, nil
}

// GetACLHuJSON fetches the ACL policy in raw HuJSON format
func (c *Client) GetACLHuJSON(ctx context.Context) (*RawACL, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	acl, err := c.ts.PolicyFile().Raw(ctx)
	if err != nil {
		return nil, classifyError(err, "GetACLHuJSON", "ACL policy")
	}
	return acl, nil
}

// GetDevices fetches all devices in the tailnet.
//
// All fields are requested: the API's default field set omits advertisedRoutes,
// enabledRoutes, sshEnabled, postureIdentity and clientConnectivity, which the
// network and device checks depend on.
func (c *Client) GetDevices(ctx context.Context) ([]*Device, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}

	var resp struct {
		Devices []*Device `json:"devices"`
	}
	if err := c.rawGet(ctx, &resp, allFields, "tailnet", url.PathEscape(c.tailnet), "devices"); err != nil {
		return nil, classifyError(err, "GetDevices", "devices")
	}
	return resp.Devices, nil
}

// GetDevice fetches a specific device by ID, with all fields populated.
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}

	var dev Device
	if err := c.rawGet(ctx, &dev, allFields, "device", url.PathEscape(deviceID)); err != nil {
		return nil, classifyError(err, "GetDevice", fmt.Sprintf("device %s", deviceID))
	}
	return &dev, nil
}

// GetKeys fetches every key in the tailnet.
//
// all=true is required: without it the API returns only the keys owned by the
// calling user, and for an OAuth-derived token it returns the tailnet's OAuth
// clients rather than its auth keys. Callers that want machine auth keys should
// filter on Key.KeyType == KeyTypeAuth.
//
// A response carrying nothing but identifiers is rejected rather than returned;
// see projectedKeys.
func (c *Client) GetKeys(ctx context.Context) ([]Key, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	keys, err := c.ts.Keys().List(ctx, true)
	if err != nil {
		return nil, classifyError(err, "GetKeys", "auth keys")
	}
	if projectedKeys(keys) {
		return nil, &APIError{
			Op:         "GetKeys",
			Resource:   "auth keys",
			Err:        ErrProjectedResponse,
			Kind:       ErrProjectedResponse,
			Suggestion: "The keys listing came back without key types, so no key could be classified. Re-run the audit; if this persists, the API is returning identifiers only and the key checks cannot run.",
		}
	}
	return keys, nil
}

// projectedKeys reports whether a keys listing came back with only the
// identifiers set.
//
// The SDK documents KeysResource.List as returning keys for which "the only
// fields set ... will be its identifier". We have not seen the live API do
// that - AUTH-001 to AUTH-004 read the capability fields today and work - but
// the failure direction if it ever does is unacceptable. Every key would
// arrive with an empty KeyType, GetFederatedIdentities would match none of
// them and return an empty slice, and GetAuthKeys, which deliberately
// tolerates an empty KeyType, would admit all of them with no capabilities
// set. AUTH-001 to AUTH-006 and LOG-006 would then all report clean on data
// they never saw.
//
// A listing where only some keys lack a KeyType is left alone: that is the
// case GetAuthKeys tolerates on purpose. Only a listing where every entry
// lacks one looks like a projection.
func projectedKeys(keys []Key) bool {
	if len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		if key.KeyType != "" {
			return false
		}
	}
	return true
}

// GetAuthKeys fetches only the machine auth keys in the tailnet, excluding
// revoked and invalidated keys.
func (c *Client) GetAuthKeys(ctx context.Context) ([]Key, error) {
	keys, err := c.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	authKeys := make([]Key, 0, len(keys))
	for _, key := range keys {
		if key.KeyType != "" && key.KeyType != KeyTypeAuth {
			continue
		}
		if key.Invalid || !key.Revoked.IsZero() {
			continue
		}
		authKeys = append(authKeys, key)
	}
	return authKeys, nil
}

// GetOAuthClients fetches the tailnet's OAuth clients.
func (c *Client) GetOAuthClients(ctx context.Context) ([]Key, error) {
	keys, err := c.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	clients := make([]Key, 0, len(keys))
	for _, key := range keys {
		if key.KeyType == KeyTypeClient && !key.Invalid && key.Revoked.IsZero() {
			clients = append(clients, key)
		}
	}
	return clients, nil
}

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

// GetKey fetches details for a specific key
func (c *Client) GetKey(ctx context.Context, keyID string) (*Key, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	key, err := c.ts.Keys().Get(ctx, keyID)
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
	prefs, err := c.ts.DNS().Preferences(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "DNS preferences")
	}

	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	nameservers, err := c.ts.DNS().Nameservers(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "nameservers")
	}

	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	searchPaths, err := c.ts.DNS().SearchPaths(ctx)
	if err != nil {
		return nil, classifyError(err, "GetDNSConfig", "search paths")
	}

	return &DNSConfig{
		MagicDNS:    prefs.MagicDNS,
		NameServers: nameservers,
		SearchPaths: searchPaths,
	}, nil
}

// GetDeviceRoutes fetches subnet routes for a specific device
func (c *Client) GetDeviceRoutes(ctx context.Context, deviceID string) (*DeviceRoutes, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	routes, err := c.ts.Devices().SubnetRoutes(ctx, deviceID)
	if err != nil {
		return nil, classifyError(err, "GetDeviceRoutes", fmt.Sprintf("routes for device %s", deviceID))
	}
	return routes, nil
}

// GetTailnetSettings fetches tailnet-wide feature settings (device approval,
// key expiry duration, network flow logging, posture identity collection, ...).
func (c *Client) GetTailnetSettings(ctx context.Context) (*TailnetSettings, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	settings, err := c.ts.TailnetSettings().Get(ctx)
	if err != nil {
		return nil, classifyError(err, "GetTailnetSettings", "tailnet settings")
	}
	return settings, nil
}

// GetUsers fetches every user in the tailnet.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	users, err := c.ts.Users().List(ctx, nil, nil)
	if err != nil {
		return nil, classifyError(err, "GetUsers", "users")
	}
	return users, nil
}

// GetWebhooks fetches the tailnet's webhook endpoints.
func (c *Client) GetWebhooks(ctx context.Context) ([]Webhook, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	hooks, err := c.ts.Webhooks().List(ctx)
	if err != nil {
		return nil, classifyError(err, "GetWebhooks", "webhooks")
	}
	return hooks, nil
}

// GetContacts fetches the tailnet's account, support and security contacts.
func (c *Client) GetContacts(ctx context.Context) (*Contacts, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	contacts, err := c.ts.Contacts().Get(ctx)
	if err != nil {
		return nil, classifyError(err, "GetContacts", "contacts")
	}
	return contacts, nil
}

// GetPostureIntegrations fetches configured device posture integrations.
func (c *Client) GetPostureIntegrations(ctx context.Context) ([]PostureIntegration, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	integrations, err := c.ts.DevicePosture().ListIntegrations(ctx)
	if err != nil {
		return nil, classifyError(err, "GetPostureIntegrations", "posture integrations")
	}
	return integrations, nil
}

// HasLogstream reports whether a log streaming destination is configured for the
// given log type. A 404 from the API means "not configured" rather than an error.
func (c *Client) HasLogstream(ctx context.Context, logType LogType) (bool, error) {
	if err := c.wait(ctx); err != nil {
		return false, err
	}
	cfg, err := c.ts.Logging().LogstreamConfiguration(ctx, logType)
	if err != nil {
		if tsapi.IsNotFound(err) {
			return false, nil
		}
		return false, classifyError(err, "HasLogstream", fmt.Sprintf("%s log stream", logType))
	}
	return cfg != nil && cfg.DestinationType != "", nil
}

// DeleteKey deletes an auth key by ID
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.Keys().Delete(ctx, keyID); err != nil {
		return classifyError(err, "DeleteKey", fmt.Sprintf("auth key %s", keyID))
	}
	return nil
}

// DeleteDevice deletes a device from the tailnet
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.Devices().Delete(ctx, deviceID); err != nil {
		return classifyError(err, "DeleteDevice", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// AuthorizeDevice marks a device as authorized
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.Devices().SetAuthorized(ctx, deviceID, true); err != nil {
		return classifyError(err, "AuthorizeDevice", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// SetDeviceTags updates tags on a device
func (c *Client) SetDeviceTags(ctx context.Context, deviceID string, tags []string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.Devices().SetTags(ctx, deviceID, tags); err != nil {
		return classifyError(err, "SetDeviceTags", fmt.Sprintf("device %s", deviceID))
	}
	return nil
}

// SetACLHuJSON updates the ACL policy using HuJSON format, without ETag
// collision detection.
func (c *Client) SetACLHuJSON(ctx context.Context, acl *RawACL) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.PolicyFile().Set(ctx, acl.HuJSON, ""); err != nil {
		return classifyError(err, "SetACLHuJSON", "ACL policy")
	}
	return nil
}

// SetACLHuJSONWithCollisionCheck updates the ACL policy, rejecting the write if
// the policy changed since it was read.
func (c *Client) SetACLHuJSONWithCollisionCheck(ctx context.Context, acl *RawACL) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.ts.PolicyFile().Set(ctx, acl.HuJSON, acl.ETag); err != nil {
		return classifyError(err, "SetACLHuJSONWithCollisionCheck", "ACL policy")
	}
	return nil
}
