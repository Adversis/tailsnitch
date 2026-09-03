package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	tsapi "tailscale.com/client/tailscale/v2"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		op         string
		resource   string
		wantKind   error
		wantStatus int
	}{
		{
			name:     "nil error",
			err:      nil,
			op:       "GetDevices",
			resource: "devices",
		},
		{
			name:       "401 unauthorized",
			err:        fmt.Errorf("HTTP 401: Unauthorized"),
			op:         "GetACL",
			resource:   "ACL policy",
			wantKind:   ErrAuthentication,
			wantStatus: 401,
		},
		{
			name:       "403 forbidden",
			err:        fmt.Errorf("HTTP 403: Forbidden"),
			op:         "GetDevices",
			resource:   "devices",
			wantKind:   ErrPermission,
			wantStatus: 403,
		},
		{
			name:       "404 not found",
			err:        fmt.Errorf("HTTP 404: not found"),
			op:         "GetDevice",
			resource:   "device xyz",
			wantKind:   ErrNotFound,
			wantStatus: 404,
		},
		{
			name:       "429 rate limit",
			err:        fmt.Errorf("HTTP 429: Too Many Requests"),
			op:         "GetDevices",
			resource:   "devices",
			wantKind:   ErrRateLimit,
			wantStatus: 429,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			op:       "GetDevices",
			resource: "devices",
			wantKind: ErrTimeout,
		},
		{
			name:       "API token invalid",
			err:        fmt.Errorf("API token invalid"),
			op:         "GetACL",
			resource:   "ACL policy",
			wantKind:   ErrAuthentication,
			wantStatus: 401,
		},
		{
			name:     "connection refused",
			err:      fmt.Errorf("dial tcp: connection refused"),
			op:       "GetDevices",
			resource: "devices",
			wantKind: ErrNetwork,
		},
		{
			name:     "unknown error",
			err:      fmt.Errorf("something went wrong"),
			op:       "GetDevices",
			resource: "devices",
			wantKind: nil, // no classification
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyError(tt.err, tt.op, tt.resource)

			if tt.err == nil {
				if result != nil {
					t.Errorf("expected nil result for nil error, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if result.Op != tt.op {
				t.Errorf("Op = %q, want %q", result.Op, tt.op)
			}

			if result.Resource != tt.resource {
				t.Errorf("Resource = %q, want %q", result.Resource, tt.resource)
			}

			if tt.wantKind != nil {
				if !errors.Is(result, tt.wantKind) {
					t.Errorf("Kind = %v, want %v", result.Kind, tt.wantKind)
				}
			}

			if tt.wantStatus != 0 && result.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", result.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestAPIErrorIs(t *testing.T) {
	apiErr := &APIError{
		Op:       "GetDevices",
		Resource: "devices",
		Err:      fmt.Errorf("HTTP 401: Unauthorized"),
		Kind:     ErrAuthentication,
	}

	if !errors.Is(apiErr, ErrAuthentication) {
		t.Error("expected errors.Is(apiErr, ErrAuthentication) to be true")
	}

	if errors.Is(apiErr, ErrRateLimit) {
		t.Error("expected errors.Is(apiErr, ErrRateLimit) to be false")
	}
}

func TestAPIErrorUnwrap(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	apiErr := &APIError{
		Op:       "GetDevices",
		Resource: "devices",
		Err:      originalErr,
	}

	if !errors.Is(apiErr, originalErr) {
		t.Error("expected Unwrap to return original error")
	}
}

func TestAPIErrorMessage(t *testing.T) {
	tests := []struct {
		name         string
		apiErr       *APIError
		wantContains []string
	}{
		{
			name: "with suggestion",
			apiErr: &APIError{
				Op:         "GetDevices",
				Err:        fmt.Errorf("HTTP 401"),
				Suggestion: "Check your API key",
			},
			wantContains: []string{"GetDevices", "HTTP 401", "→", "Check your API key"},
		},
		{
			name: "without suggestion",
			apiErr: &APIError{
				Op:  "GetDevices",
				Err: fmt.Errorf("something failed"),
			},
			wantContains: []string{"GetDevices", "something failed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.apiErr.Error()
			for _, want := range tt.wantContains {
				if !contains(msg, want) {
					t.Errorf("error message %q should contain %q", msg, want)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// newTestClient builds a Client pointed at a test server, bypassing the
// environment-driven constructor.
func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	ts := &tsapi.Client{Tailnet: "example.com", APIKey: "tskey-api-test", BaseURL: base}
	_ = ts.Devices() // finish client initialization

	return &Client{ts: ts, tailnet: "example.com"}
}

func TestGetDevicesRequestsAllFields(t *testing.T) {
	// Regression: the API's default field set omits advertisedRoutes,
	// enabledRoutes and sshEnabled, so the network checks that read them
	// always saw empty slices.
	var gotPath, gotFields string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotFields = r.URL.Query().Get("fields")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"devices":[{
			"id":"1","nodeId":"n1","name":"router","hostname":"router",
			"advertisedRoutes":["10.0.0.0/24","0.0.0.0/0"],
			"enabledRoutes":["10.0.0.0/24"],
			"sshEnabled":true,
			"multipleConnections":true,
			"tailnetLockError":"node key is not signed"
		}]}`)
	}))
	defer srv.Close()

	devices, err := newTestClient(t, srv).GetDevices(context.Background())
	if err != nil {
		t.Fatalf("GetDevices() error = %v", err)
	}

	if want := "/api/v2/tailnet/example.com/devices"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
	if gotFields != "all" {
		t.Errorf("fields query = %q, want %q", gotFields, "all")
	}

	if len(devices) != 1 {
		t.Fatalf("GetDevices() returned %d devices, want 1", len(devices))
	}
	dev := devices[0]
	if len(dev.AdvertisedRoutes) != 2 {
		t.Errorf("AdvertisedRoutes = %v, want 2 entries", dev.AdvertisedRoutes)
	}
	if len(dev.EnabledRoutes) != 1 {
		t.Errorf("EnabledRoutes = %v, want 1 entry", dev.EnabledRoutes)
	}
	if !dev.SSHEnabled {
		t.Error("SSHEnabled = false, want true")
	}
	if !dev.MultipleConnections {
		t.Error("MultipleConnections = false, want true")
	}
	if dev.TailnetLockError == "" {
		t.Error("TailnetLockError is empty, want the API value")
	}
}

func TestGetKeysRequestsAllAndFiltersAuthKeys(t *testing.T) {
	// Regression: without all=true the endpoint returns only the caller's own
	// keys, and for an OAuth-derived token it returns the tailnet's OAuth
	// clients instead of its auth keys.
	var gotAll string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAll = r.URL.Query().Get("all")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[
			{"id":"k1","keyType":"auth","description":"ci","capabilities":{"devices":{"create":{"reusable":true}}}},
			{"id":"k2","keyType":"client","description":"terraform","scopes":["all"]},
			{"id":"k3","keyType":"api","description":"personal token"},
			{"id":"k4","keyType":"auth","description":"revoked","revoked":"2024-01-01T00:00:00Z"},
			{"id":"k5","keyType":"auth","description":"invalid","invalid":true}
		]}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)

	authKeys, err := c.GetAuthKeys(context.Background())
	if err != nil {
		t.Fatalf("GetAuthKeys() error = %v", err)
	}
	if gotAll != "true" {
		t.Errorf("all query = %q, want %q", gotAll, "true")
	}
	if len(authKeys) != 1 {
		t.Fatalf("GetAuthKeys() returned %d keys, want 1 (revoked and invalid keys excluded)", len(authKeys))
	}
	if authKeys[0].ID != "k1" {
		t.Errorf("GetAuthKeys() returned %q, want k1", authKeys[0].ID)
	}
	if !authKeys[0].Capabilities.Devices.Create.Reusable {
		t.Error("reusable capability was not decoded")
	}

	clients, err := c.GetOAuthClients(context.Background())
	if err != nil {
		t.Fatalf("GetOAuthClients() error = %v", err)
	}
	if len(clients) != 1 || clients[0].ID != "k2" {
		t.Errorf("GetOAuthClients() = %#v, want just k2", clients)
	}
}

func TestGetFederatedIdentitiesFiltersByKeyType(t *testing.T) {
	keys := []Key{
		{ID: "k1", KeyType: KeyTypeAuth},
		{ID: "k2", KeyType: KeyTypeFederated, Subject: "repo:org/repo:ref:refs/heads/main"},
		{ID: "k3", KeyType: KeyTypeClient},
		{ID: "k4", KeyType: KeyTypeFederated, Invalid: true},
		{ID: "k5", KeyType: KeyTypeFederated, Revoked: time.Now()},
	}

	got := filterFederatedIdentities(keys)
	if len(got) != 1 || got[0].ID != "k2" {
		t.Errorf("filterFederatedIdentities returned %v, want only k2", got)
	}
}

func TestClassifyErrorUsesTypedAPIStatus(t *testing.T) {
	// The v2 client returns a typed error carrying the real status code, so
	// classification no longer depends on the message text.
	err := classifyError(tsapi.APIError{Message: "calling actor does not have access", Status: 403}, "GetUsers", "users")
	if !errors.Is(err, ErrPermission) {
		t.Errorf("classifyError() kind = %v, want ErrPermission", err.Kind)
	}
	if err.StatusCode != 403 {
		t.Errorf("classifyError() status = %d, want 403", err.StatusCode)
	}
}

// The SDK documents Keys().List as possibly setting only each key's
// identifier. If the live API ever does that, every key arrives with an empty
// keyType: filterFederatedIdentities matches none of them, and GetAuthKeys -
// which tolerates an empty keyType on purpose - admits all of them with no
// capabilities set. AUTH-001 to AUTH-006 would then report clean on data they
// never saw. The read has to fail so those checks fall back to not evaluated.
func TestGetKeysRejectsAProjectedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[{"id":"k1"},{"id":"k2"},{"id":"k3"}]}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)

	keys, err := c.GetKeys(context.Background())
	if err == nil {
		t.Fatalf("SECURITY: GetKeys() returned %d keys and no error for a listing with no key types; "+
			"every key check downstream would report clean on a response it could not read", len(keys))
	}
	if !errors.Is(err, ErrProjectedResponse) {
		t.Errorf("GetKeys() error = %v, want one matching ErrProjectedResponse", err)
	}

	// The three callers that classify on KeyType must all fail closed.
	if _, err := c.GetAuthKeys(context.Background()); !errors.Is(err, ErrProjectedResponse) {
		t.Errorf("GetAuthKeys() error = %v, want ErrProjectedResponse", err)
	}
	if _, err := c.GetOAuthClients(context.Background()); !errors.Is(err, ErrProjectedResponse) {
		t.Errorf("GetOAuthClients() error = %v, want ErrProjectedResponse", err)
	}
	if _, err := c.GetFederatedIdentities(context.Background()); !errors.Is(err, ErrProjectedResponse) {
		t.Errorf("GetFederatedIdentities() error = %v, want ErrProjectedResponse", err)
	}
}

// Only a listing where every entry lacks a key type looks like a projection.
// GetAuthKeys deliberately admits a key whose keyType is empty, so a mixed
// listing must still work, and an empty tailnet is not a projection either.
func TestGetKeysAcceptsPartialAndEmptyListings(t *testing.T) {
	t.Run("some keys without a key type still work", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[
				{"id":"k1","description":"no key type"},
				{"id":"k2","keyType":"auth","description":"ci","capabilities":{"devices":{"create":{"reusable":true}}}}
			]}`)
		}))
		defer srv.Close()

		keys, err := newTestClient(t, srv).GetKeys(context.Background())
		if err != nil {
			t.Fatalf("GetKeys() error = %v, want none: only an all-empty listing is a projection", err)
		}
		if len(keys) != 2 {
			t.Fatalf("GetKeys() returned %d keys, want 2", len(keys))
		}

		authKeys, err := newTestClient(t, srv).GetAuthKeys(context.Background())
		if err != nil {
			t.Fatalf("GetAuthKeys() error = %v", err)
		}
		if len(authKeys) != 2 {
			t.Errorf("GetAuthKeys() returned %d keys, want 2: an empty keyType is tolerated on purpose", len(authKeys))
		}
	})

	t.Run("an empty listing is not a projection", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[]}`)
		}))
		defer srv.Close()

		keys, err := newTestClient(t, srv).GetKeys(context.Background())
		if err != nil {
			t.Fatalf("GetKeys() error = %v, want none for a tailnet with no keys", err)
		}
		if len(keys) != 0 {
			t.Errorf("GetKeys() returned %d keys, want 0", len(keys))
		}
	})
}
