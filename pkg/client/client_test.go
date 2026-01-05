package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
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
