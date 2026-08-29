package auditor

import (
	"strings"
	"testing"
	"time"

	tsapi "tailscale.com/client/tailscale/v2"

	"github.com/Adversis/tailsnitch/pkg/client"
)

func settingsCtx(s client.TailnetSettings) *TailnetContext {
	return &TailnetContext{Settings: &s}
}

func TestCheckNetworkFlowLogsUsesTailnetSetting(t *testing.T) {
	l := &LoggingAuditor{}

	if got := l.checkNetworkFlowLogs(settingsCtx(client.TailnetSettings{NetworkFlowLoggingOn: true})); !got.Pass {
		t.Errorf("checkNetworkFlowLogs() Pass = false, want true when networkFlowLoggingOn is set")
	}

	got := l.checkNetworkFlowLogs(settingsCtx(client.TailnetSettings{NetworkFlowLoggingOn: false}))
	if got.Pass {
		t.Error("checkNetworkFlowLogs() Pass = true, want false when networkFlowLoggingOn is clear")
	}
}

func TestCheckNetworkFlowLogsDoesNotPassWhenSettingsUnavailable(t *testing.T) {
	// A missing scope must never read as a passing control.
	l := &LoggingAuditor{}
	tc := &TailnetContext{SettingsErr: client.ErrPermission}

	got := l.checkNetworkFlowLogs(tc)
	if got.Pass {
		t.Error("checkNetworkFlowLogs() Pass = true, want false when the setting could not be read")
	}
	if !strings.Contains(got.Description, "Could not determine") {
		t.Errorf("checkNetworkFlowLogs() description = %q, want it to say the setting was unreadable", got.Description)
	}
}

func TestCheckLogStreamingReportsMissingDestinations(t *testing.T) {
	l := &LoggingAuditor{}

	both := l.checkLogStreaming(&TailnetContext{ConfigLogstream: true, NetworkLogstream: true})
	if !both.Pass {
		t.Error("checkLogStreaming() Pass = false, want true when both log types stream")
	}

	partial := l.checkLogStreaming(&TailnetContext{ConfigLogstream: true})
	if partial.Pass {
		t.Error("checkLogStreaming() Pass = true, want false when network flow logs do not stream")
	}
	details, ok := partial.Details.([]string)
	if !ok || len(details) < 2 {
		t.Fatalf("checkLogStreaming() Details = %#v, want the missing log types listed", partial.Details)
	}
}

func TestCheckSecurityContact(t *testing.T) {
	l := &LoggingAuditor{}

	tests := []struct {
		name     string
		contact  client.Contacts
		wantPass bool
	}{
		{
			name:     "verified contact",
			contact:  client.Contacts{Security: tsapi.Contact{Email: "security@example.com"}},
			wantPass: true,
		},
		{
			name:     "unset contact",
			contact:  client.Contacts{},
			wantPass: false,
		},
		{
			name:     "unverified contact",
			contact:  client.Contacts{Security: tsapi.Contact{Email: "security@example.com", NeedsVerification: true}},
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contacts := tt.contact
			got := l.checkSecurityContact(&TailnetContext{Contacts: &contacts})
			if got.Pass != tt.wantPass {
				t.Errorf("checkSecurityContact() Pass = %v, want %v", got.Pass, tt.wantPass)
			}
		})
	}
}

func TestCheckOAuthClientsFlagsDepartedOwners(t *testing.T) {
	// This is the case LOG-006 exists for: the credential outlives the account
	// that created it.
	l := &LoggingAuditor{}
	tc := &TailnetContext{
		Users: []client.User{
			{ID: "u1", LoginName: "alice@example.com", Status: client.UserStatusActive},
			{ID: "u2", LoginName: "bob@example.com", Status: client.UserStatusSuspended},
		},
		OAuthClients: []client.Key{
			{ID: "k1", KeyType: client.KeyTypeClient, Description: "ci", UserID: "u1"},
			{ID: "k2", KeyType: client.KeyTypeClient, Description: "bobs-laptop", UserID: "u2"},
			{ID: "k3", KeyType: client.KeyTypeClient, Description: "ghost", UserID: "u404"},
		},
	}

	got := l.checkOAuthClients(tc)
	if got.Pass {
		t.Error("checkOAuthClients() Pass = true, want false when clients outlive their owners")
	}
	joined := strings.Join(got.Details.([]string), "\n")
	for _, want := range []string{"bobs-laptop", "ghost"} {
		if !strings.Contains(joined, want) {
			t.Errorf("checkOAuthClients() details missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "ci - ") {
		t.Errorf("checkOAuthClients() flagged a client whose owner is still active:\n%s", joined)
	}
}

func TestCheckOAuthClientsPassesWhenOwnersActive(t *testing.T) {
	l := &LoggingAuditor{}
	tc := &TailnetContext{
		Users:        []client.User{{ID: "u1", LoginName: "alice@example.com", Status: client.UserStatusActive}},
		OAuthClients: []client.Key{{ID: "k1", KeyType: client.KeyTypeClient, Description: "ci", UserID: "u1"}},
	}

	if got := l.checkOAuthClients(tc); !got.Pass {
		t.Errorf("checkOAuthClients() Pass = false, want true: %s", got.Description)
	}
}

func TestCheckWebhookEventsHonoursCategorySubscription(t *testing.T) {
	// The category subscription implies every event in its group, including
	// ones Tailscale adds later.
	l := &LoggingAuditor{}
	tc := &TailnetContext{Webhooks: []client.Webhook{{
		EndpointURL:   "https://example.com/hook",
		Subscriptions: []client.WebhookSubscriptionType{client.WebhookCategoryTailnetManagement},
	}}}

	if got := l.checkWebhookEvents(tc); !got.Pass {
		t.Errorf("checkWebhookEvents() Pass = false, want true for a category subscription: %s", got.Description)
	}
}

func TestCheckWebhookEventsReportsGaps(t *testing.T) {
	l := &LoggingAuditor{}
	tc := &TailnetContext{Webhooks: []client.Webhook{{
		EndpointURL:   "https://example.com/hook",
		Subscriptions: []client.WebhookSubscriptionType{client.WebhookNodeCreated},
	}}}

	got := l.checkWebhookEvents(tc)
	if got.Pass {
		t.Error("checkWebhookEvents() Pass = true, want false when critical events are unsubscribed")
	}
	joined := strings.Join(got.Details.([]string), "\n")
	if !strings.Contains(joined, string(client.WebhookPolicyUpdate)) {
		t.Errorf("checkWebhookEvents() details should name the unsubscribed policyUpdate event:\n%s", joined)
	}
	if strings.Contains(joined, "  - "+string(client.WebhookNodeCreated)+":") {
		t.Errorf("checkWebhookEvents() listed a subscribed event as missing:\n%s", joined)
	}
}

func TestCheckUserRolesSummarizesRealRoles(t *testing.T) {
	l := &LoggingAuditor{}
	tc := &TailnetContext{Users: []client.User{
		{LoginName: "owner@example.com", Role: client.UserRoleOwner, Status: client.UserStatusActive},
		{LoginName: "admin@example.com", Role: client.UserRoleAdmin, Status: client.UserStatusActive},
		{LoginName: "gone@example.com", Role: "member", Status: client.UserStatusSuspended},
	}}

	got := l.checkUserRoles(tc)
	if got.Pass {
		t.Error("checkUserRoles() Pass = true, want false while a suspended user remains")
	}
	joined := strings.Join(got.Details.([]string), "\n")
	if !strings.Contains(joined, "gone@example.com") {
		t.Errorf("checkUserRoles() details should name the suspended user:\n%s", joined)
	}
}

func TestCheckDevicePostureUsesIntegrations(t *testing.T) {
	l := &LoggingAuditor{}

	none := l.checkDevicePosture(&TailnetContext{})
	if none.Pass {
		t.Error("checkDevicePosture() Pass = true, want false with no integrations configured")
	}
	if none.ID != "DEV-014" {
		t.Errorf("checkDevicePosture() ID = %q, want DEV-014", none.ID)
	}

	configured := l.checkDevicePosture(&TailnetContext{
		PostureIntegrations: []client.PostureIntegration{{ID: "p1", Provider: "intune"}},
		Settings:            &client.TailnetSettings{PostureIdentityCollectionOn: true},
	})
	if !configured.Pass {
		t.Errorf("checkDevicePosture() Pass = false, want true with an integration: %s", configured.Description)
	}
	if !strings.Contains(configured.Description, "intune") {
		t.Errorf("checkDevicePosture() description = %q, want it to name the provider", configured.Description)
	}
}

func TestCheckWebhookConfigurationFlagsStaleSecrets(t *testing.T) {
	l := &LoggingAuditor{}

	fresh := l.checkWebhookConfiguration(&TailnetContext{Webhooks: []client.Webhook{
		{EndpointURL: "https://example.com/a", LastModified: time.Now().AddDate(0, -1, 0)},
	}})
	if !fresh.Pass {
		t.Errorf("checkWebhookConfiguration() Pass = false, want true for a recently rotated secret: %s", fresh.Description)
	}

	stale := l.checkWebhookConfiguration(&TailnetContext{Webhooks: []client.Webhook{
		{EndpointURL: "https://example.com/a", LastModified: time.Now().AddDate(-2, 0, 0)},
	}})
	if stale.Pass {
		t.Error("checkWebhookConfiguration() Pass = true, want false for a secret untouched for two years")
	}
}
