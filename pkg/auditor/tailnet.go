package auditor

import (
	"context"
	"sync"

	"github.com/Adversis/tailsnitch/pkg/client"
)

// TailnetContext holds tailnet-wide state that several auditors need. It is
// fetched once per audit so the parallel auditors do not each re-request it.
//
// Every field can be unavailable when the credential lacks the corresponding
// OAuth scope. Each accessor returns the error so checks can degrade to manual
// guidance rather than reporting a misleading pass or fail.
type TailnetContext struct {
	Settings    *client.TailnetSettings
	SettingsErr error

	Users    []client.User
	UsersErr error

	Webhooks    []client.Webhook
	WebhooksErr error

	Contacts    *client.Contacts
	ContactsErr error

	PostureIntegrations []client.PostureIntegration
	PostureErr          error

	// ConfigLogstream and NetworkLogstream report whether a log streaming
	// destination is configured for configuration audit logs and network flow
	// logs respectively.
	ConfigLogstream  bool
	NetworkLogstream bool
	LogstreamErr     error

	OAuthClients []client.Key
	OAuthErr     error
}

// FetchTailnetContext gathers tailnet-wide state concurrently.
//
// It never returns an error: a failure to read one resource is recorded on the
// matching *Err field and leaves the others usable, because a credential
// scoped for a read-only audit may legitimately lack access to some of them.
func FetchTailnetContext(ctx context.Context, c *client.Client) *TailnetContext {
	tc := &TailnetContext{}

	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	run(func() { tc.Settings, tc.SettingsErr = c.GetTailnetSettings(ctx) })
	run(func() { tc.Users, tc.UsersErr = c.GetUsers(ctx) })
	run(func() { tc.Webhooks, tc.WebhooksErr = c.GetWebhooks(ctx) })
	run(func() { tc.Contacts, tc.ContactsErr = c.GetContacts(ctx) })
	run(func() { tc.PostureIntegrations, tc.PostureErr = c.GetPostureIntegrations(ctx) })
	run(func() { tc.OAuthClients, tc.OAuthErr = c.GetOAuthClients(ctx) })
	run(func() {
		cfg, err := c.HasLogstream(ctx, client.LogTypeConfiguration)
		if err != nil {
			tc.LogstreamErr = err
			return
		}
		network, err := c.HasLogstream(ctx, client.LogTypeNetwork)
		if err != nil {
			tc.LogstreamErr = err
			return
		}
		tc.ConfigLogstream, tc.NetworkLogstream = cfg, network
	})

	wg.Wait()
	return tc
}

// settings returns the tailnet settings, or nil when they could not be read.
// A nil TailnetContext is treated as "nothing fetched", which lets individual
// auditors be constructed and run without one.
func (tc *TailnetContext) settings() *client.TailnetSettings {
	if tc == nil || tc.SettingsErr != nil {
		return nil
	}
	return tc.Settings
}

// activeUserLogins returns the login names of users who still have tailnet
// access, and reports whether the user list was readable.
func (tc *TailnetContext) activeUserLogins() (map[string]bool, bool) {
	if tc == nil || tc.UsersErr != nil {
		return nil, false
	}

	logins := make(map[string]bool, len(tc.Users))
	for _, user := range tc.Users {
		if user.Status == client.UserStatusSuspended {
			continue
		}
		logins[user.LoginName] = true
	}
	return logins, true
}
