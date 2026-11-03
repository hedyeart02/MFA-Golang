package plugin

import "context"

// MFAProvider defines the standard interface for all MFA plugins (TOTP, Email, SMS, LDAP, Radius, Webhook)
type MFAProvider interface {
	// Name returns the provider name (e.g., "totp", "email")
	Name() string

	// Enroll initiates the enrollment process for a user
	Enroll(ctx context.Context, userID string) (map[string]interface{}, error)

	// Verify validates the provided token or response
	Verify(ctx context.Context, userID string, token string) (bool, error)
}
