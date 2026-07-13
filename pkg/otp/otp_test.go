package otp

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOTPGenerateAndValidate(t *testing.T) {
	svc := NewTOTPService("TestIssuer", 1)

	secret, uri, err := svc.GenerateKey("user@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "TestIssuer")

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	assert.True(t, svc.Validate(code, secret))
}

func TestTOTPInvalidCode(t *testing.T) {
	svc := NewTOTPService("TestIssuer", 1)

	secret, _, err := svc.GenerateKey("user@example.com")
	require.NoError(t, err)

	assert.False(t, svc.Validate("000000", secret))
}

type mockSender struct {
	lastRecipient string
	lastCode      string
}

func (m *mockSender) Send(recipient, code string) error {
	m.lastRecipient = recipient
	m.lastCode = code
	return nil
}

func (m *mockSender) Method() string {
	return "mock"
}

func TestEmailOTPGenerateAndValidate(t *testing.T) {
	sender := &mockSender{}
	svc := NewEmailOTPService(sender, 6, 5*time.Minute)

	err := svc.Generate("user-123", "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", sender.lastRecipient)
	assert.Len(t, sender.lastCode, 6)

	err = svc.Validate("user-123", sender.lastCode, 5)
	assert.NoError(t, err)
}

func TestEmailOTPExpired(t *testing.T) {
	sender := &mockSender{}
	svc := NewEmailOTPService(sender, 6, 1*time.Millisecond)

	err := svc.Generate("user-123", "user@example.com")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	err = svc.Validate("user-123", sender.lastCode, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestEmailOTPMaxAttempts(t *testing.T) {
	sender := &mockSender{}
	svc := NewEmailOTPService(sender, 6, 5*time.Minute)

	err := svc.Generate("user-123", "user@example.com")
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = svc.Validate("user-123", "wrong", 3)
		if err == nil {
			break
		}
	}

	err = svc.Validate("user-123", sender.lastCode, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum attempts")
}

func TestBackupCodeGenerateAndValidate(t *testing.T) {
	svc := NewBackupCodeService(5, 8)

	plainCodes, hashedJSON, err := svc.GenerateCodes()
	require.NoError(t, err)
	assert.Len(t, plainCodes, 5)
	assert.NotEmpty(t, hashedJSON)

	updatedJSON, valid, err := svc.ValidateCode(plainCodes[0], hashedJSON)
	require.NoError(t, err)
	assert.True(t, valid)

	remaining, err := svc.RemainingCount(updatedJSON)
	require.NoError(t, err)
	assert.Equal(t, 4, remaining)
}

func TestBackupCodeInvalidCode(t *testing.T) {
	svc := NewBackupCodeService(5, 8)

	_, hashedJSON, err := svc.GenerateCodes()
	require.NoError(t, err)

	_, valid, err := svc.ValidateCode("invalidcode", hashedJSON)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestBackupCodeSingleUse(t *testing.T) {
	svc := NewBackupCodeService(5, 8)

	plainCodes, hashedJSON, err := svc.GenerateCodes()
	require.NoError(t, err)

	updatedJSON, valid, err := svc.ValidateCode(plainCodes[0], hashedJSON)
	require.NoError(t, err)
	assert.True(t, valid)

	_, valid, err = svc.ValidateCode(plainCodes[0], updatedJSON)
	require.NoError(t, err)
	assert.False(t, valid)
}
