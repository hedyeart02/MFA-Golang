package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeys(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	require.NoError(t, os.WriteFile(privPath, privPEM, 0600))

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	require.NoError(t, os.WriteFile(pubPath, pubPEM, 0644))

	return privPath, pubPath
}

func TestGenerateAccessToken(t *testing.T) {
	privPath, pubPath := generateTestKeys(t)

	svc, err := NewService(privPath, pubPath, "test-issuer", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc.GenerateAccessToken("user-123", "test@example.com", "Test User", "sess-456", true,
		map[string]string{"role": "admin"})
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "Test User", claims.DisplayName)
	assert.Equal(t, "sess-456", claims.SessionID)
	assert.True(t, claims.MFAVerified)
	assert.Equal(t, "admin", claims.Attributes["role"])
	assert.Equal(t, "access", claims.TokenType)
	assert.Equal(t, "test-issuer", claims.Issuer)
}

func TestGenerateRefreshToken(t *testing.T) {
	privPath, pubPath := generateTestKeys(t)

	svc, err := NewService(privPath, pubPath, "test-issuer", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc.GenerateRefreshToken("user-123", "sess-456")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "sess-456", claims.SessionID)
	assert.Equal(t, "refresh", claims.TokenType)
}

func TestValidateExpiredToken(t *testing.T) {
	privPath, pubPath := generateTestKeys(t)

	svc, err := NewService(privPath, pubPath, "test-issuer", -1*time.Hour, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc.GenerateAccessToken("user-123", "test@example.com", "", "sess-456", false, nil)
	require.NoError(t, err)

	_, err = svc.ValidateToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestValidateTamperedToken(t *testing.T) {
	privPath, pubPath := generateTestKeys(t)

	svc, err := NewService(privPath, pubPath, "test-issuer", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc.GenerateAccessToken("user-123", "test@example.com", "", "sess-456", false, nil)
	require.NoError(t, err)

	tampered := token[:len(token)-5] + "XXXXX"
	_, err = svc.ValidateToken(tampered)
	assert.Error(t, err)
}

func TestValidateWrongIssuer(t *testing.T) {
	privPath, pubPath := generateTestKeys(t)

	svc1, err := NewService(privPath, pubPath, "issuer-1", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	svc2, err := NewService(privPath, pubPath, "issuer-2", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc1.GenerateAccessToken("user-123", "test@example.com", "", "sess-456", false, nil)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestValidateWrongKey(t *testing.T) {
	privPath1, pubPath1 := generateTestKeys(t)
	privPath2, pubPath2 := generateTestKeys(t)

	svc1, err := NewService(privPath1, pubPath1, "test-issuer", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	svc2, err := NewService(privPath2, pubPath2, "test-issuer", 15*time.Minute, 24*time.Hour)
	require.NoError(t, err)

	token, err := svc1.GenerateAccessToken("user-123", "test@example.com", "", "sess-456", false, nil)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.Error(t, err)
}
