// Package jwt provides JWT token generation and validation using RS256.
// Access tokens are short-lived for API authentication. Refresh tokens
// are long-lived for session extension. Both are asymmetrically signed
// so any service can validate without knowing the signing key.
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims defines the custom JWT claims for SAMLGuard tokens.
type Claims struct {
	jwtlib.RegisteredClaims
	UserID      string            `json:"user_id"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name,omitempty"`
	MFAVerified bool              `json:"mfa_verified"`
	SessionID   string            `json:"session_id"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	TokenType   string            `json:"token_type"`
}

// Service handles JWT token operations.
type Service struct {
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	issuer             string
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// NewService creates a JWT service from PEM-encoded key files.
func NewService(privateKeyFile, publicKeyFile, issuer string,
	accessExpiry, refreshExpiry time.Duration) (*Service, error) {

	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	publicKey, err := loadPublicKey(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading public key: %w", err)
	}

	return &Service{
		privateKey:         privateKey,
		publicKey:          publicKey,
		issuer:             issuer,
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}, nil
}

// GenerateAccessToken creates a signed short-lived JWT access token.
func (s *Service) GenerateAccessToken(userID, email, displayName, sessionID string,
	mfaVerified bool, attributes map[string]string) (string, error) {

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    s.issuer,
			Subject:   userID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(s.accessTokenExpiry)),
			NotBefore: jwtlib.NewNumericDate(now),
		},
		UserID:      userID,
		Email:       email,
		DisplayName: displayName,
		MFAVerified: mfaVerified,
		SessionID:   sessionID,
		Attributes:  attributes,
		TokenType:   "access",
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing access token: %w", err)
	}

	return signed, nil
}

// GenerateRefreshToken creates a signed long-lived JWT refresh token.
func (s *Service) GenerateRefreshToken(userID, sessionID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    s.issuer,
			Subject:   userID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(s.refreshTokenExpiry)),
			NotBefore: jwtlib.NewNumericDate(now),
		},
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing refresh token: %w", err)
	}

	return signed, nil
}

// ValidateToken parses and validates a JWT token string.
// Returns the claims if the token is valid, or an error if it is expired,
// malformed, or signed with an unrecognized key.
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwtlib.ParseWithClaims(tokenString, &Claims{},
		func(token *jwtlib.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwtlib.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.publicKey, nil
		})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", s.issuer, claims.Issuer)
	}

	return claims, nil
}

// PublicKey returns the RSA public key for external verification.
func (s *Service) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

// loadPrivateKey reads and parses an RSA private key from a PEM file.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaKey, nil
}

// loadPublicKey reads and parses an RSA public key from a PEM file.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		pub = cert.PublicKey
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaKey, nil
}
