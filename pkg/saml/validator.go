package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Validator handles SAML response and assertion validation including
// XML signature verification, issuer/audience checks, timestamp validation,
// and replay detection.
type Validator struct {
	trustedCerts   []*x509.Certificate
	allowedIssuers []string
	allowedAudiences []string
	replayCache    map[string]time.Time
	replayMu       sync.RWMutex
	maxClockSkew   time.Duration
	logger         *zap.Logger
}

// ValidatorConfig holds configuration for the SAML validator.
type ValidatorConfig struct {
	IdPCertFiles     []string
	AllowedIssuers   []string
	AllowedAudiences []string
	MaxClockSkew     time.Duration
}

// NewValidator creates a validator with the provided trusted certificates
// and validation rules.
func NewValidator(cfg ValidatorConfig, log *zap.Logger) (*Validator, error) {
	var certs []*x509.Certificate
	for _, certFile := range cfg.IdPCertFiles {
		cert, err := loadCertificate(certFile)
		if err != nil {
			return nil, fmt.Errorf("loading IdP certificate %s: %w", certFile, err)
		}
		certs = append(certs, cert)
	}

	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}

	v := &Validator{
		trustedCerts:   certs,
		allowedIssuers: cfg.AllowedIssuers,
		allowedAudiences: cfg.AllowedAudiences,
		replayCache:    make(map[string]time.Time),
		maxClockSkew:   cfg.MaxClockSkew,
		logger:         log,
	}

	go v.cleanupReplayCache()

	return v, nil
}

// ValidateIssuer checks that the issuer is in the allowed list.
func (v *Validator) ValidateIssuer(issuer string) error {
	if len(v.allowedIssuers) == 0 {
		return nil
	}

	for _, allowed := range v.allowedIssuers {
		if issuer == allowed {
			return nil
		}
	}

	return fmt.Errorf("issuer %q is not in allowed list", issuer)
}

// ValidateAudience checks that at least one audience matches the allowed list.
func (v *Validator) ValidateAudience(audiences []string) error {
	if len(v.allowedAudiences) == 0 {
		return nil
	}

	for _, aud := range audiences {
		for _, allowed := range v.allowedAudiences {
			if aud == allowed {
				return nil
			}
		}
	}

	return fmt.Errorf("no audience matches allowed list")
}

// ValidateTimestamps checks NotBefore and NotOnOrAfter conditions.
func (v *Validator) ValidateTimestamps(notBefore, notOnOrAfter time.Time) error {
	now := time.Now()

	if !notBefore.IsZero() && now.Add(v.maxClockSkew).Before(notBefore) {
		return fmt.Errorf("assertion is not yet valid (NotBefore: %s, Now: %s)", notBefore, now)
	}

	if !notOnOrAfter.IsZero() && now.Add(-v.maxClockSkew).After(notOnOrAfter) {
		return fmt.Errorf("assertion has expired (NotOnOrAfter: %s, Now: %s)", notOnOrAfter, now)
	}

	return nil
}

// CheckReplay detects if an assertion ID has been seen before.
// Returns an error if the assertion is a replay.
func (v *Validator) CheckReplay(assertionID string, expiry time.Time) error {
	v.replayMu.Lock()
	defer v.replayMu.Unlock()

	if _, exists := v.replayCache[assertionID]; exists {
		v.logger.Warn("replay attack detected",
			zap.String("assertion_id", assertionID),
		)
		return fmt.Errorf("assertion ID %q has already been used", assertionID)
	}

	v.replayCache[assertionID] = expiry
	return nil
}

// VerifyCertificateSignature verifies that the signing certificate is trusted.
func (v *Validator) VerifyCertificateSignature(signingCert *x509.Certificate) error {
	if signingCert == nil {
		return fmt.Errorf("signing certificate is nil")
	}

	for _, trusted := range v.trustedCerts {
		if signingCert.Equal(trusted) {
			return nil
		}

		if err := signingCert.CheckSignatureFrom(trusted); err == nil {
			return nil
		}
	}

	return fmt.Errorf("signing certificate is not trusted")
}

// GetTrustedPublicKeys returns all trusted RSA public keys for signature verification.
func (v *Validator) GetTrustedPublicKeys() []*rsa.PublicKey {
	var keys []*rsa.PublicKey
	for _, cert := range v.trustedCerts {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keys = append(keys, rsaKey)
		}
	}
	return keys
}

// cleanupReplayCache periodically removes expired entries from the replay cache.
func (v *Validator) cleanupReplayCache() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		v.replayMu.Lock()
		now := time.Now()
		for id, expiry := range v.replayCache {
			if now.After(expiry) {
				delete(v.replayCache, id)
			}
		}
		v.replayMu.Unlock()
	}
}

// loadCertificate reads and parses an X.509 certificate from a PEM file.
func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, nil
}
