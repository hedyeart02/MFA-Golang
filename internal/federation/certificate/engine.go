package certificate

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// Decoder decodes PEM/DER strings into raw bytes
type Decoder interface {
	Decode(raw string) ([]byte, error)
}

// Parser parses raw bytes into *x509.Certificate
type Parser interface {
	Parse(data []byte) (*x509.Certificate, error)
}

// Normalizer normalizes x509 cert to CertificateDescriptor
type Normalizer interface {
	Normalize(cert *x509.Certificate, use string, rawPEM string) (*model.CertificateDescriptor, error)
}

// FingerprintGenerator computes SHA1 and SHA256 hashes
type FingerprintGenerator interface {
	Generate(cert *x509.Certificate, desc *model.CertificateDescriptor) error
}

// ExpiryValidator validates notBefore/notAfter
type ExpiryValidator interface {
	Validate(cert *x509.Certificate) error
}

// TrustValidator evaluates the trust chain or pinned status
type TrustValidator interface {
	Validate(cert *x509.Certificate, desc *model.CertificateDescriptor) error
}

type DefaultDecoder struct{}

func (d *DefaultDecoder) Decode(raw string) ([]byte, error) {
	// Attempt Base64 decode first (common in XML metadata where it's just raw base64 data)
	data, err := base64.StdEncoding.DecodeString(raw)
	if err == nil {
		return data, nil
	}

	// If it fails, maybe it's full PEM format
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("failed to decode certificate data (invalid base64/pem)")
	}
	return block.Bytes, nil
}

type DefaultParser struct{}

func (p *DefaultParser) Parse(data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(data)
}

type DefaultNormalizer struct{}

func (n *DefaultNormalizer) Normalize(cert *x509.Certificate, use string, rawPEM string) (*model.CertificateDescriptor, error) {
	return &model.CertificateDescriptor{
		Use:       use,
		RawPEM:    rawPEM,
		Subject:   cert.Subject.CommonName, // Simplified, can expand later
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

type DefaultFingerprintGenerator struct{}

func (g *DefaultFingerprintGenerator) Generate(cert *x509.Certificate, desc *model.CertificateDescriptor) error {
	s1 := sha1.Sum(cert.Raw)
	s256 := sha256.Sum256(cert.Raw)

	desc.SHA1Fingerprint = hex.EncodeToString(s1[:])
	desc.SHA256Fingerprint = hex.EncodeToString(s256[:])
	return nil
}

type DefaultExpiryValidator struct{}

func (v *DefaultExpiryValidator) Validate(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("certificate is expired or not yet valid")
	}
	return nil
}

type DefaultTrustValidator struct{}

func (v *DefaultTrustValidator) Validate(cert *x509.Certificate, desc *model.CertificateDescriptor) error {
	// Stub for milestone 7: We set TRUSTED blindly here, but in a real implementation
	// we would verify against root CAs or pinned certificates.
	desc.Trust = model.TrustStatusTrusted
	return nil
}

// Engine orchestrates the certificate processing pipeline
type Engine struct {
	Decoder              Decoder
	Parser               Parser
	Normalizer           Normalizer
	FingerprintGenerator FingerprintGenerator
	ExpiryValidator      ExpiryValidator
	TrustValidator       TrustValidator
}

// Process passes raw base64/pem data through the certificate pipeline
func (e *Engine) Process(raw string, use string) (*model.CertificateDescriptor, error) {
	data, err := e.Decoder.Decode(raw)
	if err != nil {
		return nil, err
	}

	cert, err := e.Parser.Parse(data)
	if err != nil {
		return nil, err
	}

	if err := e.ExpiryValidator.Validate(cert); err != nil {
		return nil, err
	}

	desc, err := e.Normalizer.Normalize(cert, use, raw)
	if err != nil {
		return nil, err
	}

	if err := e.FingerprintGenerator.Generate(cert, desc); err != nil {
		return nil, err
	}

	if err := e.TrustValidator.Validate(cert, desc); err != nil {
		return nil, err
	}

	return desc, nil
}
