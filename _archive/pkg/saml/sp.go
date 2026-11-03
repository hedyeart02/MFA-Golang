package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/config"
)

// SPService manages the SAML Service Provider role of the proxy gateway.
// It handles AuthnRequest generation and SAML Response reception from
// the upstream Identity Provider.
type SPService struct {
	entityID    string
	acsURL      string
	ssoURL      string
	metadataURL string
	certFile    string
	keyFile     string
	idpConfig   config.SAMLConfig
	logger      *zap.Logger
}

// NewSPService creates a new SAML SP service.
func NewSPService(cfg config.SAMLConfig, log *zap.Logger) (*SPService, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("SAML entity_id is required")
	}
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("SAML acs_url is required")
	}

	return &SPService{
		entityID:    cfg.EntityID,
		acsURL:      cfg.ACSURL,
		ssoURL:      cfg.SSOURL,
		metadataURL: cfg.MetadataURL,
		certFile:    cfg.CertFile,
		keyFile:     cfg.KeyFile,
		idpConfig:   cfg,
		logger:      log,
	}, nil
}

// BuildAuthnRequestURL constructs a SAML AuthnRequest URL for HTTP-Redirect binding.
func (s *SPService) BuildAuthnRequestURL(relayState string) (string, error) {
	if s.idpConfig.IdPSSOURL == "" {
		return "", fmt.Errorf("IdP SSO URL is not configured")
	}

	requestID := "_" + uuid.New().String()
	now := time.Now().UTC().Format(timeFormat)

	authnRequestXML := fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" `+
			`ID="%s" Version="2.0" IssueInstant="%s" `+
			`AssertionConsumerServiceURL="%s" `+
			`Destination="%s" `+
			`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`+
			`<saml:Issuer>%s</saml:Issuer>`+
			`<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>`+
			`</samlp:AuthnRequest>`,
		samlpNS, samlNS, requestID, now,
		s.acsURL, s.idpConfig.IdPSSOURL, s.entityID, nameIDEmail,
	)

	encoded, err := deflateAndEncode(authnRequestXML)
	if err != nil {
		return "", fmt.Errorf("encoding AuthnRequest: %w", err)
	}

	params := url.Values{}
	params.Set("SAMLRequest", encoded)
	if relayState != "" {
		params.Set("RelayState", relayState)
	}

	redirectURL := fmt.Sprintf("%s?%s", s.idpConfig.IdPSSOURL, params.Encode())

	s.logger.Info("built AuthnRequest redirect",
		zap.String("request_id", requestID),
		zap.String("idp_sso_url", s.idpConfig.IdPSSOURL),
	)

	return redirectURL, nil
}

// EntityID returns the SP entity ID.
func (s *SPService) EntityID() string {
	return s.entityID
}

// ACSURL returns the Assertion Consumer Service URL.
func (s *SPService) ACSURL() string {
	return s.acsURL
}

// deflateAndEncode compresses XML using DEFLATE and base64-encodes for HTTP-Redirect.
func deflateAndEncode(xmlContent string) (string, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("creating flate writer: %w", err)
	}

	if _, err := writer.Write([]byte(xmlContent)); err != nil {
		return "", fmt.Errorf("compressing XML: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("closing flate writer: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
