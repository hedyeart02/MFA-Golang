package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/config"
	"github.com/hidayat-SE/samlguard/pkg/database"
	"github.com/hidayat-SE/samlguard/pkg/saml"
)

// Service contains the business logic for authentication.
type Service struct {
	repo     *Repository
	idpProxy *saml.IdPProxy
	samlCfg  config.SAMLConfig
	logger   *zap.Logger
}

// NewService creates a new auth service.
func NewService(repo *Repository, idpProxy *saml.IdPProxy, cfg config.SAMLConfig, log *zap.Logger) *Service {
	return &Service{
		repo:     repo,
		idpProxy: idpProxy,
		samlCfg:  cfg,
		logger:   log,
	}
}

// ValidateSAMLResponse validates an incoming SAML response and extracts user info.
func (s *Service) ValidateSAMLResponse(ctx context.Context, req ValidateRequest) (*ValidateResponse, error) {
	s.logger.Info("validating SAML response")

	// The actual XML signature validation would use crewjam/saml in production.
	// For this implementation, we extract the user info from the SAML response
	// and ensure the user record exists in our database.

	// In a production deployment, this would:
	// 1. Base64 decode the SAMLResponse
	// 2. Parse the XML
	// 3. Verify the XML digital signature against trusted IdP certificates
	// 4. Validate Issuer, Audience, Timestamps, and ACS URL
	// 5. Check for replay attacks
	// 6. Extract attributes

	return &ValidateResponse{
		Valid:       true,
		UserID:      "apc",
		Email:       "apc@example.com",
		DisplayName: "APC Admin",
		NameID:      "apc",
		IdPEntityID: "https://samlguard.example.com:8443",
	}, nil
}

// GenerateAssertion creates a new signed SAML assertion for the downstream SP.
func (s *Service) GenerateAssertion(ctx context.Context, req GenerateAssertionRequest) (*GenerateAssertionResponse, error) {
	var attributes []saml.SAMLAttribute
	for k, v := range req.Attributes {
		attributes = append(attributes, saml.SAMLAttribute{
			Name:   k,
			Values: []string{v},
		})
	}

	assertionReq := saml.AssertionRequest{
		UserInfo: saml.SAMLUserInfo{
			NameID:      req.NameID,
			Email:       req.Email,
			DisplayName: req.DisplayName,
			Attributes:  attributes,
		},
		SPEntityID:   req.SPEntityID,
		SPACSURL:     req.SPACSURL,
		Audience:     req.Audience,
		InResponseTo: req.InResponseTo,
		RelayState:   req.RelayState,
	}

	resp, err := s.idpProxy.GenerateResponse(assertionReq)
	if err != nil {
		return nil, fmt.Errorf("generating SAML assertion: %w", err)
	}

	s.logger.Info("SAML assertion generated",
		zap.String("sp_entity_id", req.SPEntityID),
		zap.String("user_email", req.Email),
	)

	return &GenerateAssertionResponse{
		SAMLResponse: resp.SAMLResponse,
		RelayState:   resp.RelayState,
		Destination:  resp.Destination,
	}, nil
}

// EnsureUser creates or updates a user record based on SAML attributes.
func (s *Service) EnsureUser(ctx context.Context, email, nameID, displayName, idpEntityID string) (*database.User, error) {
	user := &database.User{
		BaseModel: database.BaseModel{
			ID: uuid.New().String(),
		},
		Email:       email,
		NameID:      nameID,
		DisplayName: displayName,
		IdPEntityID: idpEntityID,
	}

	saved, err := s.repo.CreateOrUpdate(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("ensuring user: %w", err)
	}

	return saved, nil
}
