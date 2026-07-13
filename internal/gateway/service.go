package gateway

import (
	"context"

	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/internal/audit"
	"github.com/hidayat-SE/samlguard/internal/auth"
	intmfa "github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/internal/session"
	"github.com/hidayat-SE/samlguard/pkg/config"
	"github.com/hidayat-SE/samlguard/pkg/saml"
)

// Service orchestrates the Gateway's core authentication flow by coordinating
// calls to the Auth, MFA, Session, and Audit services.
type Service struct {
	authClient    *AuthClient
	mfaClient     *MFAClient
	sessionClient *SessionClient
	auditClient   *AuditClient
	spService     *saml.SPService
	samlCfg       config.SAMLConfig
	servicesCfg   config.ServicesConfig
	logger        *zap.Logger
}

// NewService creates the gateway orchestration service.
func NewService(
	authClient *AuthClient,
	mfaClient *MFAClient,
	sessionClient *SessionClient,
	auditClient *AuditClient,
	spService *saml.SPService,
	samlCfg config.SAMLConfig,
	servicesCfg config.ServicesConfig,
	log *zap.Logger,
) *Service {
	return &Service{
		authClient:    authClient,
		mfaClient:     mfaClient,
		sessionClient: sessionClient,
		auditClient:   auditClient,
		spService:     spService,
		samlCfg:       samlCfg,
		servicesCfg:   servicesCfg,
		logger:        log,
	}
}

// InitiateLogin builds the SAML AuthnRequest URL and redirects to the upstream IdP.
func (s *Service) InitiateLogin(relayState string) (string, error) {
	redirectURL, err := s.spService.BuildAuthnRequestURL(relayState)
	if err != nil {
		return "", err
	}

	s.logger.Info("login initiated",
		zap.String("relay_state", relayState),
	)

	return redirectURL, nil
}

// ValidateSAMLResponse calls the Auth service to validate the SAML response.
func (s *Service) ValidateSAMLResponse(ctx context.Context, samlResponse, relayState string) (*auth.ValidateResponse, error) {
	req := auth.ValidateRequest{
		SAMLResponse: samlResponse,
		RelayState:   relayState,
	}

	var resp auth.ValidateResponse
	if err := s.authClient.client.Post(ctx, "/api/v1/validate", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// RequestMFAChallenge calls the MFA service to send a challenge.
func (s *Service) RequestMFAChallenge(ctx context.Context, userID, method, deviceFP string) (*intmfa.ChallengeResponse, error) {
	req := intmfa.ChallengeRequest{
		UserID:            userID,
		Method:            method,
		DeviceFingerprint: deviceFP,
	}

	var resp intmfa.ChallengeResponse
	if err := s.mfaClient.client.Post(ctx, "/api/v1/request", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// VerifyMFA calls the MFA service to verify a code.
func (s *Service) VerifyMFA(ctx context.Context, req intmfa.VerifyRequest) (*intmfa.VerifyResponse, error) {
	var resp intmfa.VerifyResponse
	if err := s.mfaClient.client.Post(ctx, "/api/v1/verify", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// CreateSession calls the Session service to create a new session.
func (s *Service) CreateSession(ctx context.Context, req session.CreateSessionRequest) (*session.CreateSessionResponse, error) {
	var resp session.CreateSessionResponse
	if err := s.sessionClient.client.Post(ctx, "/api/v1/session", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GenerateAssertion calls the Auth service to generate a new signed SAML assertion.
func (s *Service) GenerateAssertion(ctx context.Context, req auth.GenerateAssertionRequest) (*auth.GenerateAssertionResponse, error) {
	var resp auth.GenerateAssertionResponse
	if err := s.authClient.client.Post(ctx, "/api/v1/assertion", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// LogAuditEvent calls the Audit service to log an event.
func (s *Service) LogAuditEvent(ctx context.Context, req audit.LogEventRequest) {
	if err := s.auditClient.client.Post(ctx, "/api/v1/logs", req, nil); err != nil {
		s.logger.Warn("failed to log audit event",
			zap.String("event_type", req.EventType),
			zap.Error(err),
		)
	}
}
