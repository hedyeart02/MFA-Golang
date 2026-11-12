package mfa

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hidayat-SE/samlguard/internal/config"
	"go.uber.org/zap"
)

const maxSMSResponseBytes = 1024 * 1024 // 1 MB cap for gateway HTTP responses

// SMSSender dispatches OTP and test SMS messages across configured gateway providers
// ("twilio", "isms", "sendquick", "smseagle", "multitech", "teltonika", "vonage", "custom").
type SMSSender struct {
	cfg        config.SMSConfig
	env        string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewSMSSender creates an SMSSender configured with TLS 1.2+ HTTP transport.
func NewSMSSender(cfg config.SMSConfig, env string, logger *zap.Logger) *SMSSender {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &SMSSender{
		cfg:        cfg,
		env:        strings.ToLower(strings.TrimSpace(env)),
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
		logger:     logger,
	}
}

// SetHTTPClient overrides the HTTP client (primarily for unit tests).
func (s *SMSSender) SetHTTPClient(client *http.Client) {
	if s != nil && client != nil {
		s.httpClient = client
	}
}

// Send dispatches an OTP SMS to recipient using the active SMS gateway provider.
func (s *SMSSender) Send(ctx context.Context, recipient, code string) error {
	if s == nil {
		return errors.New("SMS sender is not configured")
	}
	target := NormalizePhoneNumber(recipient)
	if target == "" {
		return errors.New("recipient mobile number is required")
	}

	provider := s.cfg.EffectiveProvider()
	message := s.formatOTPMessage(code)

	if s.logger != nil {
		s.logger.Info("dispatching MFA SMS OTP",
			zap.String("provider", provider),
			zap.String("recipient", MaskPhone(target)),
		)
	}

	if s.shouldSimulateLocal() {
		fmt.Printf("\n💬 [SIMULATED SMS OTP] Provider: %s | To: %s | Verification Code: %s\n\n", provider, target, code)
		if s.logger != nil {
			s.logger.Warn("using simulated local SMS OTP output for development testing",
				zap.String("provider", provider),
				zap.String("recipient", MaskPhone(target)),
			)
		}
		return nil
	}

	return s.dispatchByProvider(ctx, provider, target, code, message)
}

// SendTestSMS verifies SMS gateway connectivity and credentials by sending a diagnostic message.
func (s *SMSSender) SendTestSMS(ctx context.Context, recipient string) error {
	if s == nil {
		return errors.New("SMS sender is not configured")
	}
	target := NormalizePhoneNumber(recipient)
	if target == "" {
		return errors.New("recipient mobile number is required")
	}

	provider := s.cfg.EffectiveProvider()
	if s.shouldSimulateLocal() {
		fmt.Printf("\n💬 [SIMULATED TEST SMS] Provider: %s | To: %s | Test message succeeded!\n\n", provider, target)
		return nil
	}

	return s.dispatchByProvider(ctx, provider, target, "000000", "SAMLGuard SMS Gateway Test: Your SMS delivery integration is working.")
}

func (s *SMSSender) shouldSimulateLocal() bool {
	if s.env == "production" || s.env == "prod" {
		return false
	}
	rawURL := strings.TrimSpace(strings.ToLower(s.cfg.APIURL))
	if strings.HasPrefix(rawURL, "mock://") {
		return true
	}
	if strings.Contains(rawURL, "://localhost") || strings.Contains(rawURL, "://127.0.0.1") {
		return true
	}
	// If no real endpoint or credentials are configured in non-production mode, fall back to safe local log simulation.
	if rawURL == "" && strings.TrimSpace(s.cfg.AccountID) == "" && strings.TrimSpace(s.cfg.AuthToken) == "" {
		return true
	}
	return false
}

func (s *SMSSender) formatOTPMessage(code string) string {
	tmpl := strings.TrimSpace(s.cfg.MessageTemplate)
	if tmpl == "" {
		return fmt.Sprintf("Your SAMLGuard verification code is: %s", code)
	}
	if strings.Contains(tmpl, "{{code}}") {
		return strings.ReplaceAll(tmpl, "{{code}}", code)
	}
	if strings.Contains(tmpl, "{code}") {
		return strings.ReplaceAll(tmpl, "{code}", code)
	}
	return fmt.Sprintf("%s %s", tmpl, code)
}

func (s *SMSSender) dispatchByProvider(ctx context.Context, provider, recipient, code, message string) error {
	switch provider {
	case "twilio":
		return s.sendTwilio(ctx, recipient, message)
	case "isms":
		return s.sendISMS(ctx, recipient, message)
	case "sendquick":
		return s.sendSendQuick(ctx, recipient, message)
	case "smseagle":
		return s.sendSMSEagle(ctx, recipient, message)
	case "multitech":
		return s.sendMultiTech(ctx, recipient, message)
	case "teltonika":
		return s.sendTeltonika(ctx, recipient, message)
	case "vonage":
		return s.sendVonage(ctx, recipient, message)
	case "custom":
		return s.sendCustomHTTP(ctx, recipient, code, message)
	default:
		return fmt.Errorf("unsupported SMS gateway provider %q", provider)
	}
}

func (s *SMSSender) sendTwilio(ctx context.Context, recipient, message string) error {
	accountSID := strings.TrimSpace(s.cfg.AccountID)
	authToken := strings.TrimSpace(s.cfg.AuthToken)
	sender := strings.TrimSpace(s.cfg.SenderID)
	if accountSID == "" || authToken == "" {
		return errors.New("twilio Account SID and Auth Token are required")
	}
	if sender == "" {
		return errors.New("twilio From Phone Number or Messaging Service SID is required")
	}

	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", url.PathEscape(accountSID))
	} else if strings.Contains(endpoint, "{account_id}") {
		endpoint = strings.ReplaceAll(endpoint, "{account_id}", url.PathEscape(accountSID))
	}

	form := url.Values{}
	form.Set("To", recipient)
	form.Set("Body", message)
	if strings.HasPrefix(sender, "MG") {
		form.Set("MessagingServiceSid", sender)
	} else {
		form.Set("From", sender)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("building Twilio request: %w", err)
	}
	req.SetBasicAuth(accountSID, authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	status, body, err := s.doRequest(req)
	if err != nil {
		return fmt.Errorf("twilio delivery failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("twilio returned HTTP %d: %s", status, truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) dispatchFormGateway(
	ctx context.Context,
	providerLabel, endpoint string,
	params url.Values,
	basicUser, basicPass string,
	headers map[string]string,
) (int, []byte, error) {
	method := strings.ToUpper(strings.TrimSpace(s.cfg.HTTPMethod))
	var req *http.Request
	var err error
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint+sep+params.Encode(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return 0, nil, fmt.Errorf("building %s request: %w", providerLabel, err)
	}
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	status, body, err := s.doRequest(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s delivery failed: %w", providerLabel, err)
	}
	if status < 200 || status >= 300 {
		return status, body, fmt.Errorf("%s returned HTTP %d: %s", providerLabel, status, truncateSMSBody(body))
	}
	return status, body, nil
}

func (s *SMSSender) sendISMS(ctx context.Context, recipient, message string) error {
	username := strings.TrimSpace(s.cfg.AccountID)
	password := strings.TrimSpace(s.cfg.AuthToken)
	if username == "" || password == "" {
		return errors.New("iSMS API Username and Password are required")
	}

	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		endpoint = "https://www.isms.com.my/isms_send_all_id.php"
	}

	params := url.Values{}
	params.Set("un", username)
	params.Set("pwd", password)
	params.Set("dstno", strings.TrimPrefix(recipient, "+"))
	params.Set("msg", message)
	params.Set("type", "1")
	params.Set("agreedterm", "YES")
	if sender := strings.TrimSpace(s.cfg.SenderID); sender != "" {
		params.Set("sendid", sender)
	}

	_, body, err := s.dispatchFormGateway(ctx, "iSMS", endpoint, params, "", "", nil)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "-") || strings.Contains(strings.ToUpper(trimmed), "FAILED") {
		return fmt.Errorf("iSMS rejected message: %s", truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) sendSendQuick(ctx context.Context, recipient, message string) error {
	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		return errors.New("SendQuick API endpoint URL is required (e.g. https://sendquick.company.com/cmd/system/api/sendmsg)")
	}
	username := strings.TrimSpace(s.cfg.AccountID)
	passwd := strings.TrimSpace(s.cfg.AuthToken)
	if username == "" || passwd == "" {
		return errors.New("SendQuick username and password/API token are required")
	}

	params := url.Values{}
	params.Set("username", username)
	params.Set("passwd", passwd)
	params.Set("tar_num", recipient)
	params.Set("tar_msg", message)
	params.Set("tar_mode", "text")
	if sender := strings.TrimSpace(s.cfg.SenderID); sender != "" {
		params.Set("tar_sender", sender)
	}

	_, body, err := s.dispatchFormGateway(ctx, "SendQuick", endpoint, params, username, passwd, nil)
	if err != nil {
		return err
	}
	upper := strings.ToUpper(strings.TrimSpace(string(body)))
	if strings.HasPrefix(upper, "ERR") || strings.Contains(upper, "INVALID USER") || strings.Contains(upper, "FAILED") {
		return fmt.Errorf("SendQuick gateway error: %s", truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) sendSMSEagle(ctx context.Context, recipient, message string) error {
	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		return errors.New("SMSEagle API endpoint URL is required (e.g. https://smseagle.company.local/index.php/http_api/send_sms)")
	}
	login := strings.TrimSpace(s.cfg.AccountID)
	pass := strings.TrimSpace(s.cfg.AuthToken)
	if pass == "" {
		return errors.New("SMSEagle API password or access token is required")
	}

	params := url.Values{}
	params.Set("to", recipient)
	params.Set("message", message)
	var headers map[string]string
	if login != "" && !strings.EqualFold(login, "token") {
		params.Set("login", login)
		params.Set("pass", pass)
	} else {
		params.Set("access_token", pass)
		headers = map[string]string{"access-token": pass}
	}

	_, body, err := s.dispatchFormGateway(ctx, "SMSEagle", endpoint, params, "", "", headers)
	if err != nil {
		return err
	}
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	if strings.HasPrefix(lower, "err") || strings.Contains(lower, "invalid login") || strings.Contains(lower, "invalid access token") {
		return fmt.Errorf("SMSEagle gateway error: %s", truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) sendMultiTech(ctx context.Context, recipient, message string) error {
	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		return errors.New("MultiTech iSMS endpoint URL is required (e.g. https://multitech.company.local/sendmsg)")
	}
	user := strings.TrimSpace(s.cfg.AccountID)
	passwd := strings.TrimSpace(s.cfg.AuthToken)
	if user == "" || passwd == "" {
		return errors.New("MultiTech iSMS username and password are required")
	}

	params := url.Values{}
	params.Set("user", user)
	params.Set("passwd", passwd)
	params.Set("cat", "1")
	params.Set("enc", "0")
	params.Set("to", recipient)
	params.Set("text", message)

	_, body, err := s.dispatchFormGateway(ctx, "MultiTech", endpoint, params, user, passwd, nil)
	if err != nil {
		return err
	}
	upper := strings.ToUpper(strings.TrimSpace(string(body)))
	if strings.HasPrefix(upper, "ERR") || strings.Contains(upper, "FAILED") {
		return fmt.Errorf("MultiTech gateway error: %s", truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) sendTeltonika(ctx context.Context, recipient, message string) error {
	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		return errors.New("Teltonika gateway URL is required (e.g. https://teltonika.company.local/cgi-bin/sms_send)")
	}
	username := strings.TrimSpace(s.cfg.AccountID)
	password := strings.TrimSpace(s.cfg.AuthToken)
	if username == "" || password == "" {
		return errors.New("Teltonika username and password are required")
	}

	params := url.Values{}
	params.Set("username", username)
	params.Set("password", password)
	params.Set("number", recipient)
	params.Set("text", message)

	_, body, err := s.dispatchFormGateway(ctx, "Teltonika", endpoint, params, "", "", nil)
	if err != nil {
		return err
	}
	upper := strings.ToUpper(strings.TrimSpace(string(body)))
	if strings.HasPrefix(upper, "ERR") || strings.Contains(upper, "INVALID") || strings.Contains(upper, "FAILED") {
		return fmt.Errorf("Teltonika gateway error: %s", truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) sendVonage(ctx context.Context, recipient, message string) error {
	apiKey := strings.TrimSpace(s.cfg.AccountID)
	apiSecret := strings.TrimSpace(s.cfg.AuthToken)
	sender := strings.TrimSpace(s.cfg.SenderID)
	if apiKey == "" || apiSecret == "" {
		return errors.New("Vonage API Key and API Secret are required")
	}
	if sender == "" {
		sender = "SAMLGuard"
	}

	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		endpoint = "https://rest.nexmo.com/sms/json"
	}

	payload := map[string]string{
		"api_key":    apiKey,
		"api_secret": apiSecret,
		"from":       sender,
		"to":         strings.TrimPrefix(recipient, "+"),
		"text":       message,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("building Vonage request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	status, body, err := s.doRequest(req)
	if err != nil {
		return fmt.Errorf("Vonage delivery failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Vonage returned HTTP %d: %s", status, truncateSMSBody(body))
	}

	var parsed struct {
		Messages []struct {
			Status    string `json:"status"`
			ErrorText string `json:"error-text"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Messages) > 0 {
		if parsed.Messages[0].Status != "" && parsed.Messages[0].Status != "0" {
			return fmt.Errorf("Vonage gateway error (status %s): %s", parsed.Messages[0].Status, parsed.Messages[0].ErrorText)
		}
	}
	return nil
}

func (s *SMSSender) sendCustomHTTP(ctx context.Context, recipient, code, message string) error {
	endpoint := strings.TrimSpace(s.cfg.APIURL)
	if endpoint == "" {
		return errors.New("Custom SMS Gateway API URL is required")
	}

	method := strings.ToUpper(strings.TrimSpace(s.cfg.HTTPMethod))
	if method == "" {
		method = http.MethodPost
	}

	var req *http.Request
	var err error
	if method == http.MethodGet {
		params := url.Values{}
		params.Set("to", recipient)
		params.Set("message", message)
		params.Set("code", code)
		if sender := strings.TrimSpace(s.cfg.SenderID); sender != "" {
			params.Set("from", sender)
		}
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint+sep+params.Encode(), nil)
	} else {
		payload := map[string]string{
			"to":      recipient,
			"from":    strings.TrimSpace(s.cfg.SenderID),
			"message": message,
			"code":    code,
		}
		raw, mErr := json.Marshal(payload)
		if mErr != nil {
			return mErr
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
		}
	}
	if err != nil {
		return fmt.Errorf("building custom SMS request: %w", err)
	}

	accountID := strings.TrimSpace(s.cfg.AccountID)
	authToken := strings.TrimSpace(s.cfg.AuthToken)
	if authToken != "" {
		if accountID == "" || strings.EqualFold(accountID, "bearer") {
			req.Header.Set("Authorization", "Bearer "+authToken)
		} else {
			req.SetBasicAuth(accountID, authToken)
		}
	}

	status, body, err := s.doRequest(req)
	if err != nil {
		return fmt.Errorf("custom SMS gateway failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("custom SMS gateway returned HTTP %d: %s", status, truncateSMSBody(body))
	}
	return nil
}

func (s *SMSSender) doRequest(req *http.Request) (int, []byte, error) {
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSMSResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func truncateSMSBody(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 220 {
		return trimmed[:220] + "..."
	}
	return trimmed
}

// NormalizePhoneNumber strips formatting spaces, dashes, and parentheses while preserving a leading '+'.
func NormalizePhoneNumber(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	for i, r := range trimmed {
		if r == '+' && i == 0 {
			sb.WriteRune(r)
		} else if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// MaskPhone masks middle digits of a phone number for safe UI display (e.g. "+60123456789" -> "+60*****6789").
func MaskPhone(phone string) string {
	norm := NormalizePhoneNumber(phone)
	if norm == "" {
		return "***"
	}
	if len(norm) <= 4 {
		return "****"
	}
	prefixLen := 3
	if !strings.HasPrefix(norm, "+") {
		prefixLen = 2
	}
	if len(norm) <= prefixLen+4 {
		return norm[:1] + "***" + norm[len(norm)-2:]
	}
	return norm[:prefixLen] + strings.Repeat("*", len(norm)-prefixLen-4) + norm[len(norm)-4:]
}
