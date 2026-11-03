package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// ServiceClient provides HTTP communication with downstream services.
type ServiceClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	logger     *zap.Logger
}

// NewServiceClient creates a client for a downstream service.
func NewServiceClient(baseURL, apiKey string, timeout time.Duration, log *zap.Logger) *ServiceClient {
	return &ServiceClient{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    baseURL,
		apiKey:     apiKey,
		logger:     log,
	}
}

// Post sends a POST request to the downstream service.
func (c *ServiceClient) Post(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

// Get sends a GET request to the downstream service.
func (c *ServiceClient) Get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}

// Delete sends a DELETE request to the downstream service.
func (c *ServiceClient) Delete(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, result)
}

func (c *ServiceClient) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	correlationID := logger.CorrelationIDFromContext(ctx)
	if correlationID != "" {
		req.Header.Set("X-Correlation-ID", correlationID)
	}

	requestID := logger.RequestIDFromContext(ctx)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request to %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiResp utils.APIResponse
		if jsonErr := json.Unmarshal(respBody, &apiResp); jsonErr == nil && apiResp.Error != nil {
			return &utils.AppError{
				StatusCode: resp.StatusCode,
				Code:       apiResp.Error.Code,
				Message:    apiResp.Error.Message,
			}
		}
		return fmt.Errorf("service returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		var apiResp utils.APIResponse
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			return fmt.Errorf("unmarshaling API response: %w", err)
		}

		if apiResp.Data != nil {
			dataBytes, err := json.Marshal(apiResp.Data)
			if err != nil {
				return fmt.Errorf("re-marshaling response data: %w", err)
			}
			if err := json.Unmarshal(dataBytes, result); err != nil {
				return fmt.Errorf("unmarshaling response data: %w", err)
			}
		}
	}

	return nil
}

// AuthClient wraps service calls to the Auth service.
type AuthClient struct {
	client *ServiceClient
}

// NewAuthClient creates an auth service client.
func NewAuthClient(baseURL, apiKey string, timeout time.Duration, log *zap.Logger) *AuthClient {
	return &AuthClient{client: NewServiceClient(baseURL, apiKey, timeout, log)}
}

// MFAClient wraps service calls to the MFA service.
type MFAClient struct {
	client *ServiceClient
}

// NewMFAClient creates an MFA service client.
func NewMFAClient(baseURL, apiKey string, timeout time.Duration, log *zap.Logger) *MFAClient {
	return &MFAClient{client: NewServiceClient(baseURL, apiKey, timeout, log)}
}

// SessionClient wraps service calls to the Session service.
type SessionClient struct {
	client *ServiceClient
}

// NewSessionClient creates a session service client.
func NewSessionClient(baseURL, apiKey string, timeout time.Duration, log *zap.Logger) *SessionClient {
	return &SessionClient{client: NewServiceClient(baseURL, apiKey, timeout, log)}
}

// AuditClient wraps service calls to the Audit service.
type AuditClient struct {
	client *ServiceClient
}

// NewAuditClient creates an audit service client.
func NewAuditClient(baseURL, apiKey string, timeout time.Duration, log *zap.Logger) *AuditClient {
	return &AuditClient{client: NewServiceClient(baseURL, apiKey, timeout, log)}
}
