package ita

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hidayat-SE/samlguard/internal/mfa"
)

const maxITAResponseBytes = 10 * 1024 * 1024 // 10 MB safety limit

// ClientOptions configures TLS verification and timeout behavior for the ITA REST API client.
type ClientOptions struct {
	Timeout            time.Duration
	CAFile             string
	InsecureSkipVerify bool
}

// Client interacts with Schneider Electric EcoStruxure IT Advisor (ITA) REST API.
type Client struct {
	httpClient *http.Client
}

// NewClient creates a hardened ITA API client with TLS 1.2+ certificate verification enabled by default.
func NewClient(timeout time.Duration) *Client {
	client, _ := NewClientWithOptions(ClientOptions{Timeout: timeout})
	return client
}

// NewClientWithOptions creates an ITA API client configured with explicit timeout and optional pinned CA file.
func NewClientWithOptions(opts ClientOptions) (*Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}

	if caPath := strings.TrimSpace(opts.CAFile); caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("reading ITA CA certificate %q: %w", caPath, err)
		}
		pool, poolErr := x509.SystemCertPool()
		if poolErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("parsing ITA CA certificate PEM %q failed", caPath)
		}
		tlsCfg.RootCAs = pool
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	return &Client{
		httpClient: &http.Client{
			Transport: tr,
			Jar:       jar,
			Timeout:   timeout,
		},
	}, nil
}

// FetchUsers connects to ITA REST API, authenticates, and retrieves the current list of authorized users.
func (c *Client) FetchUsers(ctx context.Context, apiURL, username, password string) ([]mfa.AuthorizedUser, error) {
	cleanURL := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if cleanURL == "" {
		return nil, errors.New("ITA API URL is required")
	}
	parsedURL, parseErr := url.Parse(cleanURL)
	if parseErr != nil || parsedURL.Host == "" {
		return nil, errors.New("ITA API URL must be a valid URL with scheme and host")
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("unsupported ITA API URL scheme %q (expected http or https)", parsedURL.Scheme)
	}
	if username == "" {
		return nil, errors.New("ITA API username is required")
	}

	// 1. First attempt: Direct GET with HTTP Basic Auth on /users
	usersEndpoint := cleanURL + "/users"
	users, err := c.getUsersDirect(ctx, usersEndpoint, username, password)
	if err == nil && len(users) > 0 {
		return users, nil
	}

	// 2. Second attempt: Authenticate via POST /authentication/login, then GET /users
	loginErr := c.loginSession(ctx, cleanURL, username, password)
	if loginErr == nil {
		users, err = c.getUsersDirect(ctx, usersEndpoint, "", "")
		if err == nil && len(users) > 0 {
			return users, nil
		}
	}

	// 3. Third attempt: try alternate endpoint /administration/users
	altEndpoint := cleanURL + "/administration/users"
	users, altErr := c.getUsersDirect(ctx, altEndpoint, username, password)
	if altErr == nil && len(users) > 0 {
		return users, nil
	}

	if err != nil {
		return nil, fmt.Errorf("fetching ITA users from %s: %w", usersEndpoint, err)
	}
	return nil, fmt.Errorf("no users returned from ITA API at %s", usersEndpoint)
}

func (c *Client) getUsersDirect(ctx context.Context, endpoint, username, password string) ([]mfa.AuthorizedUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if username != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP %d: authentication failed, check ITA credentials", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d received from %s", resp.StatusCode, endpoint)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxITAResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxITAResponseBytes {
		return nil, fmt.Errorf("ITA API response exceeds maximum allowed size (%d bytes)", maxITAResponseBytes)
	}

	return ParseITAUsersJSON(body)
}

func (c *Client) loginSession(ctx context.Context, baseURL, username, password string) error {
	loginURL := baseURL + "/authentication/login"
	loginPayload := map[string]string{
		"username": username,
		"password": password,
	}
	data, _ := json.Marshal(loginPayload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("login failed with HTTP %d", resp.StatusCode)
	}
	return nil
}

// ParseITAUsersJSON parses raw JSON from ITA into a slice of mfa.AuthorizedUser.
func ParseITAUsersJSON(data []byte) ([]mfa.AuthorizedUser, error) {
	// Format 1: Direct JSON Array of user objects
	var arrayUsers []map[string]interface{}
	if err := json.Unmarshal(data, &arrayUsers); err == nil && len(arrayUsers) > 0 {
		return extractUsersFromMaps(arrayUsers), nil
	}

	// Format 2: JSON Object with "users" or "data" array
	var objMap map[string]interface{}
	if err := json.Unmarshal(data, &objMap); err == nil {
		if rawUsers, ok := objMap["users"].([]interface{}); ok {
			return extractUsersFromInterfaces(rawUsers), nil
		}
		if rawUsers, ok := objMap["data"].([]interface{}); ok {
			return extractUsersFromInterfaces(rawUsers), nil
		}
	}

	return nil, errors.New("unrecognized ITA user list JSON structure")
}

func extractUsersFromMaps(maps []map[string]interface{}) []mfa.AuthorizedUser {
	var users []mfa.AuthorizedUser
	for _, m := range maps {
		u := mapToAuthorizedUser(m)
		if u.Username != "" {
			users = append(users, u)
		}
	}
	return users
}

func extractUsersFromInterfaces(rawList []interface{}) []mfa.AuthorizedUser {
	var users []mfa.AuthorizedUser
	for _, item := range rawList {
		if m, ok := item.(map[string]interface{}); ok {
			u := mapToAuthorizedUser(m)
			if u.Username != "" {
				users = append(users, u)
			}
		}
	}
	return users
}

func mapToAuthorizedUser(m map[string]interface{}) mfa.AuthorizedUser {
	var u mfa.AuthorizedUser
	u.Source = "ita_sync"

	// Extract username - prefer specific keys before generic "name"
	for _, key := range []string{"username", "userName", "id", "login", "user", "name"} {
		if val, ok := m[key].(string); ok && strings.TrimSpace(val) != "" {
			u.Username = strings.TrimSpace(val)
			break
		}
	}

	// Extract email
	for _, key := range []string{"email", "mail", "emailAddress", "userEmail"} {
		if val, ok := m[key].(string); ok && strings.TrimSpace(val) != "" {
			u.Email = strings.TrimSpace(val)
			break
		}
	}

	// Extract full name
	for _, key := range []string{"fullName", "full_name", "displayName", "name"} {
		if val, ok := m[key].(string); ok && strings.TrimSpace(val) != "" && val != u.Username {
			u.FullName = strings.TrimSpace(val)
			break
		}
	}

	return u
}
