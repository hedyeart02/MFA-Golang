package ita

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestParseITAUsersJSON_Array(t *testing.T) {
	rawJSON := `[
		{
			"username": "apc",
			"email": "apc@schneider.com",
			"fullName": "Administrator"
		},
		{
			"userName": "itaadmin",
			"emailAddress": "itaadmin@samlguard.local",
			"displayName": "ITA Admin"
		}
	]`

	users, err := ParseITAUsersJSON([]byte(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	if users[0].Username != "apc" || users[0].Email != "apc@schneider.com" {
		t.Errorf("unexpected user 0: %+v", users[0])
	}
	if users[1].Username != "itaadmin" || users[1].Email != "itaadmin@samlguard.local" {
		t.Errorf("unexpected user 1: %+v", users[1])
	}
}

func TestParseITAUsersJSON_ObjectWithData(t *testing.T) {
	rawJSON := `{
		"data": [
			{
				"id": "operator1",
				"email": "operator1@company.com",
				"name": "Operator One"
			}
		]
	}`

	users, err := ParseITAUsersJSON([]byte(rawJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "operator1" {
		t.Errorf("expected operator1, got %s", users[0].Username)
	}
}

func TestFetchUsers_MockTransport(t *testing.T) {
	mockClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) *http.Response {
			if r.URL.Path == "/api/current/users" {
				auth := r.Header.Get("Authorization")
				if auth == "" {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
						Header:     make(http.Header),
					}
				}
				jsonResp := `[{"username": "apc", "email": "apc@company.com", "fullName": "Admin"}]`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(jsonResp)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "not found"}`)),
				Header:     make(http.Header),
			}
		}),
	}

	client := &Client{httpClient: mockClient}
	users, err := client.FetchUsers(context.Background(), "https://ita.example.com/api/current", "apc", "password123")
	if err != nil {
		t.Fatalf("FetchUsers failed: %v", err)
	}
	if len(users) != 1 || users[0].Username != "apc" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 4), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, errors.New("listener closed")
	default:
	}
	cConn, sConn := net.Pipe()
	select {
	case l.conns <- sConn:
		return cConn, nil
	case <-l.closed:
		_ = cConn.Close()
		_ = sConn.Close()
		return nil, errors.New("listener closed")
	case <-ctx.Done():
		_ = cConn.Close()
		_ = sConn.Close()
		return nil, ctx.Err()
	}
}

func TestClient_Phase3_TLSAndLimits(t *testing.T) {
	// Generate a self-signed certificate for ita.example.com
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ita.example.com"},
		DNSNames:     []string{"ita.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}

	ln := newPipeListener()
	defer ln.Close()

	srvTLS := tls.NewListener(ln, &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  privKey,
		}},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"username":"apc","email":"apc@company.com","fullName":"Admin"}]`))
		}),
	}
	go func() { _ = srv.Serve(srvTLS) }()
	defer srv.Close()

	// Default client enforces TLS 1.2+ with InsecureSkipVerify=false and rejects untrusted cert
	defaultClient := NewClient(5 * time.Second)
	defaultTr := defaultClient.httpClient.Transport.(*http.Transport)
	if defaultTr.TLSClientConfig == nil || defaultTr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected default NewClient to have InsecureSkipVerify=false")
	}
	if defaultTr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("expected default NewClient to require TLS 1.2 or higher")
	}
	defaultTr.DialContext = ln.dial

	if _, err := defaultClient.FetchUsers(context.Background(), "https://ita.example.com/api/current", "apc", "pass"); err == nil {
		t.Fatal("expected default NewClient to reject untrusted self-signed HTTPS certificate")
	}

	// Pinning the server certificate via ClientOptions.CAFile succeeds over real TLS handshake
	caPath := filepath.Join(t.TempDir(), "ita-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA pem: %v", err)
	}
	pinnedClient, err := NewClientWithOptions(ClientOptions{
		Timeout: 5 * time.Second,
		CAFile:  caPath,
	})
	if err != nil {
		t.Fatalf("NewClientWithOptions failed: %v", err)
	}
	pinnedClient.httpClient.Transport.(*http.Transport).DialContext = ln.dial

	users, err := pinnedClient.FetchUsers(context.Background(), "https://ita.example.com/api/current", "apc", "pass")
	if err != nil {
		t.Fatalf("expected pinned CA client to succeed, got: %v", err)
	}
	if len(users) != 1 || users[0].Username != "apc" {
		t.Fatalf("unexpected users returned: %+v", users)
	}

	// Unsupported scheme is rejected
	if _, err := pinnedClient.FetchUsers(context.Background(), "file:///etc/passwd", "apc", "pass"); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected URL scheme rejection for file://, got: %v", err)
	}

	// Oversized response (>10 MB) is rejected cleanly
	oversizedBody := bytes.Repeat([]byte("a"), maxITAResponseBytes+10)
	oversizedClient := &Client{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(oversizedBody)),
					Header:     make(http.Header),
				}
			}),
		},
	}
	if _, err := oversizedClient.FetchUsers(context.Background(), "https://ita.example.com/api/current", "apc", "pass"); err == nil || !strings.Contains(err.Error(), "maximum allowed size") {
		t.Fatalf("expected maximum allowed size error, got: %v", err)
	}
}
