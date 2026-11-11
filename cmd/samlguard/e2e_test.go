package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

func encodeSAMLRequest(xmlReq string) (string, error) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write([]byte(xmlReq)); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func computeTOTP(secretBase32 string, timestep int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secretBase32))
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timestep))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	binaryCode := ((int(h[offset]) & 0x7f) << 24) |
		((int(h[offset+1]) & 0xff) << 16) |
		((int(h[offset+2]) & 0xff) << 8) |
		(int(h[offset+3]) & 0xff)

	otpCode := binaryCode % 1000000
	return fmt.Sprintf("%06d", otpCode), nil
}

func generateRogueCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject: pkix.Name{
			CommonName: "Rogue Attacker IdP",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func TestE2E_FullFlow_DummyOTP(t *testing.T) {
	cfg := testConfig(t)
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to setup app: %v", err)
	}

	// 1. ITA sends inbound AuthnRequest to /saml/sso
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_dummy_9999"
                    Version="2.0"
                    IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
    <saml:Issuer>https://ita.example.com</saml:Issuer>
</samlp:AuthnRequest>`

	encodedReq, err := encodeSAMLRequest(rawReqXML)
	if err != nil {
		t.Fatalf("failed to encode saml request: %v", err)
	}

	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=ita-relay-dummy", nil)
	app.ServeHTTP(wSSO, reqSSO)

	if wSSO.Code != http.StatusOK {
		t.Fatalf("expected 200 from /saml/sso, got %d (body: %s)", wSSO.Code, wSSO.Body.String())
	}

	// Extract cookie and SAMLResponse from the mock upstream IdP page
	cookies := wSSO.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "samlguard_auth_state" {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Fatal("expected samlguard_auth_state cookie to be set")
	}

	bodySSO := wSSO.Body.String()
	reSAMLResponse := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAMLResponse.FindStringSubmatch(bodySSO)
	if len(matches) < 2 {
		t.Fatalf("could not extract signed SAMLResponse from mock upstream form")
	}
	upstreamSAMLResponse := matches[1]

	// 2. Upstream IdP POSTs to /saml/acs with real signed SAMLResponse
	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", upstreamSAMLResponse)

	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	if wACS.Code != http.StatusOK {
		t.Fatalf("expected 200 from /saml/acs, got %d (body: %s)", wACS.Code, wACS.Body.String())
	}

	bodyACS := wACS.Body.String()
	if !strings.Contains(bodyACS, "Multi-Factor Verification") {
		t.Errorf("expected MFA challenge screen in ACS response")
	}

	// Extract CSRF token from challenge screen
	reCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	csrfMatches := reCSRF.FindStringSubmatch(bodyACS)
	if len(csrfMatches) < 2 {
		t.Fatalf("could not extract csrf_token from MFA challenge page")
	}
	csrfToken := csrfMatches[1]

	// 3. User submits Dummy OTP (000000) with valid CSRF token
	verifyForm := url.Values{}
	verifyForm.Set("session_id", authCookie.Value)
	verifyForm.Set("csrf_token", csrfToken)
	verifyForm.Set("method", "totp")
	verifyForm.Set("code", "000000")

	wVerify := httptest.NewRecorder()
	reqVerify, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyForm.Encode()))
	reqVerify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqVerify.AddCookie(authCookie)
	app.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 from /mfa/verify, got %d (body: %s)", wVerify.Code, wVerify.Body.String())
	}

	bodyVerify := wVerify.Body.String()
	if !strings.Contains(bodyVerify, `action="https://ita.example.com/api/current/authentication/saml2-callback"`) {
		t.Errorf("expected downstream form target to be ITA ACS URL, got: %s", bodyVerify)
	}
	if !strings.Contains(bodyVerify, `name="RelayState" value="ita-relay-dummy"`) {
		t.Errorf("expected original ITA RelayState preserved, got: %s", bodyVerify)
	}

	// Extract and decode downstream SAMLResponse
	respMatches := reSAMLResponse.FindStringSubmatch(bodyVerify)
	if len(respMatches) < 2 {
		t.Fatalf("could not extract SAMLResponse from downstream form")
	}
	samlRespXMLBytes, err := base64.StdEncoding.DecodeString(respMatches[1])
	if err != nil {
		t.Fatalf("failed to decode SAMLResponse base64: %v", err)
	}
	samlRespXML := string(samlRespXMLBytes)

	// Validate SAML Response properties
	if !strings.Contains(samlRespXML, `InResponseTo="_ita_req_dummy_9999"`) {
		t.Errorf("expected InResponseTo to match original ITA AuthnRequest ID _ita_req_dummy_9999, xml:\n%s", samlRespXML)
	}
	if !strings.Contains(samlRespXML, `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">apc</saml:NameID>`) {
		t.Errorf("expected Subject NameID apc with persistent format, xml:\n%s", samlRespXML)
	}
	if !strings.Contains(samlRespXML, `<saml:AttributeValue>Admin</saml:AttributeValue>`) {
		t.Errorf("expected mapped group Admin in attributes, xml:\n%s", samlRespXML)
	}
	if !strings.Contains(samlRespXML, `<ds:Signature`) {
		t.Errorf("expected signed assertion with ds:Signature, xml:\n%s", samlRespXML)
	}
	if !strings.Contains(samlRespXML, `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken`) {
		t.Errorf("expected TimeSyncToken AuthnContextClassRef, xml:\n%s", samlRespXML)
	}

	// 4. Session Replay Protection: verification must not be reusable
	wReplay := httptest.NewRecorder()
	reqReplay, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyForm.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReplay.AddCookie(authCookie)
	app.ServeHTTP(wReplay, reqReplay)

	if wReplay.Code != http.StatusUnauthorized && wReplay.Code != http.StatusConflict {
		t.Errorf("expected 401 or 409 on session replay, got %d", wReplay.Code)
	}
}

func TestE2E_FullFlow_TOTP_EnrollmentAndVerification(t *testing.T) {
	cfg := testConfig(t)
	cfg.MFA.AllowDummyOTP = false // Disable dummy OTP to ensure real TOTP works
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to setup app: %v", err)
	}

	// 1. ITA sends inbound AuthnRequest
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_totp_1234"
                    Version="2.0"
                    IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
    <saml:Issuer>https://ita.example.com</saml:Issuer>
</samlp:AuthnRequest>`

	encodedReq, err := encodeSAMLRequest(rawReqXML)
	if err != nil {
		t.Fatalf("failed to encode saml request: %v", err)
	}

	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-totp", nil)
	app.ServeHTTP(wSSO, reqSSO)

	cookies := wSSO.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "samlguard_auth_state" {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Fatal("expected samlguard_auth_state cookie to be set")
	}

	reSAMLResponse := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAMLResponse.FindStringSubmatch(wSSO.Body.String())
	upstreamSAMLResponse := matches[1]

	// 2. Upstream IdP POSTs to /saml/acs
	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", upstreamSAMLResponse)

	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	bodyACS := wACS.Body.String()
	// Extract Secret Key from QR enrollment section
	reKey := regexp.MustCompile(`Key:\s*([A-Z2-7=]+)`)
	keyMatches := reKey.FindStringSubmatch(bodyACS)
	if len(keyMatches) < 2 {
		t.Fatalf("could not extract pending TOTP secret key from enrollment page:\n%s", bodyACS)
	}
	totpSecret := keyMatches[1]

	reCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	csrfMatches := reCSRF.FindStringSubmatch(bodyACS)
	if len(csrfMatches) < 2 {
		t.Fatalf("could not extract csrf_token from challenge page")
	}
	csrfToken := csrfMatches[1]

	// Compute valid TOTP code for current time
	nowStep := time.Now().UTC().Unix() / 30
	validCode, err := computeTOTP(totpSecret, nowStep)
	if err != nil {
		t.Fatalf("failed to compute valid totp: %v", err)
	}

	// 3. Test Invalid code rejection
	badForm := url.Values{}
	badForm.Set("session_id", authCookie.Value)
	badForm.Set("csrf_token", csrfToken)
	badForm.Set("method", "totp")
	badForm.Set("code", "999999")
	badForm.Set("is_pending", "true")

	wBad := httptest.NewRecorder()
	reqBad, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(badForm.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBad.AddCookie(authCookie)
	app.ServeHTTP(wBad, reqBad)

	if wBad.Code != http.StatusOK || !strings.Contains(wBad.Body.String(), "Invalid verification code") {
		t.Errorf("expected 'Invalid verification code' error on bad code, got: %s", wBad.Body.String())
	}

	// 4. Submit Valid TOTP code to activate pending enrollment and succeed
	goodForm := url.Values{}
	goodForm.Set("session_id", authCookie.Value)
	goodForm.Set("csrf_token", csrfToken)
	goodForm.Set("method", "totp")
	goodForm.Set("code", validCode)
	goodForm.Set("is_pending", "true")

	wGood := httptest.NewRecorder()
	reqGood, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(goodForm.Encode()))
	reqGood.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqGood.AddCookie(authCookie)
	app.ServeHTTP(wGood, reqGood)

	if wGood.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid TOTP activation, got %d", wGood.Code)
	}

	bodyGood := wGood.Body.String()
	if !strings.Contains(bodyGood, `name="SAMLResponse"`) {
		t.Errorf("expected SAMLResponse on successful TOTP verification, got: %s", bodyGood)
	}
}

// Negative Security Test 1: Unsigned Upstream Assertion
func TestE2E_Negative_UnsignedUpstreamAssertion(t *testing.T) {
	cfg := testConfig(t)
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Create an unsigned SAMLResponse
	unsignedXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_unsigned_resp" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                        Destination="http://localhost:8080/saml/acs">
        <saml:Assertion ID="_unsigned_assertion" Version="2.0" IssueInstant="2026-11-04T12:00:00Z">
            <saml:Issuer>https://mock-idp.example.com</saml:Issuer>
            <saml:Subject><saml:NameID>apc</saml:NameID></saml:Subject>
        </saml:Assertion>
    </samlp:Response>`

	b64Unsigned := base64.StdEncoding.EncodeToString([]byte(unsignedXML))

	acsForm := url.Values{}
	acsForm.Set("RelayState", "some-session-id")
	acsForm.Set("SAMLResponse", b64Unsigned)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.ServeHTTP(w, req)

	// Must fail-closed: 400 (session invalid) or 401 (signature rejected)
	if w.Code == http.StatusOK {
		t.Fatal("SECURITY VIOLATION: unsigned upstream assertion was accepted!")
	}
}

// Negative Security Test 2: Tampered Upstream XMLDSig Signature
func TestE2E_Negative_TamperedUpstreamSignature(t *testing.T) {
	cfg := testConfig(t)
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Inbound SSO to get real signed upstream SAML response
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_tamper_1"
                    Version="2.0"
                    IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
    <saml:Issuer>https://ita.example.com</saml:Issuer>
</samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-tamper", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]
	reSAML := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAML.FindStringSubmatch(wSSO.Body.String())
	rawB64 := matches[1]

	rawXMLBytes, _ := base64.StdEncoding.DecodeString(rawB64)
	// Tamper: Modify user name inside the assertion from apc to attacker
	tamperedXML := strings.Replace(string(rawXMLBytes), "apc", "attacker", 1)
	tamperedB64 := base64.StdEncoding.EncodeToString([]byte(tamperedXML))

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", tamperedB64)

	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	if wACS.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY VIOLATION: tampered assertion signature passed! Got status %d, expected 401", wACS.Code)
	}
}

// Negative Security Test 3: Untrusted Certificate in Signature
func TestE2E_Negative_UntrustedUpstreamCertificate(t *testing.T) {
	rogueCert, rogueKey, err := generateRogueCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate rogue cert: %v", err)
	}

	// Generate a signed assertion using the untrusted rogue key
	cfg := testConfig(t)
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Construct assertion signed by rogue key
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_resp_rogue")
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("Destination", "http://localhost:8080/saml/acs")

	assertion := resp.CreateElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", "_assert_rogue")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	issuer := assertion.CreateElement("saml:Issuer")
	issuer.SetText("https://rogue-idp.com")
	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.SetText("rogue-user")

	sigCtx, err := goxmldsig.NewSigningContext(rogueKey, [][]byte{rogueCert.Raw})
	if err != nil {
		t.Fatalf("initializing signing context: %v", err)
	}
	sigCtx.Canonicalizer = goxmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	sigEl, err := sigCtx.ConstructSignature(assertion, true)
	if err != nil {
		t.Fatalf("constructing rogue signature: %v", err)
	}
	assertion.InsertChildAt(issuer.Index()+1, sigEl)

	xmlBytes, _ := doc.WriteToBytes()
	rogueB64 := base64.StdEncoding.EncodeToString(xmlBytes)

	// Attempt ACS submission
	acsForm := url.Values{}
	acsForm.Set("RelayState", "some-session")
	acsForm.Set("SAMLResponse", rogueB64)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.ServeHTTP(w, req)

	// Since rogue cert is not in configured idpCertStore, must be rejected
	if w.Code == http.StatusOK {
		t.Fatal("SECURITY VIOLATION: assertion signed by untrusted certificate was accepted!")
	}
}

// Negative Security Test 4: Missing or Tampered CSRF Token
func TestE2E_Negative_MissingOrInvalidCSRFToken(t *testing.T) {
	cfg := testConfig(t)
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Inbound SSO
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_csrf" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-csrf", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]
	reSAML := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAML.FindStringSubmatch(wSSO.Body.String())
	rawB64 := matches[1]

	// ACS
	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", rawB64)
	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	// 1. Submit /mfa/verify without CSRF token
	verifyNoCSRF := url.Values{}
	verifyNoCSRF.Set("session_id", authCookie.Value)
	verifyNoCSRF.Set("method", "totp")
	verifyNoCSRF.Set("code", "000000")

	wNoCSRF := httptest.NewRecorder()
	reqNoCSRF, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyNoCSRF.Encode()))
	reqNoCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNoCSRF.AddCookie(authCookie)
	app.ServeHTTP(wNoCSRF, reqNoCSRF)

	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: /mfa/verify succeeded without CSRF token! Got %d, expected 403", wNoCSRF.Code)
	}

	// 2. Submit /mfa/verify with forged CSRF token
	verifyBadCSRF := url.Values{}
	verifyBadCSRF.Set("session_id", authCookie.Value)
	verifyBadCSRF.Set("csrf_token", "forged-attacker-csrf-token-123456")
	verifyBadCSRF.Set("method", "totp")
	verifyBadCSRF.Set("code", "000000")

	wBadCSRF := httptest.NewRecorder()
	reqBadCSRF, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyBadCSRF.Encode()))
	reqBadCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBadCSRF.AddCookie(authCookie)
	app.ServeHTTP(wBadCSRF, reqBadCSRF)

	if wBadCSRF.Code != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: /mfa/verify succeeded with invalid CSRF token! Got %d, expected 403", wBadCSRF.Code)
	}
}

// Negative Security Test 5: TOTP Brute-Force Throttling and Lockout
func TestE2E_Negative_TOTPBruteForceLockout(t *testing.T) {
	cfg := testConfig(t)
	cfg.MFA.AllowDummyOTP = false
	cfg.Database.Path = ":memory:"

	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Inbound SSO & ACS to create session
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_lockout" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-lock", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]
	reSAML := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAML.FindStringSubmatch(wSSO.Body.String())
	rawB64 := matches[1]

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", rawB64)
	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	reCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	csrfMatches := reCSRF.FindStringSubmatch(wACS.Body.String())
	csrfToken := csrfMatches[1]

	// Submit 5 incorrect TOTP codes
	for i := 1; i <= 5; i++ {
		form := url.Values{}
		form.Set("session_id", authCookie.Value)
		form.Set("csrf_token", csrfToken)
		form.Set("method", "totp")
		form.Set("code", fmt.Sprintf("11111%d", i))
		form.Set("is_pending", "true")

		wAttempt := httptest.NewRecorder()
		reqAttempt, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(form.Encode()))
		reqAttempt.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqAttempt.AddCookie(authCookie)
		app.ServeHTTP(wAttempt, reqAttempt)

		if i == 5 {
			// At 5th failure, account should be locked
			if !strings.Contains(wAttempt.Body.String(), "locked") {
				t.Fatalf("expected account lockout message on 5th failure, got: %s", wAttempt.Body.String())
			}
		}
	}
}

// Security Feature Test: Safe TOTP Re-Enrollment Flow
func TestE2E_SafeTOTPReEnrollment(t *testing.T) {
	cfg := testConfig(t)
	cfg.MFA.AllowDummyOTP = false
	cfg.Database.Path = ":memory:"

	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// First: complete initial enrollment
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_re1" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-re", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]
	reSAML := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAML.FindStringSubmatch(wSSO.Body.String())

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", matches[1])
	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	reKey := regexp.MustCompile(`Key:\s*([A-Z2-7=]+)`)
	keyMatches := reKey.FindStringSubmatch(wACS.Body.String())
	initialSecret := keyMatches[1]

	reCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	csrfToken := reCSRF.FindStringSubmatch(wACS.Body.String())[1]

	// Activate initial TOTP
	validCode, _ := computeTOTP(initialSecret, time.Now().UTC().Unix()/30)
	verifyForm := url.Values{}
	verifyForm.Set("session_id", authCookie.Value)
	verifyForm.Set("csrf_token", csrfToken)
	verifyForm.Set("method", "totp")
	verifyForm.Set("code", validCode)
	verifyForm.Set("is_pending", "true")

	wVerify := httptest.NewRecorder()
	reqVerify, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyForm.Encode()))
	reqVerify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqVerify.AddCookie(authCookie)
	app.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("initial TOTP verification failed: %d", wVerify.Code)
	}

	// Now: Start a new login session for the same user with unique request ID
	rawReqXML2 := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_re2" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`
	encodedReq2, _ := encodeSAMLRequest(rawReqXML2)

	wSSO2 := httptest.NewRecorder()
	reqSSO2, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq2)+"&RelayState=relay-re2", nil)
	app.ServeHTTP(wSSO2, reqSSO2)

	authCookie2 := wSSO2.Result().Cookies()[0]
	matches2 := reSAML.FindStringSubmatch(wSSO2.Body.String())

	acsForm2 := url.Values{}
	acsForm2.Set("RelayState", authCookie2.Value)
	acsForm2.Set("SAMLResponse", matches2[1])
	wACS2 := httptest.NewRecorder()
	reqACS2, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm2.Encode()))
	reqACS2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS2.AddCookie(authCookie2)
	app.ServeHTTP(wACS2, reqACS2)

	csrfToken2 := reCSRF.FindStringSubmatch(wACS2.Body.String())[1]

	// 1. Unauthenticated GET ?re_enroll=true must NOT generate or leak a new TOTP secret
	wACSGetReEnroll := httptest.NewRecorder()
	reqACSGetReEnroll, _ := http.NewRequest(http.MethodGet, "/saml/acs?method=totp&re_enroll=true&session_id="+url.QueryEscape(authCookie2.Value), nil)
	reqACSGetReEnroll.AddCookie(authCookie2)
	app.ServeHTTP(wACSGetReEnroll, reqACSGetReEnroll)
	if len(reKey.FindStringSubmatch(wACSGetReEnroll.Body.String())) >= 2 {
		t.Fatal("SECURITY ERROR: GET /saml/acs?re_enroll=true leaked a new TOTP key without verifying an active factor")
	}

	// 2. Direct POST /mfa/verify with is_pending=true when !ReEnrollAuthorized must be rejected with 403
	pendingBypassForm := url.Values{}
	pendingBypassForm.Set("session_id", authCookie2.Value)
	pendingBypassForm.Set("csrf_token", csrfToken2)
	pendingBypassForm.Set("method", "totp")
	pendingBypassForm.Set("code", "000000")
	pendingBypassForm.Set("is_pending", "true")
	wBypass := httptest.NewRecorder()
	reqBypass, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(pendingBypassForm.Encode()))
	reqBypass.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBypass.AddCookie(authCookie2)
	app.ServeHTTP(wBypass, reqBypass)
	if wBypass.Code != http.StatusForbidden {
		t.Fatalf("expected 403 blocking unauthorized is_pending=true verify, got %d", wBypass.Code)
	}

	// 3. POST /mfa/re-enroll without current_code must be rejected with 403
	reEnrollNoCodeForm := url.Values{}
	reEnrollNoCodeForm.Set("session_id", authCookie2.Value)
	reEnrollNoCodeForm.Set("csrf_token", csrfToken2)

	wReEnrollDenied := httptest.NewRecorder()
	reqReEnrollDenied, _ := http.NewRequest(http.MethodPost, "/mfa/re-enroll", strings.NewReader(reEnrollNoCodeForm.Encode()))
	reqReEnrollDenied.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReEnrollDenied.AddCookie(authCookie2)
	app.ServeHTTP(wReEnrollDenied, reqReEnrollDenied)
	if wReEnrollDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on /mfa/re-enroll without current_code, got %d", wReEnrollDenied.Code)
	}

	// 4. Request Re-Enrollment via POST /mfa/re-enroll WITH valid current TOTP code
	// Use next 30s step (within TOTPSkew=1) so TOTP replay protection accepts a fresh step after initial activation.
	currentCode, _ := computeTOTP(initialSecret, (time.Now().UTC().Unix()/30)+1)
	reEnrollForm := url.Values{}
	reEnrollForm.Set("session_id", authCookie2.Value)
	reEnrollForm.Set("csrf_token", csrfToken2)
	reEnrollForm.Set("verify_method", "totp")
	reEnrollForm.Set("current_code", currentCode)

	wReEnroll := httptest.NewRecorder()
	reqReEnroll, _ := http.NewRequest(http.MethodPost, "/mfa/re-enroll", strings.NewReader(reEnrollForm.Encode()))
	reqReEnroll.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReEnroll.AddCookie(authCookie2)
	app.ServeHTTP(wReEnroll, reqReEnroll)

	if wReEnroll.Code != http.StatusOK {
		t.Fatalf("expected 200 on /mfa/re-enroll with valid current_code, got %d: %s", wReEnroll.Code, wReEnroll.Body.String())
	}

	// Re-enrollment page must present a new secret key
	newKeyMatches := reKey.FindStringSubmatch(wReEnroll.Body.String())
	if len(newKeyMatches) < 2 {
		t.Fatalf("could not extract new TOTP key from re-enroll page")
	}
	newSecret := newKeyMatches[1]
	if newSecret == initialSecret {
		t.Error("new secret key must be different from initial secret")
	}
}

func TestE2E_RejectsUntrustedAssertionConsumerServiceURL(t *testing.T) {
	cfg := testConfig(t)
	cfg.Database.Path = ":memory:"

	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_evil_acs" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://evil.attacker.example/steal-saml">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, err := encodeSAMLRequest(rawReqXML)
	if err != nil {
		t.Fatalf("encode SAML request: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=test-relay", nil)
	app.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for untrusted AssertionConsumerServiceURL, got %d: %s", w.Code, w.Body.String())
	}
}

func TestE2E_FullFlow_EmailOTP(t *testing.T) {
	cfg := testConfig(t)
	cfg.MFA.AllowDummyOTP = false

	testStorage, err := mfa.NewSQLiteStorage(":memory:")
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer testStorage.Close()

	service := mfa.NewService(testStorage, mfa.NewSMTPSender("", 0, "", "", "", "", "", testLogger().System()), cfg, testLogger().System())

	ctx := context.Background()
	userKey := "https://test.upstream.idp|test-user-email"
	email := "test-user@example.com"

	// Generate and send Email OTP
	err = service.GenerateAndSendEmailOTP(ctx, userKey, email)
	if err != nil {
		t.Fatalf("failed to generate email otp: %v", err)
	}

	// Resend cooldown check: immediate re-generation should fail with ErrCooldownActive
	err = service.GenerateAndSendEmailOTP(ctx, userKey, email)
	if err == nil || !strings.Contains(err.Error(), "wait") {
		t.Fatalf("expected resend cooldown to be active, got: %v", err)
	}

	// Invalid code verification fails
	ok, err := service.VerifyEmailOTP(ctx, userKey, "123456")
	if ok || err == nil {
		t.Errorf("expected invalid code to fail, got ok=%v, err=%v", ok, err)
	}
}

func TestE2E_ProductionMode_RejectsDummyOTP(t *testing.T) {
	cfg := &config.Config{
		Env: "production",
		Server: config.ServerConfig{
			Port: 8080,
		},
		SAML: config.SAMLConfig{
			EntityID: "https://test.samlguard.example",
		},
		Database: config.DatabaseConfig{
			Driver: "sqlite",
			Path:   ":memory:",
		},
		MFA: config.MFAConfig{
			AllowDummyOTP: true, // MUST BE REJECTED IN PRODUCTION
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected cfg.Validate() to FAIL when AllowDummyOTP=true in production mode")
	}
	if !strings.Contains(err.Error(), "security violation: mfa.allow_dummy_otp must be false in production mode") {
		t.Errorf("expected security violation error in validation message, got: %v", err)
	}
}

// Negative Security Test 6: Upstream Missing or Mismatched Issuer
func TestE2E_Negative_UpstreamMissingOrMismatchedIssuer(t *testing.T) {
	cfg := testConfig(t)
	cfg.SAML.IdPEntityID = "https://trusted-idp.example.com"
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	// Inbound SSO
	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_issuer_neg" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-issuer-neg", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]

	// Upstream response with mismatched issuer
	mismatchedXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_resp_mismatched_issuer" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                        Destination="http://localhost:8080/saml/acs">
        <saml:Issuer>https://attacker-idp.com</saml:Issuer>
        <saml:Assertion ID="_assert_mismatched_issuer" Version="2.0" IssueInstant="2026-11-04T12:00:00Z">
            <saml:Issuer>https://attacker-idp.com</saml:Issuer>
            <saml:Subject>
                <saml:NameID>apc</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData Recipient="http://localhost:8080/saml/acs" />
                </saml:SubjectConfirmationData>
            </saml:Subject>
        </saml:Assertion>
    </samlp:Response>`

	b64Mismatched := base64.StdEncoding.EncodeToString([]byte(mismatchedXML))

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", b64Mismatched)

	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	// Must fail-closed: 401 Unauthorized
	if wACS.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY VIOLATION: mismatched issuer assertion was accepted! Got %d, expected 401", wACS.Code)
	}
}

// Negative Security Test 7: Upstream Missing or Mismatched SubjectConfirmationData Recipient
func TestE2E_Negative_UpstreamMissingOrMismatchedRecipient(t *testing.T) {
	cfg := testConfig(t)
	cfg.SAML.IdPEntityID = "https://mock-idp.samlguard.local"
	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_recip_neg" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-recip-neg", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]

	// Mismatched Recipient
	mismatchedXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_resp_mismatched_recip" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                        Destination="http://localhost:8080/saml/acs">
        <saml:Issuer>https://mock-idp.samlguard.local</saml:Issuer>
        <saml:Assertion ID="_assert_mismatched_recip" Version="2.0" IssueInstant="2026-11-04T12:00:00Z">
            <saml:Issuer>https://mock-idp.samlguard.local</saml:Issuer>
            <saml:Subject>
                <saml:NameID>apc</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData Recipient="https://attacker-sp.example.com/callback" />
                </saml:SubjectConfirmationData>
            </saml:Subject>
        </saml:Assertion>
    </samlp:Response>`

	b64Mismatched := base64.StdEncoding.EncodeToString([]byte(mismatchedXML))

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", b64Mismatched)

	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	if wACS.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY VIOLATION: mismatched recipient assertion was accepted! Got %d, expected 401", wACS.Code)
	}
}

// Verification Test: Email OTP never produces TimeSyncToken, even with global TimeSyncToken configured
func TestE2E_AuthnContext_EmailOTPNeverClaimsTimeSyncToken(t *testing.T) {
	cfg := testConfig(t)
	// Explicitly set global configuration to TimeSyncToken
	cfg.SAML.AuthnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
	cfg.MFA.AllowDummyOTP = true

	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	rawReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_ita_req_email_authn" Version="2.0" IssueInstant="2026-11-04T12:00:00Z"
                    Destination="http://localhost:8080/saml/sso"
                    AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback">
        <saml:Issuer>https://ita.example.com</saml:Issuer>
    </samlp:AuthnRequest>`

	encodedReq, _ := encodeSAMLRequest(rawReqXML)
	wSSO := httptest.NewRecorder()
	reqSSO, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedReq)+"&RelayState=relay-email-authn", nil)
	app.ServeHTTP(wSSO, reqSSO)

	authCookie := wSSO.Result().Cookies()[0]
	reSAML := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := reSAML.FindStringSubmatch(wSSO.Body.String())

	acsForm := url.Values{}
	acsForm.Set("RelayState", authCookie.Value)
	acsForm.Set("SAMLResponse", matches[1])
	wACS := httptest.NewRecorder()
	reqACS, _ := http.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(acsForm.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqACS.AddCookie(authCookie)
	app.ServeHTTP(wACS, reqACS)

	reCSRF := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	csrfToken := reCSRF.FindStringSubmatch(wACS.Body.String())[1]

	// Verify using Email OTP method
	verifyForm := url.Values{}
	verifyForm.Set("session_id", authCookie.Value)
	verifyForm.Set("csrf_token", csrfToken)
	verifyForm.Set("method", "email")
	verifyForm.Set("code", "000000") // Dummy OTP in dev mode

	wVerify := httptest.NewRecorder()
	reqVerify, _ := http.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyForm.Encode()))
	reqVerify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqVerify.AddCookie(authCookie)
	app.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 on Email OTP verify, got %d (body: %s)", wVerify.Code, wVerify.Body.String())
	}

	// Extract downstream SAMLResponse
	respMatches := reSAML.FindStringSubmatch(wVerify.Body.String())
	if len(respMatches) < 2 {
		t.Fatalf("could not extract SAMLResponse from downstream form")
	}
	xmlBytes, err := base64.StdEncoding.DecodeString(respMatches[1])
	if err != nil {
		t.Fatalf("failed to decode base64 SAMLResponse: %v", err)
	}
	xmlStr := string(xmlBytes)

	// Critical Assertions:
	// 1. MUST NOT contain TimeSyncToken
	if strings.Contains(xmlStr, "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken") {
		t.Fatalf("SECURITY VIOLATION: Email OTP produced TimeSyncToken in downstream assertion!\n%s", xmlStr)
	}

	// 2. MUST contain unspecified
	if !strings.Contains(xmlStr, "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified") {
		t.Fatalf("expected Email OTP to produce AuthnContextClassRef 'unspecified', got:\n%s", xmlStr)
	}
}
