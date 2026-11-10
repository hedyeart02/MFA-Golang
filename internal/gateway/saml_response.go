package gateway

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/hidayat-SE/samlguard/internal/config"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

const (
	samlTimeFormat    = "2006-01-02T15:04:05Z"
	samlpNamespace    = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlNamespace     = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	bearerMethod      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

type SAMLResponseRequest struct {
	InResponseTo         string
	Destination          string
	RelayState           string
	Audience             string
	Issuer               string
	SubjectNameID        string
	SubjectNameIDFormat  string
	Email                string
	DisplayName          string
	RawGroups            []string
	AuthnContextClassRef string
}

type SAMLResponseResult struct {
	SAMLResponse string
	RelayState   string
	Destination  string
	PostFormHTML string
}

type ResponseGenerator struct {
	cfg         *config.Config
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
}

func NewResponseGenerator(cfg *config.Config) (*ResponseGenerator, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}

	certFile := cfg.SAML.CertFile
	keyFile := cfg.SAML.KeyFile
	if certFile == "" {
		certFile = "./cert/saml-signing.crt"
	}
	if keyFile == "" {
		keyFile = "./cert/saml-signing.key"
	}

	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("reading signing certificate file %s: %w", certFile, err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate found in %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing x509 certificate: %w", err)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading signing key file %s: %w", keyFile, err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM private key found in %s", keyFile)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing rsa private key: %w", err)
		}
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not an RSA private key")
	}

	return &ResponseGenerator{
		cfg:         cfg,
		certificate: cert,
		privateKey:  rsaKey,
	}, nil
}

// Certificate returns the X.509 certificate used for SAML signing
func (g *ResponseGenerator) Certificate() *x509.Certificate {
	if g == nil {
		return nil
	}
	return g.certificate
}

// GenerateResponse produces a signed SAML 2.0 Response with W3C Exclusive XML Canonicalization (C14N)
func (g *ResponseGenerator) GenerateResponse(req SAMLResponseRequest) (*SAMLResponseResult, error) {
	now := time.Now().UTC()
	responseID := "_" + uuid.New().String()
	assertionID := "_" + uuid.New().String()

	destination := req.Destination
	if destination == "" {
		destination = g.cfg.SAML.ACSURL
	}
	issuer := req.Issuer
	if issuer == "" {
		issuer = g.cfg.SAML.EntityID
	}
	audience := req.Audience
	if audience == "" {
		if len(g.cfg.SAML.AllowedAudiences) > 0 {
			audience = g.cfg.SAML.AllowedAudiences[0]
		} else {
			audience = "https://192.168.0.119" // Standard ITA SP Entity ID (F-06)
		}
	}

	nameIDFormat := req.SubjectNameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	}

	authnContext := req.AuthnContextClassRef
	if authnContext == "" {
		authnContext = g.cfg.SAML.AuthnContextClassRef
	}
	if authnContext == "" {
		authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	}

	// Group and role mapping (NO hardcoded Admin)
	mappedGroups := g.resolveMappedGroups(req.RawGroups)

	// Clock skew buffer: 5 minutes in the past accommodates VM/hypervisor time drift
	notBefore := now.Add(-5 * time.Minute).Format(samlTimeFormat)
	notOnOrAfter := now.Add(10 * time.Minute).Format(samlTimeFormat)
	issueInstant := now.Format(samlTimeFormat)

	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", samlpNamespace)
	resp.CreateAttr("xmlns:saml", samlNamespace)
	resp.CreateAttr("ID", responseID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", issueInstant)
	resp.CreateAttr("Destination", destination)
	if req.InResponseTo != "" {
		resp.CreateAttr("InResponseTo", req.InResponseTo)
	}

	respIssuer := resp.CreateElement("saml:Issuer")
	respIssuer.SetText(issuer)

	status := resp.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", samlStatusSuccess)

	// Create Assertion
	assertion := resp.CreateElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", samlNamespace)
	assertion.CreateAttr("ID", assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", issueInstant)

	assertIssuer := assertion.CreateElement("saml:Issuer")
	assertIssuer.SetText(issuer)

	// Subject
	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", nameIDFormat)
	nameID.SetText(req.SubjectNameID)

	subjConf := subject.CreateElement("saml:SubjectConfirmation")
	subjConf.CreateAttr("Method", bearerMethod)
	subjConfData := subjConf.CreateElement("saml:SubjectConfirmationData")
	if req.InResponseTo != "" {
		subjConfData.CreateAttr("InResponseTo", req.InResponseTo)
	}
	subjConfData.CreateAttr("NotOnOrAfter", notOnOrAfter)
	subjConfData.CreateAttr("Recipient", destination)

	// Conditions
	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", notBefore)
	conditions.CreateAttr("NotOnOrAfter", notOnOrAfter)
	audRestr := conditions.CreateElement("saml:AudienceRestriction")
	aud := audRestr.CreateElement("saml:Audience")
	aud.SetText(audience)

	// AuthnStatement
	authnStmt := assertion.CreateElement("saml:AuthnStatement")
	authnStmt.CreateAttr("AuthnInstant", issueInstant)
	authnStmt.CreateAttr("SessionIndex", "_"+uuid.New().String())
	authnCtx := authnStmt.CreateElement("saml:AuthnContext")
	authnCtxClass := authnCtx.CreateElement("saml:AuthnContextClassRef")
	authnCtxClass.SetText(authnContext)

	// AttributeStatement
	attrStmt := assertion.CreateElement("saml:AttributeStatement")
	if req.SubjectNameID != "" {
		attr := attrStmt.CreateElement("saml:Attribute")
		attr.CreateAttr("Name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
		val := attr.CreateElement("saml:AttributeValue")
		val.SetText(req.SubjectNameID)
	}
	if req.Email != "" {
		attr := attrStmt.CreateElement("saml:Attribute")
		attr.CreateAttr("Name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
		val := attr.CreateElement("saml:AttributeValue")
		val.SetText(req.Email)
	}
	if req.DisplayName != "" {
		attr := attrStmt.CreateElement("saml:Attribute")
		attr.CreateAttr("Name", "http://schemas.xmlsoap.org/claims/CommonName")
		val := attr.CreateElement("saml:AttributeValue")
		val.SetText(req.DisplayName)
	}
	if len(mappedGroups) > 0 {
		attr := attrStmt.CreateElement("saml:Attribute")
		attr.CreateAttr("Name", "http://schemas.xmlsoap.org/claims/Group")
		for _, g := range mappedGroups {
			val := attr.CreateElement("saml:AttributeValue")
			val.SetText(g)
		}
	}

	// Sign Assertion with goxmldsig (W3C Exclusive C14N + enveloped-signature + RSA-SHA256)
	sigCtx, err := goxmldsig.NewSigningContext(g.privateKey, [][]byte{g.certificate.Raw})
	if err != nil {
		return nil, fmt.Errorf("initializing xml signing context: %w", err)
	}
	sigCtx.Canonicalizer = goxmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := sigCtx.SetSignatureMethod(goxmldsig.RSASHA256SignatureMethod); err != nil {
		return nil, fmt.Errorf("setting signature method: %w", err)
	}

	sig, err := sigCtx.ConstructSignature(assertion, true)
	if err != nil {
		return nil, fmt.Errorf("constructing signature: %w", err)
	}

	// In SAML 2.0 schema: ds:Signature must be placed immediately following saml:Issuer
	assertion.InsertChildAt(assertIssuer.Index()+1, sig)

	responseXML, err := doc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("serializing saml response: %w", err)
	}

	samlResponseB64 := base64.StdEncoding.EncodeToString([]byte(responseXML))

	postFormHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>SAMLGuard - Redirecting to Schneider Electric ITA</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>JavaScript is required. Please click the button below to proceed to ITA.</p></noscript>
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
<input type="hidden" name="RelayState" value="%s"/>
<noscript><button type="submit">Continue to ITA</button></noscript>
</form></body></html>`, destination, samlResponseB64, req.RelayState)

	return &SAMLResponseResult{
		SAMLResponse: samlResponseB64,
		RelayState:   req.RelayState,
		Destination:  destination,
		PostFormHTML: postFormHTML,
	}, nil
}

// resolveMappedGroups translates upstream groups to configured ITA groups
func (g *ResponseGenerator) resolveMappedGroups(upstreamGroups []string) []string {
	mapping := g.cfg.SAML.GroupMapping
	var mapped []string
	seen := make(map[string]bool)

	for _, up := range upstreamGroups {
		trimmed := strings.TrimSpace(up)
		if target, ok := mapping[trimmed]; ok && target != "" {
			if !seen[target] {
				mapped = append(mapped, target)
				seen[target] = true
			}
		} else {
			// If already a valid target group, preserve it
			for _, allowedTarget := range mapping {
				if trimmed == allowedTarget && trimmed != "" && !seen[trimmed] {
					mapped = append(mapped, trimmed)
					seen[trimmed] = true
					break
				}
			}
		}
	}

	// If no mapped groups found, use default groups if explicitly configured
	if len(mapped) == 0 && len(g.cfg.SAML.DefaultGroups) > 0 {
		for _, dg := range g.cfg.SAML.DefaultGroups {
			trimmed := strings.TrimSpace(dg)
			if trimmed != "" && !seen[trimmed] {
				mapped = append(mapped, trimmed)
				seen[trimmed] = true
			}
		}
	}

	return mapped
}
