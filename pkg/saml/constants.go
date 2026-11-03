package saml

const (
	// Namespaces
	NamespaceProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NamespaceAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"

	// Bindings
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	// Status Codes
	StatusSuccess        = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester      = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder      = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	StatusAuthnFailed    = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// NameID Formats
	NameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)
