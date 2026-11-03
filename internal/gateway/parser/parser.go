package parser

import "github.com/hidayat-SE/samlguard/internal/gateway/model"
// Parser isolates the `crewjam/saml` library from the business logic
type Parser interface {
	ParseAuthnRequest(rawXML []byte) (*model.ParseResult, error)
}
