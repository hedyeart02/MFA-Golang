package web

import (
	_ "embed"
	"html/template"
)

//go:embed templates/mfa_challenge.html
var DefaultMFAChallengeHTML string

//go:embed templates/error.html
var DefaultErrorHTML string

// ParseMFAChallengeTemplate parses and returns the embedded MFA challenge template
func ParseMFAChallengeTemplate() (*template.Template, error) {
	return template.New("mfa_challenge.html").Parse(DefaultMFAChallengeHTML)
}

// ParseErrorTemplate parses and returns the embedded error template
func ParseErrorTemplate() (*template.Template, error) {
	return template.New("error.html").Parse(DefaultErrorHTML)
}

