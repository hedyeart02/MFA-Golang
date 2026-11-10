package web

import (
	_ "embed"
	"html/template"
)

//go:embed templates/mfa_challenge.html
var DefaultMFAChallengeHTML string

//go:embed templates/error.html
var DefaultErrorHTML string

//go:embed templates/admin_settings.html
var DefaultAdminSettingsHTML string

//go:embed templates/admin_login.html
var DefaultAdminLoginHTML string

//go:embed templates/admin_change_password.html
var DefaultAdminChangePasswordHTML string

// ParseMFAChallengeTemplate parses and returns the embedded MFA challenge template
func ParseMFAChallengeTemplate() (*template.Template, error) {
	return template.New("mfa_challenge.html").Parse(DefaultMFAChallengeHTML)
}

// ParseErrorTemplate parses and returns the embedded error template
func ParseErrorTemplate() (*template.Template, error) {
	return template.New("error.html").Parse(DefaultErrorHTML)
}

// ParseAdminSettingsTemplate parses and returns the embedded admin settings template
func ParseAdminSettingsTemplate() (*template.Template, error) {
	return template.New("admin_settings.html").Parse(DefaultAdminSettingsHTML)
}

// ParseAdminLoginTemplate parses and returns the embedded admin login template
func ParseAdminLoginTemplate() (*template.Template, error) {
	return template.New("admin_login.html").Parse(DefaultAdminLoginHTML)
}

// ParseAdminChangePasswordTemplate parses and returns the embedded admin change password template
func ParseAdminChangePasswordTemplate() (*template.Template, error) {
	return template.New("admin_change_password.html").Parse(DefaultAdminChangePasswordHTML)
}
