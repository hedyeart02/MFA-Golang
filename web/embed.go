package web

import (
	"embed"
	"html/template"
	"io/fs"
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

//go:embed templates/corporate_login.html
var DefaultCorporateLoginHTML string

//go:embed static
var staticFiles embed.FS

// StaticFS returns the embedded static assets filesystem rooted at static/.
func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}

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

// ParseCorporateLoginTemplate parses and returns the embedded corporate sign-in template
func ParseCorporateLoginTemplate() (*template.Template, error) {
	return template.New("corporate_login.html").Parse(DefaultCorporateLoginHTML)
}
