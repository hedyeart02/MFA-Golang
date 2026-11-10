package handler

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/ita"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/web"
	"go.uber.org/zap"
)

// CertDetails holds parsed metadata about a certificate.
type CertDetails struct {
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	DaysLeft  int
	IsExpired bool
	SHA256    string
}

// AdminSettingsViewModel models the view data passed to admin_settings.html.
type AdminSettingsViewModel struct {
	Settings            *config.AdminSettingsPayload
	Port                int
	AllowedAudiencesStr string
	CertInfo            CertDetails
	AuthorizedUsers     []mfa.AuthorizedUser
	ServerTimeUTC       string
	ServerTimeLocal     string
	SuccessMessage      string
	ErrorMessage        string
}

// HandleAdminSettingsGet renders the dedicated settings admin panel.
func (h *SAMLHandler) HandleAdminSettingsGet(c *gin.Context) {
	vm := h.buildAdminViewModel("", "")
	h.renderAdminSettings(c, vm)
}

// HandleAdminSettingsPost processes form submissions from the admin panel and persists to YAML.
func (cHandler *SAMLHandler) HandleAdminSettingsPost(c *gin.Context) {
	var payload config.AdminSettingsPayload

	// Upstream IdP
	payload.IdPEntityID = strings.TrimSpace(c.PostForm("idp_entity_id"))
	payload.IdPSSOURL = strings.TrimSpace(c.PostForm("idp_sso_url"))
	payload.IdPMetadataURL = strings.TrimSpace(c.PostForm("idp_metadata_url"))
	payload.IdPCertFile = strings.TrimSpace(c.PostForm("idp_cert_file"))

	// Downstream SP (ITA) & Gateway
	payload.EntityID = strings.TrimSpace(c.PostForm("entity_id"))
	payload.ACSURL = strings.TrimSpace(c.PostForm("acs_url"))
	payload.SSOURL = strings.TrimSpace(c.PostForm("sso_url"))
	payload.SLOURL = strings.TrimSpace(c.PostForm("slo_url"))

	// Audiences
	audiencesRaw := c.PostForm("allowed_audiences_str")
	if audiencesRaw != "" {
		parts := strings.Split(audiencesRaw, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				payload.AllowedAudiences = append(payload.AllowedAudiences, trimmed)
			}
		}
	}

	// Group Mapping
	keys := c.PostFormArray("group_map_key[]")
	vals := c.PostFormArray("group_map_val[]")
	payload.GroupMapping = make(map[string]string)
	for i := 0; i < len(keys) && i < len(vals); i++ {
		tk := strings.TrimSpace(keys[i])
		tv := strings.TrimSpace(vals[i])
		if tk != "" && tv != "" {
			payload.GroupMapping[tk] = tv
		}
	}

	// MFA Policies
	payload.MFADefaultProvider = strings.TrimSpace(c.PostForm("mfa_default_provider"))
	payload.MFAIssuer = strings.TrimSpace(c.PostForm("mfa_issuer"))
	if otpExpStr := strings.TrimSpace(c.PostForm("otp_expiry")); otpExpStr != "" {
		if d, err := time.ParseDuration(otpExpStr); err == nil && d > 0 {
			payload.OTPExpiry = d
		}
	}
	if resendCooldownStr := strings.TrimSpace(c.PostForm("resend_cooldown")); resendCooldownStr != "" {
		if d, err := time.ParseDuration(resendCooldownStr); err == nil && d > 0 {
			payload.ResendCooldown = d
		}
	}
	payload.AllowDummyOTP = c.PostForm("allow_dummy_otp") == "true"

	// SMTP Server
	payload.SMTPHost = strings.TrimSpace(c.PostForm("smtp_host"))
	if p, err := strconv.Atoi(c.PostForm("smtp_port")); err == nil && p > 0 {
		payload.SMTPPort = p
	}
	payload.SMTPUsername = strings.TrimSpace(c.PostForm("smtp_username"))
	payload.SMTPPassword = c.PostForm("smtp_password") // if empty, SaveConfig preserves current
	payload.SMTPFrom = strings.TrimSpace(c.PostForm("smtp_from"))
	payload.SMTPFromName = strings.TrimSpace(c.PostForm("smtp_from_name"))
	payload.SMTPEncryption = strings.ToLower(strings.TrimSpace(c.PostForm("smtp_encryption")))

	// ITA API Integration & User Whitelist
	payload.ITAAPIURL = strings.TrimSpace(c.PostForm("ita_api_url"))
	payload.ITAAPIUsername = strings.TrimSpace(c.PostForm("ita_api_username"))
	payload.ITAAPIPassword = c.PostForm("ita_api_password") // if empty, SaveConfig preserves current
	payload.ITAEnforceWhitelist = c.PostForm("ita_enforce_whitelist") == "true"

	// Persist to configs/config.yaml and update runtime in-memory
	configPath := "configs/config.yaml"
	if err := config.SaveConfig(configPath, cHandler.cfg, &payload); err != nil {
		cHandler.logger.Error("failed saving config file", zap.Error(err))
		vm := cHandler.buildAdminViewModel("", fmt.Sprintf("Failed to save configuration: %v", err))
		cHandler.renderAdminSettings(c, vm)
		return
	}

	// Hot-reload SMTP sender on active MFA service
	newSMTPSender := mfa.NewSMTPSender(
		cHandler.cfg.SMTP.Host,
		cHandler.cfg.SMTP.Port,
		cHandler.cfg.SMTP.Username,
		cHandler.cfg.SMTP.Password,
		cHandler.cfg.SMTP.From,
		cHandler.cfg.SMTP.FromName,
		cHandler.cfg.SMTP.Encryption,
		cHandler.logger,
	)
	cHandler.mfaService.UpdateSMTPSender(newSMTPSender)

	cHandler.logger.Info("admin settings successfully updated and saved to config",
		zap.String("path", configPath),
		zap.String("entity_id", cHandler.cfg.SAML.EntityID),
		zap.String("acs_url", cHandler.cfg.SAML.ACSURL),
		zap.Bool("enforce_whitelist", cHandler.cfg.ITA.EnforceUserWhitelist),
	)

	vm := cHandler.buildAdminViewModel("Configuration updated successfully and saved to "+configPath, "")
	cHandler.renderAdminSettings(c, vm)
}

// HandleAdminITASyncPost connects to ITA API, fetches current users, and updates SQLite.
func (h *SAMLHandler) HandleAdminITASyncPost(c *gin.Context) {
	var req struct {
		APIURL      string `json:"api_url"`
		APIUsername string `json:"api_username"`
		APIPassword string `json:"api_password"`
	}
	_ = c.ShouldBindJSON(&req)

	apiURL := req.APIURL
	if apiURL == "" {
		apiURL = h.cfg.ITA.APIURL
	}
	username := req.APIUsername
	if username == "" {
		username = h.cfg.ITA.APIUsername
	}
	password := req.APIPassword
	if password == "" {
		password = h.cfg.ITA.APIPassword
	}

	itaClient := ita.NewClient(15 * time.Second)
	users, err := itaClient.FetchUsers(c.Request.Context(), apiURL, username, password)
	if err != nil {
		h.logger.Warn("ITA user sync failed", zap.Error(err), zap.String("api_url", apiURL))
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if h.mfaService != nil && h.mfaService.Storage() != nil {
		if err := h.mfaService.Storage().SaveAuthorizedUsers(c.Request.Context(), users); err != nil {
			h.logger.Error("saving synced ITA users failed", zap.Error(err))
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"error":   fmt.Sprintf("Failed to save synced users: %v", err),
			})
			return
		}
	}

	h.logger.Info("successfully synced users from Schneider ITA",
		zap.Int("user_count", len(users)),
		zap.String("api_url", apiURL),
	)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Successfully synced %d users from Schneider IT Advisor.", len(users)),
		"count":   len(users),
		"users":   users,
	})
}

// HandleAdminUserAddPost manually adds an authorized user.
func (h *SAMLHandler) HandleAdminUserAddPost(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		FullName string `json:"full_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Username) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Username is required"})
		return
	}

	user := mfa.AuthorizedUser{
		Username: strings.TrimSpace(req.Username),
		Email:    strings.TrimSpace(req.Email),
		FullName: strings.TrimSpace(req.FullName),
		Source:   "manual",
	}

	if h.mfaService != nil && h.mfaService.Storage() != nil {
		if err := h.mfaService.Storage().AddAuthorizedUser(c.Request.Context(), user); err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("User '%s' was successfully added.", user.Username)})
}

// HandleAdminUserDeletePost removes a user from authorized_users table.
func (h *SAMLHandler) HandleAdminUserDeletePost(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Username) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Username is required"})
		return
	}

	if h.mfaService != nil && h.mfaService.Storage() != nil {
		if err := h.mfaService.Storage().DeleteAuthorizedUser(c.Request.Context(), req.Username); err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("User '%s' has been removed.", req.Username)})
}

// HandleAdminTestEmailPost executes a real-time SMTP test and returns JSON status.
func (h *SAMLHandler) HandleAdminTestEmailPost(c *gin.Context) {
	var req struct {
		Recipient      string `json:"recipient"`
		SMTPHost       string `json:"smtp_host"`
		SMTPPort       int    `json:"smtp_port"`
		SMTPUsername   string `json:"smtp_username"`
		SMTPPassword   string `json:"smtp_password"`
		SMTPFrom       string `json:"smtp_from"`
		SMTPFromName   string `json:"smtp_from_name"`
		SMTPEncryption string `json:"smtp_encryption"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Invalid request payload: " + err.Error()})
		return
	}

	if strings.TrimSpace(req.Recipient) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "Recipient email address is required."})
		return
	}

	start := time.Now()
	err := h.mfaService.TestEmail(
		c.Request.Context(),
		req.SMTPHost,
		req.SMTPPort,
		req.SMTPUsername,
		req.SMTPPassword,
		req.SMTPFrom,
		req.SMTPFromName,
		req.SMTPEncryption,
		req.Recipient,
	)
	duration := time.Since(start).Round(time.Millisecond)

	if err != nil {
		h.logger.Warn("admin test email failed",
			zap.String("recipient", req.Recipient),
			zap.String("host", req.SMTPHost),
			zap.Error(err),
		)
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   fmt.Sprintf("%v (Attempted in %v)", err, duration),
		})
		return
	}

	h.logger.Info("admin test email sent successfully",
		zap.String("recipient", req.Recipient),
		zap.String("host", req.SMTPHost),
		zap.Duration("duration", duration),
	)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Test email delivered successfully to %s in %v!", req.Recipient, duration),
	})
}

// HandleAdminCertDownload allows downloading public certificates directly from the UI.
func (h *SAMLHandler) HandleAdminCertDownload(c *gin.Context) {
	certType := c.Query("type")
	filePath := h.cfg.SAML.CertFile
	filename := "saml-signing.crt"

	if certType == "server" {
		filePath = h.cfg.TLS.CertFile
		filename = "server.crt"
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.String(http.StatusNotFound, "Certificate file not found: %s", filePath)
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "application/x-x509-ca-cert")
	c.File(filePath)
}

func (h *SAMLHandler) buildAdminViewModel(successMsg, errorMsg string) *AdminSettingsViewModel {
	payload := &config.AdminSettingsPayload{
		IdPEntityID:           h.cfg.SAML.IdPEntityID,
		IdPSSOURL:             h.cfg.SAML.IdPSSOURL,
		IdPMetadataURL:        h.cfg.SAML.IdPMetadataURL,
		IdPCertFile:           h.cfg.SAML.IdPCertFile,
		EntityID:              h.cfg.SAML.EntityID,
		ACSURL:                h.cfg.SAML.ACSURL,
		SSOURL:                h.cfg.SAML.SSOURL,
		SLOURL:                h.cfg.SAML.SLOURL,
		AllowedAudiences:      h.cfg.SAML.AllowedAudiences,
		GroupMapping:          h.cfg.SAML.GroupMapping,
		MFADefaultProvider:    h.cfg.MFA.DefaultProvider,
		MFAIssuer:             h.cfg.MFA.Issuer,
		OTPExpiry:             h.cfg.MFA.OTPExpiry,
		ResendCooldown:        h.cfg.MFA.ResendCooldown,
		AllowDummyOTP:         h.cfg.MFA.AllowDummyOTP,
		SMTPHost:              h.cfg.SMTP.Host,
		SMTPPort:              h.cfg.SMTP.Port,
		SMTPUsername:          h.cfg.SMTP.Username,
		SMTPFrom:              h.cfg.SMTP.From,
		SMTPFromName:          h.cfg.SMTP.FromName,
		SMTPEncryption:        h.cfg.SMTP.Encryption,
		ITAAPIURL:             h.cfg.ITA.APIURL,
		ITAAPIUsername:        h.cfg.ITA.APIUsername,
		ITAEnforceWhitelist:   h.cfg.ITA.EnforceUserWhitelist,
		ITAManualAllowedUsers: h.cfg.ITA.ManualAllowedUsers,
	}

	now := time.Now()
	certInfo := parseCertDetails(h.cfg.SAML.CertFile)

	var authorizedUsers []mfa.AuthorizedUser
	if h.mfaService != nil && h.mfaService.Storage() != nil {
		users, err := h.mfaService.Storage().ListAuthorizedUsers(context.Background())
		if err == nil {
			authorizedUsers = users
		}
	}

	return &AdminSettingsViewModel{
		Settings:            payload,
		Port:                h.cfg.Server.Port,
		AllowedAudiencesStr: strings.Join(h.cfg.SAML.AllowedAudiences, ", "),
		CertInfo:            certInfo,
		AuthorizedUsers:     authorizedUsers,
		ServerTimeUTC:       now.UTC().Format("2006-01-02 15:04:05 UTC"),
		ServerTimeLocal:     now.Format("2006-01-02 15:04:05 MST"),
		SuccessMessage:      successMsg,
		ErrorMessage:        errorMsg,
	}
}

func (h *SAMLHandler) renderAdminSettings(c *gin.Context, vm *AdminSettingsViewModel) {
	tmplPath := filepath.Join("web", "templates", "admin_settings.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		tmpl, err = web.ParseAdminSettingsTemplate()
	}
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to load admin settings template: %v", err)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(c.Writer, vm); err != nil {
		h.logger.Error("failed executing admin settings template", zap.Error(err))
	}
}

func parseCertDetails(certPath string) CertDetails {
	details := CertDetails{
		Subject:   "N/A",
		Issuer:    "N/A",
		DaysLeft:  0,
		NotBefore: "N/A",
		NotAfter:  "N/A",
	}
	if certPath == "" {
		return details
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return details
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return details
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return details
	}

	details.Subject = cert.Subject.CommonName
	if details.Subject == "" {
		details.Subject = cert.Subject.String()
	}
	details.Issuer = cert.Issuer.CommonName
	if details.Issuer == "" {
		details.Issuer = cert.Issuer.String()
	}
	details.NotBefore = cert.NotBefore.Format("2006-01-02 15:04:05 UTC")
	details.NotAfter = cert.NotAfter.Format("2006-01-02 15:04:05 UTC")

	now := time.Now()
	if now.After(cert.NotAfter) {
		details.IsExpired = true
		details.DaysLeft = 0
	} else {
		details.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	var hexParts []string
	for _, b := range fingerprint {
		hexParts = append(hexParts, fmt.Sprintf("%02X", b))
	}
	details.SHA256 = strings.Join(hexParts, ":")

	return details
}
