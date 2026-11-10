package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AdminSettingsPayload holds the editable settings from the Admin UI.
type AdminSettingsPayload struct {
	// Upstream IdP
	IdPEntityID    string `json:"idp_entity_id" form:"idp_entity_id"`
	IdPSSOURL      string `json:"idp_sso_url" form:"idp_sso_url"`
	IdPMetadataURL string `json:"idp_metadata_url" form:"idp_metadata_url"`
	IdPCertFile    string `json:"idp_cert_file" form:"idp_cert_file"`

	// Downstream SP (Schneider ITA) & Gateway
	EntityID         string            `json:"entity_id" form:"entity_id"`
	ACSURL           string            `json:"acs_url" form:"acs_url"`
	SSOURL           string            `json:"sso_url" form:"sso_url"`
	SLOURL           string            `json:"slo_url" form:"slo_url"`
	AllowedAudiences []string          `json:"allowed_audiences" form:"allowed_audiences"`
	GroupMapping     map[string]string `json:"group_mapping" form:"group_mapping"`

	// MFA & Policies
	MFADefaultProvider string        `json:"mfa_default_provider" form:"mfa_default_provider"`
	MFAIssuer          string        `json:"mfa_issuer" form:"mfa_issuer"`
	OTPExpiry          time.Duration `json:"otp_expiry" form:"otp_expiry"`
	ResendCooldown     time.Duration `json:"resend_cooldown" form:"resend_cooldown"`
	AllowDummyOTP      bool          `json:"allow_dummy_otp" form:"allow_dummy_otp"`

	// SMTP Email Server
	SMTPHost       string `json:"smtp_host" form:"smtp_host"`
	SMTPPort       int    `json:"smtp_port" form:"smtp_port"`
	SMTPUsername   string `json:"smtp_username" form:"smtp_username"`
	SMTPPassword   string `json:"smtp_password" form:"smtp_password"` // If empty, keep existing password
	SMTPFrom       string `json:"smtp_from" form:"smtp_from"`
	SMTPFromName   string `json:"smtp_from_name" form:"smtp_from_name"`
	SMTPEncryption string `json:"smtp_encryption" form:"smtp_encryption"`
}

// SaveConfig updates the in-memory Config and persists the changes to the specified YAML file.
func SaveConfig(filePath string, cfg *Config, payload *AdminSettingsPayload) error {
	if filePath == "" {
		filePath = "configs/config.yaml"
	}

	// 1. Read existing YAML file to preserve other fields (database, jwt, logging, etc.)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading config file %q: %w", filePath, err)
	}

	// Parse into map to make mutations straightforward and preserve unspecified sections
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("unmarshaling config map: %w", err)
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}

	// Update SAML section
	samlMap, _ := raw["saml"].(map[string]interface{})
	if samlMap == nil {
		samlMap = make(map[string]interface{})
		raw["saml"] = samlMap
	}

	if payload.EntityID != "" {
		samlMap["entity_id"] = strings.TrimSpace(payload.EntityID)
		cfg.SAML.EntityID = samlMap["entity_id"].(string)
	}
	if payload.ACSURL != "" {
		samlMap["acs_url"] = strings.TrimSpace(payload.ACSURL)
		cfg.SAML.ACSURL = samlMap["acs_url"].(string)
	}
	if payload.SSOURL != "" {
		samlMap["sso_url"] = strings.TrimSpace(payload.SSOURL)
		cfg.SAML.SSOURL = samlMap["sso_url"].(string)
	}
	if payload.SLOURL != "" {
		samlMap["slo_url"] = strings.TrimSpace(payload.SLOURL)
		cfg.SAML.SLOURL = samlMap["slo_url"].(string)
	}
	samlMap["idp_entity_id"] = strings.TrimSpace(payload.IdPEntityID)
	cfg.SAML.IdPEntityID = samlMap["idp_entity_id"].(string)

	samlMap["idp_sso_url"] = strings.TrimSpace(payload.IdPSSOURL)
	cfg.SAML.IdPSSOURL = samlMap["idp_sso_url"].(string)

	samlMap["idp_metadata_url"] = strings.TrimSpace(payload.IdPMetadataURL)
	cfg.SAML.IdPMetadataURL = samlMap["idp_metadata_url"].(string)

	if payload.IdPCertFile != "" {
		samlMap["idp_cert_file"] = strings.TrimSpace(payload.IdPCertFile)
		cfg.SAML.IdPCertFile = samlMap["idp_cert_file"].(string)
	}

	if len(payload.AllowedAudiences) > 0 {
		var audiences []interface{}
		var cfgAudiences []string
		for _, aud := range payload.AllowedAudiences {
			trimmed := strings.TrimSpace(aud)
			if trimmed != "" {
				audiences = append(audiences, trimmed)
				cfgAudiences = append(cfgAudiences, trimmed)
			}
		}
		if len(audiences) > 0 {
			samlMap["allowed_audiences"] = audiences
			cfg.SAML.AllowedAudiences = cfgAudiences
		}
	}

	if payload.GroupMapping != nil {
		gm := make(map[string]interface{})
		for k, v := range payload.GroupMapping {
			tk := strings.TrimSpace(k)
			tv := strings.TrimSpace(v)
			if tk != "" && tv != "" {
				gm[tk] = tv
			}
		}
		samlMap["group_mapping"] = gm
		cfg.SAML.GroupMapping = payload.GroupMapping
	}

	// Update MFA section
	mfaMap, _ := raw["mfa"].(map[string]interface{})
	if mfaMap == nil {
		mfaMap = make(map[string]interface{})
		raw["mfa"] = mfaMap
	}
	if payload.MFADefaultProvider != "" {
		mfaMap["default_provider"] = strings.TrimSpace(payload.MFADefaultProvider)
		cfg.MFA.DefaultProvider = mfaMap["default_provider"].(string)
	}
	if payload.MFAIssuer != "" {
		mfaMap["issuer"] = strings.TrimSpace(payload.MFAIssuer)
		cfg.MFA.Issuer = mfaMap["issuer"].(string)
	}
	if payload.OTPExpiry > 0 {
		mfaMap["otp_expiry"] = payload.OTPExpiry.String()
		cfg.MFA.OTPExpiry = payload.OTPExpiry
	}
	if payload.ResendCooldown > 0 {
		mfaMap["resend_cooldown"] = payload.ResendCooldown.String()
		cfg.MFA.ResendCooldown = payload.ResendCooldown
	}
	mfaMap["allow_dummy_otp"] = payload.AllowDummyOTP
	cfg.MFA.AllowDummyOTP = payload.AllowDummyOTP

	// Update SMTP section
	smtpMap, _ := raw["smtp"].(map[string]interface{})
	if smtpMap == nil {
		smtpMap = make(map[string]interface{})
		raw["smtp"] = smtpMap
	}
	smtpMap["host"] = strings.TrimSpace(payload.SMTPHost)
	cfg.SMTP.Host = smtpMap["host"].(string)

	if payload.SMTPPort > 0 {
		smtpMap["port"] = payload.SMTPPort
		cfg.SMTP.Port = payload.SMTPPort
	}
	smtpMap["username"] = strings.TrimSpace(payload.SMTPUsername)
	cfg.SMTP.Username = smtpMap["username"].(string)

	if payload.SMTPPassword != "" {
		smtpMap["password"] = payload.SMTPPassword
		cfg.SMTP.Password = payload.SMTPPassword
	}
	if payload.SMTPFrom != "" {
		smtpMap["from"] = strings.TrimSpace(payload.SMTPFrom)
		cfg.SMTP.From = smtpMap["from"].(string)
	}
	if payload.SMTPFromName != "" {
		smtpMap["from_name"] = strings.TrimSpace(payload.SMTPFromName)
		cfg.SMTP.FromName = smtpMap["from_name"].(string)
	}
	if payload.SMTPEncryption != "" {
		smtpMap["encryption"] = strings.ToLower(strings.TrimSpace(payload.SMTPEncryption))
		cfg.SMTP.Encryption = smtpMap["encryption"].(string)
	}

	// 3. Write back cleanly
	updatedData, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshaling updated config: %w", err)
	}

	// Atomic write via temp file in same directory
	dir := filepath.Dir(filePath)
	tmpFile, err := os.CreateTemp(dir, "config-*.yaml")
	if err != nil {
		return os.WriteFile(filePath, updatedData, 0644)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := tmpFile.Write(updatedData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp config: %w", err)
	}

	if err := os.Rename(tmpName, filePath); err != nil {
		return os.WriteFile(filePath, updatedData, 0644)
	}

	return nil
}

