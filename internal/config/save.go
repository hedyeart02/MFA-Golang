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

	// ITA User Sync & Whitelist Guard
	ITAAPIURL             string   `json:"ita_api_url" form:"ita_api_url"`
	ITAAPIUsername        string   `json:"ita_api_username" form:"ita_api_username"`
	ITAAPIPassword        string   `json:"ita_api_password" form:"ita_api_password"`
	ITAEnforceWhitelist   bool     `json:"ita_enforce_whitelist" form:"ita_enforce_whitelist"`
	ITAManualAllowedUsers []string `json:"ita_manual_allowed_users" form:"ita_manual_allowed_users"`
}

// ApplyAdminSettings updates the in-memory Config from an AdminSettingsPayload without touching disk.
func ApplyAdminSettings(cfg *Config, payload *AdminSettingsPayload) {
	if cfg == nil || payload == nil {
		return
	}

	if v := strings.TrimSpace(payload.EntityID); v != "" {
		cfg.SAML.EntityID = v
	}
	if v := strings.TrimSpace(payload.ACSURL); v != "" {
		cfg.SAML.ACSURL = v
	}
	if v := strings.TrimSpace(payload.SSOURL); v != "" {
		cfg.SAML.SSOURL = v
	}
	if v := strings.TrimSpace(payload.SLOURL); v != "" {
		cfg.SAML.SLOURL = v
	}
	cfg.SAML.IdPEntityID = strings.TrimSpace(payload.IdPEntityID)
	cfg.SAML.IdPSSOURL = strings.TrimSpace(payload.IdPSSOURL)
	cfg.SAML.IdPMetadataURL = strings.TrimSpace(payload.IdPMetadataURL)
	if v := strings.TrimSpace(payload.IdPCertFile); v != "" {
		cfg.SAML.IdPCertFile = v
	}

	if len(payload.AllowedAudiences) > 0 {
		var cfgAudiences []string
		for _, aud := range payload.AllowedAudiences {
			if trimmed := strings.TrimSpace(aud); trimmed != "" {
				cfgAudiences = append(cfgAudiences, trimmed)
			}
		}
		if len(cfgAudiences) > 0 {
			cfg.SAML.AllowedAudiences = cfgAudiences
		}
	}

	if payload.GroupMapping != nil {
		gm := make(map[string]string)
		for k, v := range payload.GroupMapping {
			tk := strings.TrimSpace(k)
			tv := strings.TrimSpace(v)
			if tk != "" && tv != "" {
				gm[tk] = tv
			}
		}
		cfg.SAML.GroupMapping = gm
	}

	if v := strings.TrimSpace(payload.MFADefaultProvider); v != "" {
		cfg.MFA.DefaultProvider = v
	}
	if v := strings.TrimSpace(payload.MFAIssuer); v != "" {
		cfg.MFA.Issuer = v
	}
	if payload.OTPExpiry > 0 {
		cfg.MFA.OTPExpiry = payload.OTPExpiry
	}
	if payload.ResendCooldown > 0 {
		cfg.MFA.ResendCooldown = payload.ResendCooldown
	}
	cfg.MFA.AllowDummyOTP = payload.AllowDummyOTP

	cfg.SMTP.Host = strings.TrimSpace(payload.SMTPHost)
	if payload.SMTPPort > 0 {
		cfg.SMTP.Port = payload.SMTPPort
	}
	cfg.SMTP.Username = strings.TrimSpace(payload.SMTPUsername)
	if payload.SMTPPassword != "" {
		cfg.SMTP.Password = payload.SMTPPassword
	}
	if v := strings.TrimSpace(payload.SMTPFrom); v != "" {
		cfg.SMTP.From = v
	}
	if v := strings.TrimSpace(payload.SMTPFromName); v != "" {
		cfg.SMTP.FromName = v
	}
	if v := strings.ToLower(strings.TrimSpace(payload.SMTPEncryption)); v != "" {
		cfg.SMTP.Encryption = v
	}

	if v := strings.TrimSpace(payload.ITAAPIURL); v != "" {
		cfg.ITA.APIURL = v
	}
	cfg.ITA.APIUsername = strings.TrimSpace(payload.ITAAPIUsername)
	if payload.ITAAPIPassword != "" {
		cfg.ITA.APIPassword = payload.ITAAPIPassword
	}
	cfg.ITA.EnforceUserWhitelist = payload.ITAEnforceWhitelist

	if len(payload.ITAManualAllowedUsers) > 0 {
		var cfgList []string
		for _, u := range payload.ITAManualAllowedUsers {
			if tu := strings.TrimSpace(u); tu != "" {
				cfgList = append(cfgList, tu)
			}
		}
		if len(cfgList) > 0 {
			cfg.ITA.ManualAllowedUsers = cfgList
		}
	}
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

	ApplyAdminSettings(cfg, payload)

	// Update SAML section
	samlMap, _ := raw["saml"].(map[string]interface{})
	if samlMap == nil {
		samlMap = make(map[string]interface{})
		raw["saml"] = samlMap
	}

	if payload.EntityID != "" {
		samlMap["entity_id"] = cfg.SAML.EntityID
	}
	if payload.ACSURL != "" {
		samlMap["acs_url"] = cfg.SAML.ACSURL
	}
	if payload.SSOURL != "" {
		samlMap["sso_url"] = cfg.SAML.SSOURL
	}
	if payload.SLOURL != "" {
		samlMap["slo_url"] = cfg.SAML.SLOURL
	}
	samlMap["idp_entity_id"] = cfg.SAML.IdPEntityID
	samlMap["idp_sso_url"] = cfg.SAML.IdPSSOURL
	samlMap["idp_metadata_url"] = cfg.SAML.IdPMetadataURL

	if payload.IdPCertFile != "" {
		samlMap["idp_cert_file"] = cfg.SAML.IdPCertFile
	}

	if len(payload.AllowedAudiences) > 0 && len(cfg.SAML.AllowedAudiences) > 0 {
		audiences := make([]interface{}, 0, len(cfg.SAML.AllowedAudiences))
		for _, aud := range cfg.SAML.AllowedAudiences {
			audiences = append(audiences, aud)
		}
		samlMap["allowed_audiences"] = audiences
	}

	if payload.GroupMapping != nil {
		gm := make(map[string]interface{}, len(cfg.SAML.GroupMapping))
		for k, v := range cfg.SAML.GroupMapping {
			gm[k] = v
		}
		samlMap["group_mapping"] = gm
	}

	// Update MFA section
	mfaMap, _ := raw["mfa"].(map[string]interface{})
	if mfaMap == nil {
		mfaMap = make(map[string]interface{})
		raw["mfa"] = mfaMap
	}
	if payload.MFADefaultProvider != "" {
		mfaMap["default_provider"] = cfg.MFA.DefaultProvider
	}
	if payload.MFAIssuer != "" {
		mfaMap["issuer"] = cfg.MFA.Issuer
	}
	if payload.OTPExpiry > 0 {
		mfaMap["otp_expiry"] = cfg.MFA.OTPExpiry.String()
	}
	if payload.ResendCooldown > 0 {
		mfaMap["resend_cooldown"] = cfg.MFA.ResendCooldown.String()
	}
	mfaMap["allow_dummy_otp"] = cfg.MFA.AllowDummyOTP

	// Update SMTP section
	smtpMap, _ := raw["smtp"].(map[string]interface{})
	if smtpMap == nil {
		smtpMap = make(map[string]interface{})
		raw["smtp"] = smtpMap
	}
	smtpMap["host"] = cfg.SMTP.Host
	if payload.SMTPPort > 0 {
		smtpMap["port"] = cfg.SMTP.Port
	}
	smtpMap["username"] = cfg.SMTP.Username
	if payload.SMTPPassword != "" {
		smtpMap["password"] = cfg.SMTP.Password
	}
	if payload.SMTPFrom != "" {
		smtpMap["from"] = cfg.SMTP.From
	}
	if payload.SMTPFromName != "" {
		smtpMap["from_name"] = cfg.SMTP.FromName
	}
	if payload.SMTPEncryption != "" {
		smtpMap["encryption"] = cfg.SMTP.Encryption
	}

	// Update ITA section
	itaMap, _ := raw["ita"].(map[string]interface{})
	if itaMap == nil {
		itaMap = make(map[string]interface{})
		raw["ita"] = itaMap
	}
	if payload.ITAAPIURL != "" {
		itaMap["api_url"] = cfg.ITA.APIURL
	}
	itaMap["api_username"] = cfg.ITA.APIUsername
	if payload.ITAAPIPassword != "" {
		itaMap["api_password"] = cfg.ITA.APIPassword
	}
	itaMap["enforce_user_whitelist"] = cfg.ITA.EnforceUserWhitelist

	if len(payload.ITAManualAllowedUsers) > 0 && len(cfg.ITA.ManualAllowedUsers) > 0 {
		list := make([]interface{}, 0, len(cfg.ITA.ManualAllowedUsers))
		for _, u := range cfg.ITA.ManualAllowedUsers {
			list = append(list, u)
		}
		itaMap["manual_allowed_users"] = list
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

