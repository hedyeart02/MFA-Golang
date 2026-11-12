package mfa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hidayat-SE/samlguard/internal/config"
	"go.uber.org/zap"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mockHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestNormalizePhoneNumberAndMask(t *testing.T) {
	cases := []struct {
		raw      string
		wantNorm string
		wantMask string
	}{
		{" +60 12-345 6789 ", "+60123456789", "+60*****6789"},
		{"+1 (555) 234-5678", "+15552345678", "+15*****5678"},
		{"012-9988776", "0129988776", "01****8776"},
		{"1234", "1234", "****"},
		{"", "", "***"},
	}
	for _, tc := range cases {
		gotNorm := NormalizePhoneNumber(tc.raw)
		if gotNorm != tc.wantNorm {
			t.Errorf("NormalizePhoneNumber(%q) = %q, want %q", tc.raw, gotNorm, tc.wantNorm)
		}
		gotMask := MaskPhone(tc.raw)
		if gotMask != tc.wantMask {
			t.Errorf("MaskPhone(%q) = %q, want %q", tc.raw, gotMask, tc.wantMask)
		}
	}
}

func TestSMSSender_Gateways(t *testing.T) {
	t.Run("Twilio", func(t *testing.T) {
		var gotUser, gotPass, gotAuth, gotPath string
		var gotForm url.Values

		sender := NewSMSSender(config.SMSConfig{
			Provider:        "twilio",
			APIURL:          "https://api.twilio.test/2010-04-01/Accounts/{account_id}/Messages.json",
			AccountID:       "AC123",
			AuthToken:       "tok-secret",
			SenderID:        "+15550001111",
			MessageTemplate: "Code is {code}",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotUser, gotPass, _ = r.BasicAuth()
			gotAuth = r.Header.Get("Authorization")
			gotPath = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			gotForm, _ = url.ParseQuery(string(body))
			return mockHTTPResponse(http.StatusCreated, `{"sid":"SM123"}`), nil
		})})

		if err := sender.Send(context.Background(), "+6012-3456789", "482910"); err != nil {
			t.Fatalf("Twilio Send failed: %v", err)
		}
		if !strings.HasSuffix(gotPath, "/Accounts/AC123/Messages.json") {
			t.Errorf("unexpected Twilio path: %s", gotPath)
		}
		if gotUser != "AC123" || gotPass != "tok-secret" || !strings.HasPrefix(gotAuth, "Basic ") {
			t.Errorf("unexpected Twilio BasicAuth: user=%q pass=%q", gotUser, gotPass)
		}
		if gotForm.Get("To") != "+60123456789" || gotForm.Get("From") != "+15550001111" || gotForm.Get("Body") != "Code is 482910" {
			t.Errorf("unexpected Twilio form: %v", gotForm)
		}
	})

	t.Run("iSMS POST & GET", func(t *testing.T) {
		var gotForm url.Values

		sender := NewSMSSender(config.SMSConfig{
			Provider:  "isms",
			APIURL:    "https://isms.test/isms_send_all_id.php",
			AccountID: "isms_user",
			AuthToken: "isms_pass",
			SenderID:  "SAMLGuard",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				gotForm = r.URL.Query()
			} else {
				body, _ := io.ReadAll(r.Body)
				gotForm, _ = url.ParseQuery(string(body))
			}
			return mockHTTPResponse(http.StatusOK, "2000 = SUCCESS"), nil
		})})

		if err := sender.Send(context.Background(), "+60123456789", "654321"); err != nil {
			t.Fatalf("iSMS POST Send failed: %v", err)
		}
		if gotForm.Get("un") != "isms_user" || gotForm.Get("pwd") != "isms_pass" || gotForm.Get("dstno") != "60123456789" || gotForm.Get("sendid") != "SAMLGuard" {
			t.Errorf("unexpected iSMS form: %v", gotForm)
		}
		if !strings.Contains(gotForm.Get("msg"), "654321") {
			t.Errorf("expected iSMS msg to contain OTP code, got %q", gotForm.Get("msg"))
		}

		sender.cfg.HTTPMethod = "GET"
		if err := sender.Send(context.Background(), "+60123456789", "999111"); err != nil {
			t.Fatalf("iSMS GET Send failed: %v", err)
		}
		if !strings.Contains(gotForm.Get("msg"), "999111") {
			t.Errorf("expected iSMS GET query msg to contain 999111, got %q", gotForm.Get("msg"))
		}
	})

	t.Run("SendQuick POST & Error Rejection", func(t *testing.T) {
		var gotUser, gotPass string
		var gotForm url.Values
		returnErr := false

		sender := NewSMSSender(config.SMSConfig{
			Provider:        "sendquick",
			APIURL:          "https://sendquick.test/sq/sendmsg.php",
			AccountID:       "sq_admin",
			AuthToken:       "sq_secret",
			SenderID:        "SAMLGuard",
			HTTPMethod:      "POST",
			MessageTemplate: "Your code: {{code}}",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotUser, gotPass, _ = r.BasicAuth()
			body, _ := io.ReadAll(r.Body)
			gotForm, _ = url.ParseQuery(string(body))
			if returnErr {
				return mockHTTPResponse(http.StatusOK, "ERR: INVALID USER OR PASSWORD"), nil
			}
			return mockHTTPResponse(http.StatusOK, "OK: Queued 1 message"), nil
		})})

		if err := sender.Send(context.Background(), "+6591234567", "778899"); err != nil {
			t.Fatalf("SendQuick Send failed: %v", err)
		}
		if gotUser != "sq_admin" || gotPass != "sq_secret" {
			t.Errorf("unexpected SendQuick BasicAuth: %q / %q", gotUser, gotPass)
		}
		if gotForm.Get("username") != "sq_admin" || gotForm.Get("passwd") != "sq_secret" ||
			gotForm.Get("tar_num") != "+6591234567" || gotForm.Get("tar_mode") != "text" ||
			gotForm.Get("tar_msg") != "Your code: 778899" || gotForm.Get("tar_sender") != "SAMLGuard" {
			t.Errorf("unexpected SendQuick payload: %v", gotForm)
		}

		returnErr = true
		if err := sender.Send(context.Background(), "+6591234567", "778899"); err == nil || !strings.Contains(err.Error(), "SendQuick gateway error") {
			t.Fatalf("expected SendQuick ERR response error, got: %v", err)
		}
	})

	t.Run("SMSEagle Hardware Login & AccessToken", func(t *testing.T) {
		var gotForm url.Values
		var gotHeader string
		returnErr := false

		sender := NewSMSSender(config.SMSConfig{
			Provider:   "smseagle",
			APIURL:     "https://smseagle.corp.local/index.php/http_api/send_sms",
			AccountID:  "eagle_admin",
			AuthToken:  "eagle_pass",
			HTTPMethod: "POST",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotHeader = r.Header.Get("access-token")
			if r.Method == http.MethodGet {
				gotForm = r.URL.Query()
			} else {
				body, _ := io.ReadAll(r.Body)
				gotForm, _ = url.ParseQuery(string(body))
			}
			if returnErr {
				return mockHTTPResponse(http.StatusOK, "Invalid login or password"), nil
			}
			return mockHTTPResponse(http.StatusOK, "OK; ID=42"), nil
		})})

		if err := sender.Send(context.Background(), "+60123456789", "246810"); err != nil {
			t.Fatalf("SMSEagle login Send failed: %v", err)
		}
		if gotForm.Get("login") != "eagle_admin" || gotForm.Get("pass") != "eagle_pass" || gotForm.Get("to") != "+60123456789" {
			t.Errorf("unexpected SMSEagle form payload: %v", gotForm)
		}

		// Token-only mode
		sender.cfg.AccountID = ""
		sender.cfg.AuthToken = "eagle-api-token-99"
		if err := sender.Send(context.Background(), "+60123456789", "135791"); err != nil {
			t.Fatalf("SMSEagle access-token Send failed: %v", err)
		}
		if gotHeader != "eagle-api-token-99" || gotForm.Get("access_token") != "eagle-api-token-99" {
			t.Errorf("expected SMSEagle access-token header & param, got header=%q form=%v", gotHeader, gotForm)
		}

		returnErr = true
		if err := sender.Send(context.Background(), "+60123456789", "135791"); err == nil || !strings.Contains(err.Error(), "SMSEagle gateway error") {
			t.Fatalf("expected SMSEagle gateway error rejection, got: %v", err)
		}
	})

	t.Run("MultiTech iSMS Hardware", func(t *testing.T) {
		var gotQuery url.Values
		returnErr := false

		sender := NewSMSSender(config.SMSConfig{
			Provider:   "multitech",
			APIURL:     "https://multitech.corp.local/sendmsg",
			AccountID:  "mt_admin",
			AuthToken:  "mt_secret",
			HTTPMethod: "GET",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotQuery = r.URL.Query()
			if returnErr {
				return mockHTTPResponse(http.StatusOK, "Err: 604 Invalid username/password"), nil
			}
			return mockHTTPResponse(http.StatusOK, "OK\r\nID: 19"), nil
		})})

		if err := sender.Send(context.Background(), "+15551234567", "556677"); err != nil {
			t.Fatalf("MultiTech Send failed: %v", err)
		}
		if gotQuery.Get("user") != "mt_admin" || gotQuery.Get("passwd") != "mt_secret" || gotQuery.Get("cat") != "1" || gotQuery.Get("to") != "+15551234567" {
			t.Errorf("unexpected MultiTech query params: %v", gotQuery)
		}

		returnErr = true
		if err := sender.Send(context.Background(), "+15551234567", "556677"); err == nil || !strings.Contains(err.Error(), "MultiTech gateway error") {
			t.Fatalf("expected MultiTech error rejection, got: %v", err)
		}
	})

	t.Run("Teltonika RUT/TRB Hardware", func(t *testing.T) {
		var gotQuery url.Values
		returnErr := false

		sender := NewSMSSender(config.SMSConfig{
			Provider:   "teltonika",
			APIURL:     "https://teltonika.corp.local/cgi-bin/sms_send",
			AccountID:  "user1",
			AuthToken:  "rut_pass",
			HTTPMethod: "GET",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotQuery = r.URL.Query()
			if returnErr {
				return mockHTTPResponse(http.StatusOK, "Invalid username or password"), nil
			}
			return mockHTTPResponse(http.StatusOK, "OK"), nil
		})})

		if err := sender.Send(context.Background(), "+60123456789", "889900"); err != nil {
			t.Fatalf("Teltonika Send failed: %v", err)
		}
		if gotQuery.Get("username") != "user1" || gotQuery.Get("password") != "rut_pass" || gotQuery.Get("number") != "+60123456789" {
			t.Errorf("unexpected Teltonika query params: %v", gotQuery)
		}

		returnErr = true
		if err := sender.Send(context.Background(), "+60123456789", "889900"); err == nil || !strings.Contains(err.Error(), "Teltonika gateway error") {
			t.Fatalf("expected Teltonika error rejection, got: %v", err)
		}
	})

	t.Run("Vonage JSON & Status Failure", func(t *testing.T) {
		var gotBody map[string]string
		statusCode := "0"

		sender := NewSMSSender(config.SMSConfig{
			Provider:  "vonage",
			APIURL:    "https://rest.nexmo.test/sms/json",
			AccountID: "v_key",
			AuthToken: "v_sec",
			SenderID:  "SAMLGuard",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
			return mockHTTPResponse(http.StatusOK, `{"messages":[{"status":"`+statusCode+`","error-text":"bad api key"}]}`), nil
		})})

		if err := sender.Send(context.Background(), "+60123456789", "112233"); err != nil {
			t.Fatalf("Vonage Send failed: %v", err)
		}
		if gotBody["api_key"] != "v_key" || gotBody["api_secret"] != "v_sec" || gotBody["to"] != "60123456789" || !strings.Contains(gotBody["text"], "112233") {
			t.Errorf("unexpected Vonage JSON body: %v", gotBody)
		}

		statusCode = "4"
		if err := sender.Send(context.Background(), "+60123456789", "112233"); err == nil || !strings.Contains(err.Error(), "Vonage gateway error") {
			t.Fatalf("expected Vonage error when message status != 0, got: %v", err)
		}
	})

	t.Run("Custom HTTP Bearer & TestSMS", func(t *testing.T) {
		var gotAuth string
		var gotBody map[string]string

		sender := NewSMSSender(config.SMSConfig{
			Provider:  "custom",
			APIURL:    "https://custom-sms.test/send",
			AuthToken: "bearer-tok-123",
			SenderID:  "SAMLGuard",
		}, "production", zap.NewNop())
		sender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotAuth = r.Header.Get("Authorization")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
			return mockHTTPResponse(http.StatusOK, `{"ok":true}`), nil
		})})

		if err := sender.SendTestSMS(context.Background(), "+60123456789"); err != nil {
			t.Fatalf("Custom SendTestSMS failed: %v", err)
		}
		if gotAuth != "Bearer bearer-tok-123" || gotBody["to"] != "+60123456789" || gotBody["code"] != "000000" {
			t.Errorf("unexpected custom webhook request: auth=%q body=%v", gotAuth, gotBody)
		}
	})
}

func TestSMSSender_LocalSimulationAndProdGuard(t *testing.T) {
	devMock := NewSMSSender(config.SMSConfig{
		Provider: "twilio",
		APIURL:   "mock://dev",
	}, "development", zap.NewNop())
	if err := devMock.Send(context.Background(), "+60123456789", "314159"); err != nil {
		t.Fatalf("expected dev mock SMS to succeed without HTTP endpoint, got: %v", err)
	}

	prodMock := NewSMSSender(config.SMSConfig{
		Provider: "twilio",
		APIURL:   "mock://dev",
	}, "production", zap.NewNop())
	if err := prodMock.Send(context.Background(), "+60123456789", "314159"); err == nil {
		t.Fatalf("expected production mode to refuse mock simulation fallback")
	}
}

func TestService_SMSOTPFlowAndStorage(t *testing.T) {
	store := setupTestStorage(t)
	svc := setupTestService(t, store, false, false)

	ctx := context.Background()

	// 1. AuthorizedUser phone storage, lookup & update
	if err := store.AddAuthorizedUser(ctx, AuthorizedUser{
		Username: "smsuser",
		Email:    "smsuser@example.com",
		Phone:    "+60 12-345 6789",
		FullName: "SMS User",
		Source:   "manual",
	}); err != nil {
		t.Fatalf("AddAuthorizedUser failed: %v", err)
	}
	if got := svc.LookupUserPhone(ctx, "smsuser"); got != "+60123456789" {
		t.Fatalf("expected normalized LookupUserPhone '+60123456789', got %q", got)
	}
	if err := store.UpdateAuthorizedUserPhone(ctx, "smsuser", "+6598765432"); err != nil {
		t.Fatalf("UpdateAuthorizedUserPhone failed: %v", err)
	}
	if got := svc.LookupUserPhone(ctx, "smsuser@example.com"); got != "+6598765432" {
		t.Fatalf("expected updated phone lookup by email '+6598765432', got %q", got)
	}

	// 2. Wire in-memory HTTP SMS capture transport (zero network socket)
	var capturedCode string
	var capturedTarget string
	smsSender := NewSMSSender(config.SMSConfig{
		Provider:  "custom",
		APIURL:    "https://sms-capture.test/send",
		AuthToken: "tok",
		SenderID:  "SAMLGuard",
	}, "production", zap.NewNop())
	smsSender.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		capturedTarget = payload["to"]
		capturedCode = payload["code"]
		return mockHTTPResponse(http.StatusOK, `{"status":"sent"}`), nil
	})})
	svc.UpdateSMSSender(smsSender)

	// Missing phone error
	if err := svc.GenerateAndSendSMSOTP(ctx, "user-no-phone", ""); err == nil || !strings.Contains(err.Error(), "phone") {
		t.Fatalf("expected error for missing user phone, got: %v", err)
	}

	// Valid dispatch
	if err := svc.GenerateAndSendSMSOTP(ctx, "idp|smsuser", "+6598765432"); err != nil {
		t.Fatalf("GenerateAndSendSMSOTP failed: %v", err)
	}
	if capturedTarget != "+6598765432" || len(capturedCode) != 6 {
		t.Fatalf("expected 6-digit SMS OTP dispatched to +6598765432, got target=%q code=%q", capturedTarget, capturedCode)
	}

	// Cooldown enforcement
	if err := svc.GenerateAndSendSMSOTP(ctx, "idp|smsuser", "+6598765432"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "cooldown") {
		t.Fatalf("expected resend cooldown error, got: %v", err)
	}

	// Wrong code then right code, then replay check
	if ok, err := svc.VerifySMSOTP(ctx, "idp|smsuser", "000001"); ok || err == nil {
		t.Fatalf("expected wrong SMS OTP rejected, got ok=%v err=%v", ok, err)
	}
	if ok, err := svc.VerifySMSOTP(ctx, "idp|smsuser", capturedCode); err != nil || !ok {
		t.Fatalf("expected valid SMS OTP accepted, got ok=%v err=%v", ok, err)
	}
	if ok, err := svc.VerifySMSOTP(ctx, "idp|smsuser", capturedCode); ok || err == nil {
		t.Fatalf("expected consumed SMS OTP replay rejected, got ok=%v err=%v", ok, err)
	}

	// 3. Encrypted SMS profile persistence in SaveAdminSettings / GetAdminSettings
	adminPayload := &config.AdminSettingsPayload{
		ActiveIdP:           "simulator",
		EntityID:            "https://gw.local",
		ACSURL:              "https://ita.local/callback",
		MFAEnabledProviders: []string{"totp", "sms"},
		MFADefaultProvider:  "select",
		MFAIssuer:           "SAMLGuard",
		OTPExpiry:           5 * time.Minute,
		ResendCooldown:      time.Minute,
		SMSProvider:         "sendquick",
		SMSAPIURL:           "https://sq.company.local/send",
		SMSAccountID:        "sq_user",
		SMSAuthToken:        "super-secret-sq-token",
		SMSSenderID:         "SAMLGuard",
		SMSProfiles: map[string]config.SMSGatewayProfile{
			"twilio": {
				APIURL:    "https://api.twilio.com/2010-04-01",
				AccountID: "AC999",
				AuthToken: "twilio-secret-xyz",
				SenderID:  "+15551112222",
			},
			"sendquick": {
				APIURL:    "https://sq.company.local/send",
				AccountID: "sq_user",
				AuthToken: "super-secret-sq-token",
				SenderID:  "SAMLGuard",
			},
		},
	}
	if err := store.SaveAdminSettings(ctx, adminPayload); err != nil {
		t.Fatalf("SaveAdminSettings failed: %v", err)
	}
	loaded, err := store.GetAdminSettings(ctx)
	if err != nil {
		t.Fatalf("GetAdminSettings failed: %v", err)
	}
	if loaded.SMSProvider != "sendquick" || loaded.SMSAuthToken != "super-secret-sq-token" {
		t.Errorf("expected decrypted SendQuick settings, got provider=%q token=%q", loaded.SMSProvider, loaded.SMSAuthToken)
	}
	if loaded.SMSProfiles["twilio"].AuthToken != "twilio-secret-xyz" {
		t.Errorf("expected decrypted Twilio profile token, got %q", loaded.SMSProfiles["twilio"].AuthToken)
	}
}
