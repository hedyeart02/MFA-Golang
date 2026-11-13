package mfa

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strings"
	"time"

	"go.uber.org/zap"
)

type SMTPSender struct {
	host       string
	port       int
	username   string
	password   string
	from       string
	fromName   string
	encryption string
	logger     *zap.Logger
}

func NewSMTPSender(host string, port int, username, password, from, fromName, encryption string, log *zap.Logger) *SMTPSender {
	if fromName == "" {
		fromName = "SAMLGuard MFA"
	}
	if from == "" {
		from = "no-reply@samlguard.local"
	}
	if port <= 0 {
		port = 587
	}
	if encryption == "" {
		encryption = "starttls"
	}

	return &SMTPSender{
		host:       host,
		port:       port,
		username:   username,
		password:   password,
		from:       from,
		fromName:   fromName,
		encryption: strings.ToLower(encryption),
		logger:     log,
	}
}

// Send sends an email with the verification code. In local/development mode with localhost, it logs the simulated code.
func (s *SMTPSender) Send(ctx context.Context, recipient, code string) error {
	if s == nil {
		return errors.New("SMTP sender is not configured")
	}
	if s.logger != nil {
		s.logger.Info("dispatching MFA email OTP",
			zap.String("recipient", maskRecipient(recipient)),
			zap.String("smtp_host", s.host),
			zap.Int("smtp_port", s.port),
		)
	}

	appName := s.fromName
	if appName == "" {
		appName = "Schneider IT Advisor"
	}

	// High-priority subject: placing code in brackets makes it immediately visible in mobile notification previews (Outlook/iOS/Android)
	subject := fmt.Sprintf("[%s] %s Sign-In Code", code, appName)

	plainBody := fmt.Sprintf(
		"Your one-time sign-in verification code for %s is:\r\n\r\n"+
			"    %s\r\n\r\n"+
			"Enter this 6-digit code on your computer screen to complete your sign-in.\r\n\r\n"+
			"This code will expire in 5 minutes.\r\n"+
			"If you did not request this sign-in attempt, please contact your IT administrator immediately.",
		appName, code,
	)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s Verification Code</title>
</head>
<body style="margin: 0; padding: 24px 12px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b;">
<div style="max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
  <div style="background: #0f172a; padding: 20px 24px; text-align: left; border-bottom: 3px solid #00B050;">
    <h2 style="margin: 0; color: #ffffff; font-size: 18px; font-weight: 600; letter-spacing: -0.3px;">%s</h2>
    <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Identity Verification Alert</p>
  </div>
  <div style="padding: 28px 24px; text-align: center;">
    <p style="margin: 0 0 16px 0; font-size: 15px; color: #475569; line-height: 1.5;">Enter this verification code on your computer screen to complete your sign-in:</p>
    <div style="display: inline-block; background: #f0fdf4; border: 2px dashed #00B050; border-radius: 8px; padding: 14px 28px; margin: 8px 0 20px 0;">
      <span style="font-family: 'SF Mono', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #00B050;">%s</span>
    </div>
    <div style="background: #f8fafc; border-radius: 8px; padding: 12px 16px; margin-top: 10px; font-size: 13px; color: #64748b; line-height: 1.6; text-align: left; border: 1px solid #f1f5f9;">
      <div>⏱️ <strong>Valid for:</strong> 5 minutes</div>
      <div>🔒 <strong>Account:</strong> %s</div>
    </div>
    <p style="margin: 24px 0 0 0; font-size: 12px; color: #94a3b8; line-height: 1.5;">If you did not initiate this sign-in attempt, someone may be attempting to access your account. Please notify your IT administrator immediately.</p>
  </div>
</div>
</body>
</html>`,
		html.EscapeString(appName),
		html.EscapeString(appName),
		code,
		html.EscapeString(recipient),
	)

	// If host is empty or dummy localhost, log and return in test/dev
	if s.host == "" || s.host == "localhost" || s.host == "127.0.0.1" {
		if s.logger != nil {
			s.logger.Info("local/development mode: simulated email delivery",
				zap.String("recipient", maskRecipient(recipient)),
				zap.String("code", code),
			)
		}
		fmt.Printf("\n📧 [SIMULATED EMAIL OTP] To: %s | Subject: %s | Verification Code: %s (Expires in 5m)\n\n", recipient, subject, code)
		return nil
	}

	return s.sendMultipartMail(ctx, recipient, subject, plainBody, htmlBody)
}

// SendTestEmail sends an explicit test email to verify SMTP connectivity, credentials, and delivery.
func (s *SMTPSender) SendTestEmail(ctx context.Context, recipient string) error {
	if strings.TrimSpace(recipient) == "" {
		return fmt.Errorf("recipient email address cannot be empty")
	}
	if strings.TrimSpace(s.host) == "" {
		return fmt.Errorf("SMTP host cannot be empty")
	}

	subject := "SAMLGuard Enterprise Gateway - SMTP Test"
	body := fmt.Sprintf(
		"Hello,\r\n\r\n"+
			"This is a verified test email sent from SAMLGuard Enterprise MFA Gateway.\r\n\r\n"+
			"Configuration Details:\r\n"+
			" • SMTP Host: %s\r\n"+
			" • SMTP Port: %d\r\n"+
			" • Encryption: %s\r\n"+
			" • Sender: %s <%s>\r\n"+
			" • Timestamp: %s\r\n\r\n"+
			"If you received this message, your SMTP email delivery is configured properly and ready for production Email OTP.\r\n",
		s.host, s.port, strings.ToUpper(s.encryption), s.fromName, s.from, time.Now().Format(time.RFC1123Z),
	)

	return s.sendMail(ctx, recipient, subject, body)
}

func validateSMTPHeaderValue(field, val string) error {
	if strings.ContainsAny(val, "\r\n\x00") {
		return fmt.Errorf("invalid characters in SMTP %s header", field)
	}
	return nil
}

func (s *SMTPSender) sendMultipartMail(ctx context.Context, recipient, subject, plainBody, htmlBody string) error {
	for field, val := range map[string]string{
		"from_name": s.fromName,
		"from":      s.from,
		"to":        recipient,
		"subject":   subject,
	} {
		if err := validateSMTPHeaderValue(field, val); err != nil {
			return err
		}
	}

	boundary := fmt.Sprintf("----=_SAMLGuard_%d", time.Now().UnixNano())

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: multipart/alternative; boundary=\"%s\"\r\n"+
		"Date: %s\r\n"+
		"X-Priority: 1 (Highest)\r\n"+
		"Priority: Urgent\r\n"+
		"Importance: High\r\n"+
		"\r\n"+
		"--%s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Content-Transfer-Encoding: 8bit\r\n"+
		"\r\n"+
		"%s\r\n\r\n"+
		"--%s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"Content-Transfer-Encoding: 8bit\r\n"+
		"\r\n"+
		"%s\r\n\r\n"+
		"--%s--\r\n",
		s.fromName, s.from, recipient, subject, boundary, time.Now().Format(time.RFC1123Z),
		boundary, plainBody,
		boundary, htmlBody,
		boundary,
	)

	return s.deliverMessage(ctx, recipient, msg)
}

func (s *SMTPSender) sendMail(ctx context.Context, recipient, subject, body string) error {
	for field, val := range map[string]string{
		"from_name": s.fromName,
		"from":      s.from,
		"to":        recipient,
		"subject":   subject,
	} {
		if err := validateSMTPHeaderValue(field, val); err != nil {
			return err
		}
	}

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n"+
		"X-Priority: 1 (Highest)\r\n"+
		"Priority: Urgent\r\n"+
		"Importance: High\r\n"+
		"\r\n"+
		"%s\r\n",
		s.fromName, s.from, recipient, subject, time.Now().Format(time.RFC1123Z), body)

	return s.deliverMessage(ctx, recipient, msg)
}

func (s *SMTPSender) deliverMessage(ctx context.Context, recipient, msg string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	if s.encryption == "tls" {
		tlsConfig := &tls.Config{
			ServerName: s.host,
			MinVersion: tls.VersionTLS12,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls dial smtp server: %w", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		client, err := smtp.NewClient(conn, s.host)
		if err != nil {
			return fmt.Errorf("creating smtp client: %w", err)
		}
		defer client.Close()

		if auth != nil {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return fmt.Errorf("smtp auth: %w", err)
				}
			}
		}

		if err := client.Mail(s.from); err != nil {
			return fmt.Errorf("smtp mail from: %w", err)
		}
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("smtp rcpt to: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp data: %w", err)
		}
		if _, err := w.Write([]byte(msg)); err != nil {
			return fmt.Errorf("writing email body: %w", err)
		}
		return w.Close()
	}

	// STARTTLS or None
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dialing smtp server: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("creating smtp client: %w", err)
	}
	defer client.Close()

	if s.encryption == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: s.host,
				MinVersion: tls.VersionTLS12,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}

	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("writing email body: %w", err)
	}
	return w.Close()
}

func maskRecipient(recipient string) string {
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return "***"
	}
	user := parts[0]
	if len(user) <= 2 {
		return user[:1] + "***@" + parts[1]
	}
	return user[:2] + "***@" + parts[1]
}
