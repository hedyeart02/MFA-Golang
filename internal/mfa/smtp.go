package mfa

import (
	"context"
	"crypto/tls"
	"fmt"
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

func (s *SMTPSender) Send(ctx context.Context, recipient, code string) error {
	if s.logger != nil {
		s.logger.Info("dispatching MFA email OTP",
			zap.String("recipient", maskRecipient(recipient)),
			zap.String("smtp_host", s.host),
			zap.Int("smtp_port", s.port),
		)
	}

	// If host is empty or dummy localhost, log and return in test/dev
	if s.host == "" || s.host == "localhost" || s.host == "127.0.0.1" {
		if s.logger != nil {
			s.logger.Info("local/development mode: simulated email delivery",
				zap.String("recipient", maskRecipient(recipient)),
				zap.String("code", code),
			)
		}
		fmt.Printf("\n📧 [SIMULATED EMAIL OTP] To: %s | Verification Code: %s (Expires in 5m)\n\n", recipient, code)
		return nil
	}

	subject := "Your SAMLGuard Verification Code"
	body := fmt.Sprintf("Your one-time verification code is:\r\n\r\n%s\r\n\r\nThis code will expire in 5 minutes. If you did not request this code, please ignore this email.", code)

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"%s\r\n",
		s.fromName, s.from, recipient, subject, time.Now().Format(time.RFC1123Z), body)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	if s.encryption == "tls" {
		tlsConfig := &tls.Config{
			ServerName: s.host,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls dial smtp server: %w", err)
		}
		defer conn.Close()

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

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("creating smtp client: %w", err)
	}
	defer client.Close()

	if s.encryption == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: s.host,
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
