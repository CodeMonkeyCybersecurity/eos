// pkg/alerts/smtp.go

package alerts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"

	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
)

// compile-time interface guard
var _ SMTPSender = (*smtpSender)(nil)

// ───────────────── Interfaces & cfg stub ─────────────────────────

// If these already exist elsewhere, remove these duplicates.
type SMTPSender interface {
	Send(ctx context.Context, subj, html, txt string) error
}

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string
	To   string
}

// ───────────────── smtpSender implementation ────────────────────

type smtpSender struct {
	addr string
	host string
	auth gosasl.Client
	from mail.Address
	to   []mail.Address
}

func NewSMTPSender(cfg SMTPConfig) SMTPSender {
	return &smtpSender{
		addr: fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		host: cfg.Host,
		auth: gosasl.NewPlainClient("", cfg.User, cfg.Pass),
		from: mail.Address{Address: cfg.From},
		to:   []mail.Address{{Address: cfg.To}},
	}
}

func (s *smtpSender) Send(ctx context.Context, subj, htmlBody, txtBody string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// 1. build message
	msg := buildMime(s.from, s.to, subj, txtBody, htmlBody)


	// 2. connect (still plain TCP so we can time-out with ctx)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}

	// 3. upgrade to TLS immediately with the helper introduced in v0.20
	c, err := gosmtp.NewClientStartTLS(conn, &tls.Config{ServerName: s.host})
	if err != nil {
		return err // TLS not supported or handshake failed
	}
	defer c.Quit()

	// 5. EHLO with our hostname (optional but polite)
	if err := c.Hello(s.host); err != nil { // for v0.20+, method is Hello
		return err
	}

	// 6. auth
	if err := c.Auth(s.auth); err != nil {
		// 503 = already authenticated – ignore
		if err.Error() != "503 5.5.2 Already authenticated" {
			return err
		}
	}

	// 7. envelope
	if err := c.Mail(s.from.Address, nil); err != nil {
		return err
	}
	for _, a := range s.to {
		if err := c.Rcpt(a.Address, nil); err != nil { // 2nd arg required now
			return err
		}
	}

	// 8. data
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
