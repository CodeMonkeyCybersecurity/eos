// pkg/alerts/smtp.go

package alerts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"os"
	"sync"
	"time"

	cerr "github.com/cockroachdb/errors"
	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ────────────────────────────────────────────────────────────────────────────
// Globals (rate-limit window identical to Python: 3 failures / minute)
// ────────────────────────────────────────────────────────────────────────────
const (
	maxFails  = 3
	windowDur = time.Minute
)

var (
	failMu    sync.Mutex
	failTimes []time.Time
)

// ────────────────────────────────────────────────────────────────────────────
// Public interface
// ────────────────────────────────────────────────────────────────────────────
type SMTPSender interface {
	Send(ctx context.Context, subj, html, txt string) error
}

type SMTPConfig struct {
	Host, User, Pass, From, To string
	Port                       int
}

// ───────────────── smtpSender implementation ───────────────────────────────
type smtpSender struct {
	addr, host string
	auth       gosasl.Client
	from       mail.Address
	to         []mail.Address
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
	log := otelzap.Ctx(ctx)

	// 0. soft circuit-breaker on recent failures
	if !rateOK() {
		err := cerr.New("smtp: rate-limit reached (failures)")
		log.Warn("skipping send", zap.Error(err))
		return err
	}

	// 1. build message
	msg := buildMime(s.from, s.to, subj, txtBody, htmlBody)

	// 2. connect (plain TCP, context aware)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
	if err != nil {
		recordFail(err)
		return cerr.Wrap(err, "dial smtp")
	}

	// 3. upgrade to TLS in one step (go-smtp ≥ v0.20)
	c, err := gosmtp.NewClientStartTLS(conn, &tls.Config{ServerName: s.host})
	if err != nil {
		recordFail(err)
		return cerr.Wrap(err, "starttls")
	}
	defer func() {
		if qerr := c.Quit(); qerr != nil {
			recordFail(qerr)
		}
	}()

	// 4. EHLO
	if err := c.Hello(s.host); err != nil {
		recordFail(err)
		return cerr.Wrap(err, "EHLO")
	}

	// 5. AUTH (ignore “already authenticated”)
	if err := c.Auth(s.auth); err != nil &&
		err.Error() != "503 5.5.2 Already authenticated" {
		recordFail(err)
		return cerr.Wrap(err, "auth")
	}

	// 6. MAIL / RCPT
	if err := c.Mail(s.from.Address, nil); err != nil {
		recordFail(err)
		return cerr.Wrap(err, "MAIL FROM")
	}
	for _, a := range s.to {
		if err := c.Rcpt(a.Address, nil); err != nil {
			recordFail(err)
			return cerr.Wrapf(err, "RCPT TO %s", a.Address)
		}
	}

	// 7. DATA
	w, err := c.Data()
	if err != nil {
		recordFail(err)
		return cerr.Wrap(err, "DATA cmd")
	}
	if _, err := w.Write(msg); err != nil {
		recordFail(err)
		return cerr.Wrap(err, "write message")
	}
	if err := w.Close(); err != nil {
		recordFail(err)
		return cerr.Wrap(err, "close DATA")
	}

	log.Info("email sent", zap.String("subject", subj))
	return nil
}

// ---- rate-limiter ---------------------------------------------------------

func rateOK() bool {
	failMu.Lock()
	defer failMu.Unlock()

	cutoff := time.Now().Add(-windowDur)
	j := 0
	for _, t := range failTimes {
		if t.After(cutoff) {
			failTimes[j] = t
			j++
		}
	}
	failTimes = failTimes[:j]
	return len(failTimes) < maxFails
}

func recordFail(err error) {
	failMu.Lock()
	failTimes = append(failTimes, time.Now())
	failMu.Unlock()
	logEmailError(err)
}

// ---- logging helper -------------------------------------------------------

func logEmailError(err error) {
	ts := time.Now().Format(time.RFC3339)
	_ = os.WriteFile(
		"/var/log/stackstorm/email-errors.log",
		[]byte(ts+" "+err.Error()+"\n"),
		0644,
	)

	// add component field so we can grep easily
	otelzap.L().Error("smtp-error",
		zap.String("component", "alerts.smtp"),
		zap.Error(err),
	)
}
