// pkg/stackstorm/emailer.go

package stackstorm

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/alerts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	postgres "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_postgres"
	cerr "github.com/cockroachdb/errors"
	"github.com/fsnotify/fsnotify"
	validator "github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Cue schema for runtime validation
// cue:generate cue vet
//
//    #Config: {
//      logFile:           string
//      sentHashesFile:    string
//      smtp: {
//        host:           string
//        port:           int
//        user?:          string
//        pass?:          string
//        from, to:       =~"^.+@.+\\..+$"
//      }
//    }

// ───────────────── Config ────────────────────────────────────────────────
type Config struct {
	LogFile        string `validate:"required,file"`
	SentHashesFile string `validate:"required"`
	SMTP           struct {
		Host string `validate:"required,hostname|ip"`
		Port int    `validate:"required,gt=0"`
		User string
		Pass string
		From string `validate:"required,email"`
		To   string `validate:"required,email"`
	}
}

func LoadConfig(_ context.Context) (*Config, error) {
	_ = godotenv.Load("/opt/stackstorm/packs/delphi/.env")

	intEnv := func(k string, def int) int {
		if s := os.Getenv(k); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				return v
			}
		}
		return def
	}
	var cfg Config
	cfg.LogFile = os.Getenv("DELPHI_LOG_FILE")
	cfg.SentHashesFile = os.Getenv("DELPHI_SENT_HASHES_FILE")
	cfg.SMTP.Host = os.Getenv("MAILCOW_SMTP_HOST")
	cfg.SMTP.Port = intEnv("MAILCOW_SMTP_PORT", 587)
	cfg.SMTP.User = os.Getenv("MAILCOW_SMTP_USER")
	cfg.SMTP.Pass = os.Getenv("MAILCOW_SMTP_PASS")
	cfg.SMTP.From = os.Getenv("MAILCOW_FROM")
	cfg.SMTP.To = os.Getenv("MAILCOW_TO")

	if err := validator.New().Struct(cfg); err != nil {
		return nil, cerr.WithStack(err)
	}
	return &cfg, nil
}

// ───────────────── Interfaces ────────────────────────────────────────────
type HashStore interface {
	Seen(string) bool
	Mark(string) error
}
type SMTPSender interface {
	Send(ctx context.Context, subj, html, txt string) error
}

// ───────── Emailer – EOS style ───────────
type Emailer struct {
	cfg      *Config
	tracer   trace.Tracer
	log      *otelzap.Logger
	hash     HashStore
	sender   SMTPSender
	policy   rego.PreparedEvalQuery
	fs       *fsnotify.Watcher
	location *time.Location
}

// ───────────────── Minimal shims ─────────────────────────────────────────
type memHash struct{ m map[string]struct{} }

func newMemHash() HashStore            { return &memHash{m: map[string]struct{}{}} }
func (h *memHash) Seen(s string) bool  { _, ok := h.m[s]; return ok }
func (h *memHash) Mark(s string) error { h.m[s] = struct{}{}; return nil }

// stub mailer
type nopSender struct{}

func (nopSender) Send(_ context.Context, subj, _, _ string) error {
	fmt.Println("[EMAIL] →", subj)
	return nil
}
func hash256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func fileSize(p string) int64 {
	fi, _ := os.Stat(p)
	if fi != nil {
		return fi.Size()
	}
	return 0
}

// ───────────────── Emailer ───────────────────────────────────────────────

func New(ctx context.Context, cfg *Config) (*Emailer, error) {
	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	pq, err := rego.New(
		rego.Query(`allow`),
		rego.Module("policy.rego", `package delphi allow { input.level > 5 }`),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	loc, _ := time.LoadLocation("Australia/Perth")
	return &Emailer{
		cfg:      cfg,
		tracer:   otel.Tracer("delphi/emailer"),
		log:      otelzap.New(zap.L()),
		hash:     newMemHash(),
		sender:   nopSender{},
		policy:   pq,
		fs:       fs,
		location: loc,
	}, nil
}

func (e *Emailer) Run(ctx context.Context) error {
	ctx, span := e.tracer.Start(ctx, "Run")
	defer span.End()

	if err := e.fs.Add(filepath.Dir(e.cfg.LogFile)); err != nil {
		return err
	}
	pos := fileSize(e.cfg.LogFile)

	for {
		select {
		case ev := <-e.fs.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if err := e.consume(ctx, &pos); err != nil {
					e.log.Logger.Warn("consume", zap.Error(err))
				}
			}
		case err := <-e.fs.Errors:
			e.log.Error("fswatch", zap.Error(err))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *Emailer) consume(ctx context.Context, pos *int64) error {
	f, err := os.Open(e.cfg.LogFile)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Seek(*pos, io.SeekStart)
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !reSplit.MatchString(line) {
			continue
		}

		h := hash256(line)
		if e.hash.Seen(h) {
			continue
		}

		a, r := parseLine(line)
		rs, _ := e.policy.Eval(ctx, rego.EvalInput(map[string]any{
			"alert": a,
		}))
		if len(rs) == 0 {
			continue
		}

		html := "<b>" + a + "</b><p>" + r + "</p>"
		txt := a + "\n\n" + r
		if err := e.sender.Send(ctx, "[Delphi] "+a, html, txt); err == nil {
			_ = e.hash.Mark(h)
		}
	}
	*pos, _ = f.Seek(0, io.SeekCurrent)
	return sc.Err()
}

// --------- keep near the other regexes ----------
var reLLM = regexp.MustCompile(`\| chatgpt_response:`)                   // single source of truth
var rePrompt = regexp.MustCompile(`(?i)Please explain.*?line breaks\.?`) // now used

// -----------------------------------------------
// parseLine removes the GPT prompt (using rePrompt) *and* splits on reLLM.
func parseLine(line string) (alert, resp string) {
	if !reLLM.MatchString(line) {
		return "", ""
	}
	parts := reLLM.Split(line, 2)
	if len(parts) != 2 {
		return "", ""
	}
	// Trim the noisy prompt:
	alert = strings.TrimSpace(rePrompt.ReplaceAllString(parts[0], ""))
	alert = strings.TrimSpace(strings.TrimPrefix(alert,
		"wazuh-LLM: INFO - Alert: "))
	resp = strings.TrimSpace(parts[1])
	return
}

// RenderEmail builds both HTML + plain parts.
// Feel free to replace with your fancy template version later.
func RenderEmail(alert, resp string, when *time.Location) (html, txt string) {
	ts := time.Now().In(when).Format("Mon, 02 Jan 2006 15:04 MST")
	txt = fmt.Sprintf("Delphi Notify • %s\n\n%s\n\n%s\n", ts, alert, resp)
	html = fmt.Sprintf(`<h3>Delphi Notify • %s</h3><b>%s</b><p>%s</p>`,
		ts, alert, resp)
	return
}

// Utility helpers (hash256, parseLine, RenderEmail) remain mostly unchanged.

// ---------- defaultOptions & plumbing ----------
// Option pattern lets unit tests swap deps quickly.

type Option func(*options)

type options struct {
	hash    HashStore
	smtp    SMTPSender
	opaEval rego.PreparedEvalQuery
}

// callers:
//
//	opts, err := DefaultOptions(ctx, cfg)
//	if err != nil { return err }
//	e := &Emailer{
//	    hash:   opts.hash,
//	    sender: opts.smtp,
//	    policy: opts.opaEval,
//	    // ...
//	}
func DefaultOptions(ctx context.Context, cfg *Config, extra ...Option) (*options, error) {
	// --- Hash store -------------------------------------------------------
	hash, err := postgres.NewPGHashStore(ctx) // new signature, returns error
	if err != nil {
		return nil, fmt.Errorf("hash store: %w", err)
	}

	// --- SMTP sender ------------------------------------------------------
	defSender := alerts.NewSMTPSender(alerts.SMTPConfig{
		Host: cfg.SMTP.Host,
		Port: cfg.SMTP.Port,
		User: cfg.SMTP.User,
		Pass: cfg.SMTP.Pass,
		From: cfg.SMTP.From,
		To:   cfg.SMTP.To,
	})

	// --- OPA policy -------------------------------------------------------
	pq, err := eos_opa.CompiledPolicyCtx(ctx) // assume helper accepts ctx
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	// --- assemble baseline -----------------------------------------------
	o := &options{
		hash:    hash,
		smtp:    defSender,
		opaEval: pq,
	}

	// apply functional overrides
	for _, fn := range extra {
		fn(o)
	}
	return o, nil
}
