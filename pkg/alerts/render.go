// pkg/alerts/renderer.go
package alerts

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	thtml "html/template"
	"mime"
	"net/mail"
	"path"
	ttxt "text/template" // aliased as ttxt below
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
)

// helper
func mustRead(name string) string {
	b, err := templates.FS.ReadFile(path.Base(name))
	if err != nil {
		panic(err)
	}
	return string(b)
}

// -----------------------------------------------------------------------------
// template sources
// -----------------------------------------------------------------------------
var (
	subjSrc = mustRead("email_subject.txt")
	txtSrc  = mustRead("email_body.txt")
	htmlSrc = mustRead("email_body.html")
)

// -----------------------------------------------------------------------------
// Compile templates once at init()
// -----------------------------------------------------------------------------
var (
	subjTpl *thtml.Template
	txtTpl  *ttxt.Template
	htmlTpl *thtml.Template // may stay nil if compile fails
)

func init() {
	subjTpl = thtml.Must(thtml.New("subj").Parse(subjSrc))
	txtTpl = ttxt.Must(ttxt.New("txt").Parse(txtSrc))

	// HTML is optional: if parsing fails, we just log and continue.
	if t, err := thtml.New("html").Parse(htmlSrc); err == nil {
		htmlTpl = t
	}
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

type Rendered struct {
	Subject string
	Text    string
	HTML    string // empty if the template failed or missing
}

// BestBody returns the body you should send and its MIME type.
func (r Rendered) BestBody() (mime string, body string) {
	if r.HTML != "" {
		return "text/html", r.HTML
	}
	return "text/plain", r.Text
}

// RenderEmail fills Subject/Text/HTML. HTML may be empty; Text is guaranteed.
func RenderEmail(a Alert) (Rendered, error) {
	var buf bytes.Buffer
	var out Rendered

	// -------- subject --------
	buf.Reset()
	if err := subjTpl.Execute(&buf, a); err != nil {
		return out, err
	}
	out.Subject = buf.String()

	// -------- plain text -----
	buf.Reset()
	if err := txtTpl.Execute(&buf, a); err != nil {
		return out, err
	}
	out.Text = buf.String()

	// -------- HTML (optional) -----
	if htmlTpl != nil {
		buf.Reset()
		if err := htmlTpl.Execute(&buf, a); err == nil {
			out.HTML = buf.String()
		}
	}

	// Sanity: we must have at least plain text.
	if out.Text == "" {
		return out, errors.New("render: empty plain-text output")
	}
	return out, nil
}

// ────────────────── helpers ──────────────────

func buildMime(from mail.Address, to []mail.Address, subj, txt, html string) []byte {
	var buf bytes.Buffer
	boundary := fmt.Sprintf("delphi-%d", time.Now().UnixNano())
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to[0])
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subj))
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%s\r\n\r\n", boundary)

	fmt.Fprintf(&buf, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n", boundary, txt)
	if html != "" {
		fmt.Fprintf(&buf, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n\r\n", boundary, html)
	}
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return buf.Bytes()
}
