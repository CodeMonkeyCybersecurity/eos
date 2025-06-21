// pkg/llm/helpers.go
package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ───────────────────────── Config (env driven) ────────────────────────────

var (
	apiKey       = env("AZURE_API_KEY", "")
	endpoint     = env("AZURE_ENDPOINT", "https://languageatcodemonkey.openai.azure.com")
	deployment   = env("AZURE_DEPLOYMENT", "gpt-4.1")
	apiVersion   = env("AZURE_API_VERSION", "2025-01-01-preview")
	promptFile   = env("PROMPT_FILE", "/opt/system-prompt.txt")
	debugLogFile = env("DEBUG_LOG", "/var/log/stackstorm/llm-debug.log")
	_            = env("PROMPT_DEBUG", "/var/log/stackstorm/prompt-debug.log") // promptDbgFile unused but kept for future debug logging
	maxLogBytes  = int64(10 * 1024 * 1024)
)

func env(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

// ───────────────────────── Logger helper ──────────────────────────────────

func dbg(ctx context.Context, fmtStr string, args ...any) {
	rotateFileIfLarge(debugLogFile, maxLogBytes)
	_ = appendLine(debugLogFile, fmt.Sprintf(fmtStr, args...))
	otelzap.Ctx(ctx).Debug(strings.TrimSuffix(fmt.Sprintf(fmtStr, args...), "\n"))
}

// ───────────────────────── File utils ─────────────────────────────────────

func appendLine(path, s string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			// Log error silently since this is a helper function
			// and we're already returning an error from WriteString
			_ = cerr
		}
	}()
	_, err = f.WriteString(s)
	return err
}

func rotateFileIfLarge(path string, max int64) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > max {
		_ = os.Rename(path, path+".old")
	}
}

// ───────────────────────── Prompt helpers ─────────────────────────────────

func ReadPrompt(ctx context.Context) string {
	b, err := os.ReadFile(promptFile)
	if err == nil {
		return string(b)
	}
	dbg(ctx, "Prompt file missing (%v); using default\n", err)
	return "You are Delphi Notify, a digital cybersecurity first-responder. Please reply as a single line."
}

func BuildUserPrompt(alertJSON any) (string, error) {
	js, err := json.MarshalIndent(alertJSON, "", "  ")
	if err != nil {
		return "", err
	}
	header := `You will receive a Wazuh alert in JSON format. Explain for a non-technical user what happened, what to do, and how to verify it worked. Be concise and avoid jargon.

Alert JSON:
`
	return header + string(js), nil
}

func BuildPayload(systemPrompt, userPrompt string) map[string]any {
	return map[string]any{
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": 1,
		"top_p":       1,
		"max_tokens":  800,
	}
}

// ───────────────────────── JSON / hashing utils ───────────────────────────

func IsJSONLine(line string) bool {
	line = strings.TrimLeft(line, " \t")
	return strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[")
}

func ParseAlert(line string) (map[string]any, error) {
	if !IsJSONLine(line) {
		return nil, cerr.New("not JSON")
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func AlertHash(raw string) string {
	if m, err := ParseAlert(raw); err == nil {
		canonical, _ := json.Marshal(m) // never fails on map
		sum := sha256.Sum256(canonical)
		return fmt.Sprintf("%x", sum[:])
	}
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:])
}

// ───────────────────────── Duplication filter ─────────────────────────────
// Same semantics as Python: TTL = 5 min, clean every 100 lookups.

type Deduper struct {
	ttl       time.Duration
	cleanEach int
	mu        sync.Mutex
	seen      map[string]time.Time
	count     int
}

func NewDeduper() *Deduper {
	return &Deduper{
		ttl:       5 * time.Minute,
		cleanEach: 100,
		seen:      make(map[string]time.Time),
	}
}

func (d *Deduper) IsDup(hash string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if t, ok := d.seen[hash]; ok && now.Sub(t) < d.ttl {
		d.count++
	} else {
		d.seen[hash] = now
		d.count++
		return false
	}

	if d.count >= d.cleanEach {
		for k, v := range d.seen {
			if now.Sub(v) >= d.ttl {
				delete(d.seen, k)
			}
		}
		d.count = 0
	}
	return true
}

// ───────────────────────── Azure request helper ───────────────────────────

func CallAzure(ctx context.Context, payload map[string]any, retries int, delay time.Duration) (*http.Response, error) {
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		endpoint, deployment, apiVersion)

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", apiKey)

	cl := &http.Client{Timeout: 20 * time.Second}
	for i := 0; i < retries; i++ {
		resp, err := cl.Do(req)
		if err == nil {
			return resp, nil
		}
		dbg(ctx, "call_azure failed attempt %d: %v\n", i+1, err)
		time.Sleep(delay)
	}
	return nil, cerr.New("call_azure exhausted retries")
}

func ExtractResponseText(resp *http.Response) (string, error) {
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently as this is a utility function
			_ = err
		}
	}()
	var data struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if len(data.Choices) == 0 {
		return "", cerr.New("no choices")
	}
	text := strings.Join(strings.Fields(data.Choices[0].Message.Content), " ")
	return text, nil
}

// ───────────────────────── File tail helper (rotation aware) ──────────────

func ReopenLog(ctx context.Context, path string) (<-chan string, error) {
	out := make(chan string)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	go func() {
		defer func() {
			if cerr := f.Close(); cerr != nil {
				dbg(ctx, "failed to close log file: %v\n", cerr)
			}
		}()
		r := bufio.NewReader(f)
		for {
			select {
			case <-ctx.Done():
				close(out)
				return
			default:
			}

			line, err := r.ReadString('\n')
			if err == io.EOF {
				// rotated?
				if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
					time.Sleep(time.Second)
					if err := f.Close(); err != nil {
						dbg(ctx, "failed to close rotated log file: %v\n", err)
					}
					f, _ = os.Open(path)
					r = bufio.NewReader(f)
				} else {
					time.Sleep(time.Second)
				}
				continue
			}
			if err != nil {
				dbg(ctx, "read log error: %v\n", err)
				time.Sleep(time.Second)
				continue
			}
			out <- strings.TrimRight(line, "\r\n")
		}
	}()
	return out, nil
}

// ───────────────────────── Result logger (file) ───────────────────────────

func LogResult(ruleDesc, response string) error {
	rotateFileIfLarge("/var/log/stackstorm/active-responses.log", maxLogBytes)
	line := fmt.Sprintf("wazuh-LLM: INFO - Alert: %s | chatgpt_response: %s\n", ruleDesc, response)
	return appendLine("/var/log/stackstorm/active-responses.log", line)
}
