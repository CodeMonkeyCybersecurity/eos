// pkg/stackstorm/watcher.go

package stackstorm

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/alerts"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// -----------------------------------------------------------------------------
// Public bootstrap – start a background watcher
// -----------------------------------------------------------------------------

func StartWatcher(ctx context.Context, cfg *Config, log *zap.Logger, store HashStore, sender SMTPSender) error {
	ws, _ := fsnotify.NewWatcher()
	if err := ws.Add(filepath.Dir(cfg.LogFile)); err != nil {
		return err
	}
	go runWatcher(ctx, cfg, log, ws, store, sender)
	return nil
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

var (
	reSplit    = regexp.MustCompile(`\| chatgpt_response:`)
	failTimes  []time.Time
	maxFailsPM = 3
)

func runWatcher(ctx context.Context, cfg *Config, log *zap.Logger, w *fsnotify.Watcher, store HashStore, sender SMTPSender) {
	pos := fileSize(cfg.LogFile)
	for {
		select {
		case ev := <-w.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if err := consume(ctx, cfg.LogFile, &pos, log, store, sender); err != nil {
					log.Warn("consume", zap.Error(err))
				}
			}
		case err := <-w.Errors:
			log.Warn("watch", zap.Error(err))
		case <-ctx.Done():
			_ = w.Close()
			return
		}
	}
}

func consume(ctx context.Context, path string, pos *int64, log *zap.Logger, store HashStore, sender SMTPSender) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(*pos, io.SeekStart); err != nil {
		return err
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		h := sha256.Sum256([]byte(line))
		hash := hex.EncodeToString(h[:])

		if store.Seen(hash) {
			continue
		}

		alert, reply := parseLine(line)
		if alert == "" {
			continue
		}

		// Render
		rendered, err := alerts.RenderEmail(alerts.Alert{
			Time:        time.Now(),
			Severity:    5,
			Title:       alert,
			Description: reply,
		})
		if err != nil {
			log.Error("render email", zap.Error(err))
			continue
		}

		// Rate-limit on recent failures
		if !canSend() {
			continue
		}

		if err := sender.Send(ctx, rendered.Subject, rendered.HTML, rendered.Text); err != nil {
			failTimes = append(failTimes, time.Now())
			log.Error("send", zap.Error(err))
			continue
		}
		_ = store.Mark(hash)
		time.Sleep(time.Second) // gentle throttle
	}
	*pos, _ = f.Seek(0, io.SeekCurrent)
	return sc.Err()
}

func canSend() bool {
	now := time.Now()
	window := now.Add(-time.Minute)
	newSlice := failTimes[:0]
	for _, t := range failTimes {
		if t.After(window) {
			newSlice = append(newSlice, t)
		}
	}
	failTimes = newSlice
	return len(failTimes) < maxFailsPM
}
