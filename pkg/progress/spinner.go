// pkg/progress/spinner.go
//
// Terminal-friendly progress indicators with spinners and progress bars
// Human-centric visual feedback for long operations

package progress

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// Spinner frames for animation
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// VisualOperation provides visual progress feedback with spinners and status
type VisualOperation struct {
	Name     string
	Duration string
	Stage    string // Current stage description
	frame    int
	elapsed  time.Duration
	logger   otelzap.LoggerWithCtx
	ctx      context.Context
	done     chan struct{}
	ticker   *time.Ticker
}

// NewVisual creates a visual progress operation
func NewVisual(ctx context.Context, name, duration string) *VisualOperation {
	return &VisualOperation{
		Name:     name,
		Duration: duration,
		logger:   otelzap.Ctx(ctx),
		ctx:      ctx,
		done:     make(chan struct{}),
	}
}

// Start begins the visual progress display
func (vo *VisualOperation) Start() {
	vo.logger.Info(fmt.Sprintf("┌─ %s", vo.Name),
		zap.String("duration", vo.Duration))

	vo.ticker = time.NewTicker(1 * time.Second) // Update once per second
	go vo.animate()
}

// UpdateStage changes the current stage message
func (vo *VisualOperation) UpdateStage(stage string) {
	vo.Stage = stage
}

// animate runs the spinner animation
func (vo *VisualOperation) animate() {
	start := time.Now()

	for {
		select {
		case <-vo.done:
			return
		case <-vo.ticker.C:
			vo.frame = (vo.frame + 1) % len(spinnerFrames)
			vo.elapsed = time.Since(start)

			status := vo.Stage
			if status == "" {
				status = "working"
			}

			// Format: │ ⠋ [2m 30s] Pulling images...
			elapsed := formatDuration(vo.elapsed)
			vo.logger.Info(fmt.Sprintf("│ %s [%s] %s",
				spinnerFrames[vo.frame],
				elapsed,
				status))
		}
	}
}

// Done stops the visual progress
func (vo *VisualOperation) Done() {
	if vo.ticker != nil {
		vo.ticker.Stop()
	}
	close(vo.done)

	elapsed := formatDuration(vo.elapsed)
	vo.logger.Info(fmt.Sprintf("└─ ✓ %s completed in %s",
		vo.Name,
		elapsed))
}

// Fail marks the operation as failed
func (vo *VisualOperation) Fail(err error) {
	if vo.ticker != nil {
		vo.ticker.Stop()
	}
	close(vo.done)

	elapsed := formatDuration(vo.elapsed)
	vo.logger.Error(fmt.Sprintf("└─ ✗ %s failed after %s",
		vo.Name,
		elapsed),
		zap.Error(err))
}

// ProgressBar shows a visual progress bar for operations with known progress
type ProgressBar struct {
	Total   int64
	Current int64
	Width   int // Width of progress bar in characters
	logger  otelzap.LoggerWithCtx
	lastLog time.Time
}

// NewProgressBar creates a new progress bar
func NewProgressBar(ctx context.Context, total int64) *ProgressBar {
	// Calculate progress bar width as 50% of terminal width
	width := 40 // Default fallback
	if termWidth, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && termWidth > 0 {
		// Use 50% of terminal width for progress bar, min 20, max 100
		width = termWidth / 2
		if width < 20 {
			width = 20
		}
		if width > 100 {
			width = 100
		}
	}

	return &ProgressBar{
		Total:  total,
		Width:  width,
		logger: otelzap.Ctx(ctx),
	}
}

// Update updates the progress bar
// Only logs every 1 second to avoid spam
func (pb *ProgressBar) Update(current int64, status string) {
	pb.Current = current

	// Rate limit to once per second
	if time.Since(pb.lastLog) < time.Second {
		return
	}
	pb.lastLog = time.Now()

	percent := float64(current) / float64(pb.Total) * 100
	filled := int(float64(pb.Width) * float64(current) / float64(pb.Total))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)

	pb.logger.Info(fmt.Sprintf("[%s] %.1f%% %s",
		bar,
		percent,
		status))
}

// Complete marks the progress bar as complete
func (pb *ProgressBar) Complete() {
	bar := strings.Repeat("█", pb.Width)
	pb.logger.Info(fmt.Sprintf("[%s] 100.0%% ✓ Complete", bar))
}

// formatDuration formats a duration for human readability
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// Stages shows multi-stage progress (like a build pipeline)
type Stages struct {
	stages  []string
	current int
	logger  otelzap.LoggerWithCtx
}

// NewStages creates a multi-stage progress tracker
func NewStages(ctx context.Context, stages []string) *Stages {
	return &Stages{
		stages: stages,
		logger: otelzap.Ctx(ctx),
	}
}

// Start begins a stage
func (s *Stages) Start(index int) {
	s.current = index
	for i, stage := range s.stages {
		status := "○"
		if i < index {
			status = "✓"
		} else if i == index {
			status = "⟳"
		}
		s.logger.Info(fmt.Sprintf("  %s %d/%d %s",
			status,
			i+1,
			len(s.stages),
			stage))
	}
}

// Complete marks current stage as complete
func (s *Stages) Complete(index int) {
	s.logger.Info(fmt.Sprintf("  ✓ %d/%d %s",
		index+1,
		len(s.stages),
		s.stages[index]))
}

// Fail marks current stage as failed
func (s *Stages) Fail(index int, err error) {
	s.logger.Error(fmt.Sprintf("  ✗ %d/%d %s",
		index+1,
		len(s.stages),
		s.stages[index]),
		zap.Error(err))
}
