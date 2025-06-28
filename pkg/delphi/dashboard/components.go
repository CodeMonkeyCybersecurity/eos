/* pkg/delphi/dashboard/components.go */

package dashboard

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
)

// Common color palette for consistent styling
var (
	ColorPrimary    = lipgloss.Color("#00ffff")  // Cyan
	ColorSuccess    = lipgloss.Color("#00ff00")  // Green
	ColorWarning    = lipgloss.Color("#ffaa00")  // Orange
	ColorError      = lipgloss.Color("#ff0000")  // Red
	ColorInfo       = lipgloss.Color("#0099ff")  // Blue
	ColorMuted      = lipgloss.Color("#666666")  // Gray
	ColorBackground = lipgloss.Color("#1a1a2e")  // Dark blue
	ColorBorder     = lipgloss.Color("#3d5a80")  // Medium blue
)

// StatusIndicator represents different status types
type StatusIndicator int

const (
	StatusHealthy StatusIndicator = iota
	StatusWarning
	StatusCritical
	StatusUnknown
	StatusActive
	StatusInactive
	StatusEnabled
	StatusDisabled
)

// String returns the emoji representation of the status
func (s StatusIndicator) String() string {
	switch s {
	case StatusHealthy:
		return "🟢"
	case StatusWarning:
		return "🟡"
	case StatusCritical:
		return "🔴"
	case StatusUnknown:
		return "⚫"
	case StatusActive:
		return "✅"
	case StatusInactive:
		return "❌"
	case StatusEnabled:
		return "🔛"
	case StatusDisabled:
		return "🔴"
	default:
		return "❓"
	}
}

// Color returns the lipgloss color for the status
func (s StatusIndicator) Color() lipgloss.Color {
	switch s {
	case StatusHealthy, StatusActive, StatusEnabled:
		return ColorSuccess
	case StatusWarning:
		return ColorWarning
	case StatusCritical, StatusInactive, StatusDisabled:
		return ColorError
	case StatusUnknown:
		return ColorMuted
	default:
		return ColorInfo
	}
}

// CommonStyles provides consistent styling across all dashboard modules
type CommonStyles struct {
	// Header styles
	Title       lipgloss.Style
	Subtitle    lipgloss.Style
	HeaderBar   lipgloss.Style
	
	// Content styles
	Panel       lipgloss.Style
	Card        lipgloss.Style
	Table       lipgloss.Style
	
	// Text styles
	Primary     lipgloss.Style
	Secondary   lipgloss.Style
	Success     lipgloss.Style
	Warning     lipgloss.Style
	Error       lipgloss.Style
	Muted       lipgloss.Style
	
	// Interactive styles
	Selected    lipgloss.Style
	Focused     lipgloss.Style
	Button      lipgloss.Style
	
	// Status styles
	StatusGood  lipgloss.Style
	StatusWarn  lipgloss.Style
	StatusBad   lipgloss.Style
	
	// Layout styles
	Border      lipgloss.Style
	Separator   lipgloss.Style
	Footer      lipgloss.Style
}

// NewCommonStyles creates a new set of common styles
func NewCommonStyles() CommonStyles {
	return CommonStyles{
		// Headers
		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Background(ColorBackground).
			Padding(0, 1).
			MarginBottom(1),
			
		Subtitle: lipgloss.NewStyle().
			Foreground(ColorInfo).
			Italic(true).
			MarginBottom(1),
			
		HeaderBar: lipgloss.NewStyle().
			Background(ColorBackground).
			Foreground(ColorPrimary).
			Padding(0, 1).
			Bold(true),
			
		// Content
		Panel: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1).
			MarginBottom(1),
			
		Card: lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(ColorBorder).
			Padding(1).
			MarginRight(1),
			
		Table: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder),
			
		// Text
		Primary: lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true),
			
		Secondary: lipgloss.NewStyle().
			Foreground(ColorInfo),
			
		Success: lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true),
			
		Warning: lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true),
			
		Error: lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true),
			
		Muted: lipgloss.NewStyle().
			Foreground(ColorMuted),
			
		// Interactive
		Selected: lipgloss.NewStyle().
			Background(ColorPrimary).
			Foreground(lipgloss.Color("#000000")).
			Bold(true),
			
		Focused: lipgloss.NewStyle().
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(ColorPrimary),
			
		Button: lipgloss.NewStyle().
			Background(ColorBorder).
			Foreground(lipgloss.Color("#ffffff")).
			Padding(0, 2).
			MarginRight(1),
			
		// Status
		StatusGood: lipgloss.NewStyle().
			Foreground(ColorSuccess),
			
		StatusWarn: lipgloss.NewStyle().
			Foreground(ColorWarning),
			
		StatusBad: lipgloss.NewStyle().
			Foreground(ColorError),
			
		// Layout
		Border: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder),
			
		Separator: lipgloss.NewStyle().
			Foreground(ColorBorder),
			
		Footer: lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1),
	}
}

// StatusBadge creates a styled status badge
func (s CommonStyles) StatusBadge(status StatusIndicator, text string) string {
	style := s.Muted
	switch status {
	case StatusHealthy, StatusActive, StatusEnabled:
		style = s.StatusGood
	case StatusWarning:
		style = s.StatusWarn
	case StatusCritical, StatusInactive, StatusDisabled:
		style = s.StatusBad
	}
	
	return style.Render(fmt.Sprintf("%s %s", status.String(), text))
}

// MetricCard creates a styled metric display card
func (s CommonStyles) MetricCard(title, value, unit string, status StatusIndicator) string {
	titleStyle := s.Muted
	valueStyle := s.Primary
	
	if status != StatusUnknown {
		valueStyle = lipgloss.NewStyle().Foreground(status.Color()).Bold(true)
	}
	
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		titleStyle.Render(title),
		valueStyle.Render(value+" "+unit),
	)
	
	return s.Card.Render(content)
}

// ProgressBar creates a styled progress bar
func (s CommonStyles) ProgressBar(current, max int, label string) string {
	if max == 0 {
		return s.Muted.Render(label + ": N/A")
	}
	
	percentage := float64(current) / float64(max)
	barWidth := 20
	filled := int(percentage * float64(barWidth))
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	
	var color lipgloss.Color
	switch {
	case percentage >= 0.8:
		color = ColorError
	case percentage >= 0.6:
		color = ColorWarning
	default:
		color = ColorSuccess
	}
	
	styledBar := lipgloss.NewStyle().Foreground(color).Render(bar)
	text := fmt.Sprintf("%s [%s] %d/%d (%.1f%%)", label, styledBar, current, max, percentage*100)
	
	return text
}

// KeyValuePair creates a styled key-value pair display
func (s CommonStyles) KeyValuePair(key, value string, highlight bool) string {
	keyStyle := s.Muted
	valueStyle := s.Primary
	
	if highlight {
		keyStyle = s.Secondary
		valueStyle = s.Selected
	}
	
	return keyStyle.Render(key+": ") + valueStyle.Render(value)
}

// Section creates a titled section with content
func (s CommonStyles) Section(title, content string) string {
	header := s.Subtitle.Render(title)
	body := s.Panel.Render(content)
	
	return lipgloss.JoinVertical(lipgloss.Left, header, body)
}

// Timeline creates a timeline-style display of events
func (s CommonStyles) Timeline(events []TimelineEvent) string {
	if len(events) == 0 {
		return s.Muted.Render("No events")
	}
	
	var lines []string
	for i, event := range events {
		var connector string
		if i == 0 {
			connector = "┌─"
		} else if i == len(events)-1 {
			connector = "└─"
		} else {
			connector = "├─"
		}
		
		timestamp := s.Muted.Render(event.Time.Format("15:04:05"))
		
		var statusStyle lipgloss.Style
		switch event.Status {
		case StatusHealthy, StatusActive:
			statusStyle = s.Success
		case StatusWarning:
			statusStyle = s.Warning
		case StatusCritical, StatusInactive:
			statusStyle = s.Error
		default:
			statusStyle = s.Primary
		}
		
		message := statusStyle.Render(event.Message)
		line := fmt.Sprintf("%s %s %s", connector, timestamp, message)
		lines = append(lines, line)
	}
	
	return strings.Join(lines, "\n")
}

// TimelineEvent represents an event in a timeline
type TimelineEvent struct {
	Time    time.Time
	Status  StatusIndicator
	Message string
}

// LoadingSpinner creates a loading spinner with message
func (s CommonStyles) LoadingSpinner(spinner spinner.Model, message string) string {
	return fmt.Sprintf("%s %s", spinner.View(), s.Primary.Render(message))
}

// ProgressIndicator creates a simple text-based progress indicator
func (s CommonStyles) ProgressIndicator(percentage float64, label string) string {
	barWidth := 20
	filled := int(percentage * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	
	var color lipgloss.Color
	switch {
	case percentage >= 0.8:
		color = ColorError
	case percentage >= 0.6:
		color = ColorWarning
	default:
		color = ColorSuccess
	}
	
	styledBar := lipgloss.NewStyle().Foreground(color).Render(bar)
	progressText := fmt.Sprintf("%.1f%%", percentage*100)
	
	return lipgloss.JoinVertical(
		lipgloss.Left,
		s.Secondary.Render(label),
		fmt.Sprintf("[%s] %s", styledBar, progressText),
	)
}

// Grid creates a grid layout of items
func (s CommonStyles) Grid(items []string, columns int, width int) string {
	if len(items) == 0 {
		return ""
	}
	
	colWidth := width / columns
	var rows []string
	
	for i := 0; i < len(items); i += columns {
		var rowItems []string
		for j := 0; j < columns && i+j < len(items); j++ {
			item := items[i+j]
			// Ensure item fits in column width
			if lipgloss.Width(item) > colWidth-2 {
				item = item[:colWidth-5] + "..."
			}
			rowItems = append(rowItems, lipgloss.NewStyle().Width(colWidth).Render(item))
		}
		row := lipgloss.JoinHorizontal(lipgloss.Top, rowItems...)
		rows = append(rows, row)
	}
	
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

// Alert creates a styled alert box
func (s CommonStyles) Alert(alertType StatusIndicator, title, message string) string {
	var style lipgloss.Style
	var icon string
	
	switch alertType {
	case StatusHealthy:
		style = s.Success
		icon = "✓"
	case StatusWarning:
		style = s.Warning
		icon = "⚠"
	case StatusCritical:
		style = s.Error
		icon = "✗"
	default:
		style = s.Primary
		icon = "ℹ"
	}
	
	header := style.Bold(true).Render(fmt.Sprintf("%s %s", icon, title))
	body := s.Secondary.Render(message)
	
	content := lipgloss.JoinVertical(lipgloss.Left, header, body)
	
	return s.Panel.
		BorderForeground(style.GetForeground()).
		Render(content)
}

// HorizontalRule creates a horizontal separator
func (s CommonStyles) HorizontalRule(width int, char string) string {
	if char == "" {
		char = "─"
	}
	return s.Separator.Render(strings.Repeat(char, width))
}

// Tabs creates a tab navigation bar
func (s CommonStyles) Tabs(tabs []string, activeIndex int) string {
	var renderedTabs []string
	
	for i, tab := range tabs {
		var style lipgloss.Style
		if i == activeIndex {
			style = s.Selected
		} else {
			style = s.Button
		}
		renderedTabs = append(renderedTabs, style.Render(tab))
	}
	
	return lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
}