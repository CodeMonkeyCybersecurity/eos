/* pkg/delphi/dashboard_ui.go */

package delphi

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Define color scheme and styles for the dashboard
var (
	// Status colors - like traffic lights for the pipeline
	healthyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	warningStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffaa00"))
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))

	// UI element styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00ffff")).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(0, 1)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3d5a80")).
			Padding(1)

	selectedTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000000")).
				Background(lipgloss.Color("#00ffff")).
				Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#666666")).
				Padding(0, 1)

	selectedRowStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000000")).
				Background(lipgloss.Color("#00ffff"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff0000")).
			Bold(true)
)

// keyMap defines keyboard shortcuts for the dashboard
type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Left    key.Binding
	Right   key.Binding
	Help    key.Binding
	Quit    key.Binding
	Refresh key.Binding
}

// Define keyboard shortcuts with descriptions
var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "move down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "prev view"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "next view"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("r", "ctrl+r"),
		key.WithHelp("r", "refresh data"),
	),
}

// ShortHelp returns keybindings to be shown in the mini help view
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Left, k.Right, k.Refresh, k.Help, k.Quit}
}

// FullHelp returns keybindings for the expanded help view
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Refresh, k.Help, k.Quit},
	}
}

// Message types for updating the dashboard
type refreshCompleteMsg struct {
	data *DashboardData
}

type errMsg struct {
	err error
}

// DashboardModel represents the dashboard's application state
type DashboardModel struct {
	// Core components
	monitor     *DashboardMonitor
	currentView ViewType
	width       int
	height      int
	rc          *eos_io.RuntimeContext

	// Data storage
	data *DashboardData

	// UI components
	healthTable     table.Model
	bottleneckTable table.Model
	failureTable    table.Model

	// State management
	loading        bool
	loadingSpinner spinner.Model
	lastUpdate     time.Time
	err            error

	// Navigation and help
	help     help.Model
	keys     keyMap
	showHelp bool
}

// InitializeDashboard creates a new dashboard model
func InitializeDashboard(db *sql.DB, rc *eos_io.RuntimeContext) DashboardModel {
	monitor := NewDashboardMonitor(db)

	// Set up loading spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Initialize model
	m := DashboardModel{
		monitor:        monitor,
		currentView:    ViewPipelineHealth,
		loadingSpinner: s,
		help:           help.New(),
		keys:           keys,
		loading:        true,
		rc:             rc,
	}

	// Create data tables
	m.healthTable = createHealthTable()
	m.bottleneckTable = createBottleneckTable()
	m.failureTable = createFailureTable()

	return m
}

// Init returns the initial command for the dashboard
func (m DashboardModel) Init() tea.Cmd {
	return tea.Batch(
		m.loadingSpinner.Tick,
		m.loadCurrentViewData(),
	)
}

// loadCurrentViewData fetches data for the current view
func (m DashboardModel) loadCurrentViewData() tea.Cmd {
	return func() tea.Msg {
		data, err := m.monitor.GetAllDashboardData(m.rc)
		if err != nil {
			return errMsg{err}
		}
		return refreshCompleteMsg{data}
	}
}

// Update handles events and updates the model
func (m DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit

		case key.Matches(msg, m.keys.Left):
			m.currentView = m.prevView()
			m.updateTablesWithData()

		case key.Matches(msg, m.keys.Right):
			m.currentView = m.nextView()
			m.updateTablesWithData()

		case key.Matches(msg, m.keys.Help):
			m.showHelp = !m.showHelp

		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			return m, tea.Batch(
				m.loadingSpinner.Tick,
				m.loadCurrentViewData(),
			)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Update table sizes to fit new window
		tableHeight := m.height - 15 // Leave room for header and footer
		if tableHeight < 5 {
			tableHeight = 5
		}
		m.healthTable.SetHeight(tableHeight)
		m.bottleneckTable.SetHeight(tableHeight)
		m.failureTable.SetHeight(tableHeight)

		m.help.Width = msg.Width

	case refreshCompleteMsg:
		m.loading = false
		m.lastUpdate = time.Now()
		m.data = msg.data
		m.updateTablesWithData()
		return m, nil

	case errMsg:
		m.err = msg.err
		m.loading = false
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			m.loadingSpinner, cmd = m.loadingSpinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	// Update the current table based on view
	switch m.currentView {
	case ViewPipelineHealth:
		m.healthTable, cmd = m.healthTable.Update(msg)
	case ViewBottlenecks:
		m.bottleneckTable, cmd = m.bottleneckTable.Update(msg)
	case ViewRecentFailures:
		m.failureTable, cmd = m.failureTable.Update(msg)
	}

	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View renders the dashboard
func (m DashboardModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	// Build the header with navigation
	header := m.renderHeader()

	var content string
	if m.showHelp {
		content = m.help.View(m.keys)
	} else if m.loading {
		content = lipgloss.Place(
			m.width,
			m.height-10,
			lipgloss.Center,
			lipgloss.Center,
			m.loadingSpinner.View()+" Loading dashboard data...",
		)
	} else if m.err != nil {
		content = lipgloss.Place(
			m.width,
			m.height-10,
			lipgloss.Center,
			lipgloss.Center,
			errorStyle.Render("Error: "+m.err.Error()),
		)
	} else {
		content = m.renderCurrentView()
	}

	// Build the footer with help and status
	footer := m.renderFooter()

	// Combine all elements
	return lipgloss.JoinVertical(
		lipgloss.Top,
		header,
		content,
		footer,
	)
}

// renderHeader creates the top navigation bar
func (m DashboardModel) renderHeader() string {
	views := []ViewType{
		ViewPipelineHealth,
		ViewBottlenecks,
		ViewParserPerformance,
		ViewRecentFailures,
		ViewDailySummary,
	}

	var tabs []string
	for _, v := range views {
		style := inactiveTabStyle
		if v == m.currentView {
			style = selectedTabStyle
		}
		tabs = append(tabs, style.Render(" "+v.String()+" "))
	}

	title := titleStyle.Render(" Delphi Pipeline Monitor")
	navigation := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)

	return lipgloss.JoinVertical(
		lipgloss.Top,
		title,
		navigation,
		strings.Repeat("─", m.width),
	)
}

// renderCurrentView renders the appropriate view based on current selection
func (m DashboardModel) renderCurrentView() string {
	if m.data == nil {
		return "No data available"
	}

	switch m.currentView {
	case ViewPipelineHealth:
		return m.renderPipelineHealth()
	case ViewBottlenecks:
		return m.renderBottlenecks()
	case ViewParserPerformance:
		return m.renderParserPerformance()
	case ViewRecentFailures:
		return m.renderRecentFailures()
	case ViewDailySummary:
		return m.renderDailySummary()
	default:
		return "Unknown view"
	}
}

// renderPipelineHealth creates the pipeline health visualization
func (m DashboardModel) renderPipelineHealth() string {
	if len(m.data.PipelineHealth) == 0 {
		return "No pipeline health data available"
	}

	// Create a visual pipeline flow diagram
	var pipelineFlow strings.Builder
	pipelineFlow.WriteString("\n  Pipeline Flow:\n\n  ")

	// Draw the pipeline stages with visual indicators
	stages := []AlertState{
		AlertStateNew, AlertStateEnriched, AlertStateAnalyzed,
		AlertStateStructured, AlertStateFormatted, AlertStateSent,
	}

	for i, stage := range stages {
		// Find data for this stage
		var stageData *PipelineHealth
		for j := range m.data.PipelineHealth {
			if m.data.PipelineHealth[j].State == stage {
				stageData = &m.data.PipelineHealth[j]
				break
			}
		}

		if stageData != nil {
			// Choose color based on health status
			var style lipgloss.Style
			switch stageData.HealthStatus {
			case "Healthy":
				style = healthyStyle
			case "Monitor":
				style = warningStyle
			default:
				style = criticalStyle
			}

			// Draw the stage box with count
			box := fmt.Sprintf("[%s: %d]", stage, stageData.Count)
			pipelineFlow.WriteString(style.Render(box))
		} else {
			// No data for this stage
			pipelineFlow.WriteString(fmt.Sprintf("[%s: 0]", stage))
		}

		// Draw arrow between stages
		if i < len(stages)-1 {
			pipelineFlow.WriteString(" → ")
		}
	}

	pipelineFlow.WriteString("\n\n")

	return pipelineFlow.String() + m.healthTable.View()
}

// renderBottlenecks creates the bottlenecks view
func (m DashboardModel) renderBottlenecks() string {
	if len(m.data.Bottlenecks) == 0 {
		return "No bottleneck data available"
	}

	return borderStyle.Render(m.bottleneckTable.View())
}

// renderParserPerformance creates the parser performance view
func (m DashboardModel) renderParserPerformance() string {
	if m.data.ParserPerformance == nil {
		return "No parser performance data available"
	}

	pp := m.data.ParserPerformance

	content := fmt.Sprintf(`
Parser Performance Summary

Total Parsed:     %d
Successful:       %d 
Errors:          %d
Success Rate:    %.1f%%
Avg Processing:  %.2fs
Last Parsed:     %s
`,
		pp.ParsedCount,
		pp.SuccessfulCount,
		pp.ErrorCount,
		pp.SuccessRate,
		pp.AvgProcessingTime,
		pp.LastParsed.Format("2006-01-02 15:04:05"),
	)

	return borderStyle.Render(content)
}

// renderRecentFailures creates the recent failures view
func (m DashboardModel) renderRecentFailures() string {
	if len(m.data.RecentFailures) == 0 {
		return "No recent failures"
	}

	return borderStyle.Render(m.failureTable.View())
}

// renderDailySummary creates the daily summary view
func (m DashboardModel) renderDailySummary() string {
	if m.data.DailySummary == nil {
		return "No daily summary data available"
	}

	ds := m.data.DailySummary

	content := fmt.Sprintf(`
Daily Operations Summary - %s

Total Processed:    %d
Successful:         %d
Failed:             %d
Success Rate:       %.1f%%
Avg Processing:     %.2fs
Peak Hour:          %02d:00 (%d alerts)
`,
		ds.Date.Format("2006-01-02"),
		ds.TotalAlertsProcessed,
		ds.TotalAlertsSuccessful,
		ds.TotalAlertsFailed,
		ds.SuccessRate,
		ds.AvgProcessingTime,
		ds.PeakHour,
		ds.PeakHourAlertCount,
	)

	return borderStyle.Render(content)
}

// renderFooter creates the bottom status bar
func (m DashboardModel) renderFooter() string {
	var status string
	if m.data != nil {
		status = fmt.Sprintf("Last updated: %s", m.data.LastUpdated.Format("15:04:05"))
	} else {
		status = "No data"
	}

	helpText := m.help.ShortHelpView(m.keys.ShortHelp())

	return lipgloss.JoinVertical(
		lipgloss.Top,
		strings.Repeat("─", m.width),
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			status,
			strings.Repeat(" ", m.width-lipgloss.Width(status)-lipgloss.Width(helpText)),
			helpText,
		),
	)
}

// Helper methods for navigation
func (m DashboardModel) nextView() ViewType {
	switch m.currentView {
	case ViewPipelineHealth:
		return ViewBottlenecks
	case ViewBottlenecks:
		return ViewParserPerformance
	case ViewParserPerformance:
		return ViewRecentFailures
	case ViewRecentFailures:
		return ViewDailySummary
	case ViewDailySummary:
		return ViewPipelineHealth
	default:
		return ViewPipelineHealth
	}
}

func (m DashboardModel) prevView() ViewType {
	switch m.currentView {
	case ViewPipelineHealth:
		return ViewDailySummary
	case ViewBottlenecks:
		return ViewPipelineHealth
	case ViewParserPerformance:
		return ViewBottlenecks
	case ViewRecentFailures:
		return ViewParserPerformance
	case ViewDailySummary:
		return ViewRecentFailures
	default:
		return ViewPipelineHealth
	}
}

// updateTablesWithData updates table data when view changes or data refreshes
func (m *DashboardModel) updateTablesWithData() {
	if m.data == nil {
		return
	}

	// Update pipeline health table
	var healthRows []table.Row
	for _, ph := range m.data.PipelineHealth {
		healthRows = append(healthRows, table.Row{
			string(ph.State),
			fmt.Sprintf("%d", ph.Count),
			fmt.Sprintf("%.1fs", ph.AvgAgeSeconds),
			ph.HealthStatus + " " + ph.HealthStatusIcon(),
			FormatAge(ph.OldestTimestamp),
		})
	}
	m.healthTable.SetRows(healthRows)

	// Update bottleneck table
	var bottleneckRows []table.Row
	for _, pb := range m.data.Bottlenecks {
		bottleneckRows = append(bottleneckRows, table.Row{
			string(pb.State),
			fmt.Sprintf("%d", pb.Count),
			fmt.Sprintf("%.1fs", pb.AvgProcessingTime),
			fmt.Sprintf("%.1fs", pb.MaxProcessingTime),
			pb.BottleneckSeverity + " " + pb.SeverityIcon(),
		})
	}
	m.bottleneckTable.SetRows(bottleneckRows)

	// Update failure table
	var failureRows []table.Row
	for _, rf := range m.data.RecentFailures {
		failureRows = append(failureRows, table.Row{
			fmt.Sprintf("%d", rf.ID),
			string(rf.State),
			rf.AgentName,
			rf.AlertLevel,
			rf.ErrorMessage[:min(50, len(rf.ErrorMessage))],
			FormatAge(rf.FailedAt),
		})
	}
	m.failureTable.SetRows(failureRows)
}

// Table creation functions
func createHealthTable() table.Model {
	columns := []table.Column{
		{Title: "State", Width: 15},
		{Title: "Count", Width: 10},
		{Title: "Avg Age", Width: 15},
		{Title: "Status", Width: 20},
		{Title: "Oldest", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = selectedRowStyle
	t.SetStyles(s)

	return t
}

func createBottleneckTable() table.Model {
	columns := []table.Column{
		{Title: "State", Width: 15},
		{Title: "Count", Width: 10},
		{Title: "Avg Time", Width: 15},
		{Title: "Max Time", Width: 15},
		{Title: "Severity", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = selectedRowStyle
	t.SetStyles(s)

	return t
}

func createFailureTable() table.Model {
	columns := []table.Column{
		{Title: "ID", Width: 8},
		{Title: "State", Width: 12},
		{Title: "Agent", Width: 15},
		{Title: "Level", Width: 10},
		{Title: "Error", Width: 50},
		{Title: "Age", Width: 15},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = selectedRowStyle
	t.SetStyles(s)

	return t
}
