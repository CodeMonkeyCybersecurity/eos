/* pkg/delphi/dashboard/services_module.go */

package dashboard

import (
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DelphiServices contains the list of all Delphi pipeline services
// This should match the service registry in cmd/delphi/services/service_registry.go
var DelphiServices = []string{
	"delphi-listener",
	"delphi-agent-enricher",
	"alert-to-db",
	"prompt-ab-tester",
	"llm-worker",
	"ab-test-analyzer",
	"email-structurer",
	"email-formatter",
	"email-sender",
	"parser-monitor",
}

// ServiceStatus represents the status of a single service
type ServiceStatus struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	IsActive    bool      `json:"is_active"`
	IsEnabled   bool      `json:"is_enabled"`
	LastUpdate  time.Time `json:"last_update"`
	CPU         float64   `json:"cpu_percent"`
	Memory      int64     `json:"memory_mb"`
	Uptime      string    `json:"uptime"`
	PID         int       `json:"pid"`
	Description string    `json:"description"`
}

// servicesKeyMap defines keyboard shortcuts for the services module
type servicesKeyMap struct {
	StartService   key.Binding
	StopService    key.Binding
	RestartService key.Binding
	EnableService  key.Binding
	DisableService key.Binding
	ViewLogs       key.Binding
	HealthCheck    key.Binding
	Deploy         key.Binding
	Config         key.Binding
	RefreshData    key.Binding
	SelectUp       key.Binding
	SelectDown     key.Binding
	ToggleDetails  key.Binding
	Help           key.Binding
}

// servicesKeys defines the keyboard shortcuts for services management
var servicesKeys = servicesKeyMap{
	StartService: key.NewBinding(
		key.WithKeys("s"),
		key.WithHelp("s", "start service"),
	),
	StopService: key.NewBinding(
		key.WithKeys("S"),
		key.WithHelp("S", "stop service"),
	),
	RestartService: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "restart service"),
	),
	EnableService: key.NewBinding(
		key.WithKeys("e"),
		key.WithHelp("e", "enable service"),
	),
	DisableService: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "disable service"),
	),
	ViewLogs: key.NewBinding(
		key.WithKeys("l"),
		key.WithHelp("l", "view logs"),
	),
	HealthCheck: key.NewBinding(
		key.WithKeys("h"),
		key.WithHelp("h", "health check"),
	),
	Deploy: key.NewBinding(
		key.WithKeys("D"),
		key.WithHelp("D", "deploy/update"),
	),
	Config: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "view config"),
	),
	RefreshData: key.NewBinding(
		key.WithKeys("ctrl+r"),
		key.WithHelp("ctrl+r", "refresh"),
	),
	SelectUp: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "move up"),
	),
	SelectDown: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "move down"),
	),
	ToggleDetails: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "toggle details"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
}

// ShortHelp returns the short help for services module
func (k servicesKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.SelectUp, k.SelectDown, k.StartService, k.StopService, k.Help}
}

// FullHelp returns the full help for services module
func (k servicesKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.SelectUp, k.SelectDown, k.ToggleDetails, k.RefreshData},
		{k.StartService, k.StopService, k.RestartService, k.EnableService, k.DisableService},
		{k.ViewLogs, k.HealthCheck, k.Deploy, k.Config},
		{k.Help},
	}
}

// serviceOperation represents an operation being performed on a service
type serviceOperation struct {
	serviceName string
	operation   string
	inProgress  bool
	result      string
	err         error
}

// ServicesModule implements the services management dashboard
type ServicesModule struct {
	BaseModule

	// State
	rc            *eos_io.RuntimeContext
	db            *sql.DB
	services      []ServiceStatus
	selectedIndex int
	showDetails   bool
	lastRefresh   time.Time

	// UI components
	table table.Model
	help  help.Model
	keys  servicesKeyMap

	// Operations
	currentOp      *serviceOperation
	operationQueue []serviceOperation

	// Styles
	titleStyle   lipgloss.Style
	tableStyle   lipgloss.Style
	detailsStyle lipgloss.Style
	statusStyle  lipgloss.Style
	errorStyle   lipgloss.Style
	successStyle lipgloss.Style
}

// NewServicesModule creates a new services management module
func NewServicesModule(rc *eos_io.RuntimeContext, db *sql.DB) *ServicesModule {
	base := NewBaseModule("Services", ModuleServices, "Interactive management of Delphi pipeline services")

	// Initialize table
	columns := []table.Column{
		{Title: "Service", Width: 20},
		{Title: "Status", Width: 15},
		{Title: "Enabled", Width: 8},
		{Title: "CPU%", Width: 8},
		{Title: "Memory", Width: 10},
		{Title: "Uptime", Width: 12},
		{Title: "PID", Width: 8},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	// Set table styles
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	// Define styles
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Background(lipgloss.Color("235")).
		Padding(0, 1)

	tableStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238"))

	detailsStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238")).
		Padding(1).
		MarginTop(1)

	statusStyle := lipgloss.NewStyle().
		Padding(0, 1).
		MarginBottom(1)

	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")).
		Bold(true)

	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("46")).
		Bold(true)

	return &ServicesModule{
		BaseModule:     base,
		rc:             rc,
		db:             db,
		services:       []ServiceStatus{},
		selectedIndex:  0,
		showDetails:    false,
		table:          t,
		help:           help.New(),
		keys:           servicesKeys,
		titleStyle:     titleStyle,
		tableStyle:     tableStyle,
		detailsStyle:   detailsStyle,
		statusStyle:    statusStyle,
		errorStyle:     errorStyle,
		successStyle:   successStyle,
		operationQueue: []serviceOperation{},
	}
}

// refreshServicesMsg is sent when services data should be refreshed
type refreshServicesMsg struct{}

// serviceOperationMsg is sent when a service operation completes
type serviceOperationMsg struct {
	serviceName string
	operation   string
	success     bool
	message     string
	err         error
}

// Init initializes the services module
func (m *ServicesModule) Init() tea.Cmd {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Initializing services management module")

	return tea.Batch(
		m.refreshServices(),
		tea.Tick(time.Second*10, func(t time.Time) tea.Msg {
			return refreshServicesMsg{}
		}),
	)
}

// Update handles services module events
func (m *ServicesModule) Update(msg tea.Msg) (DashboardModule, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case refreshServicesMsg:
		// Auto-refresh services data
		cmds = append(cmds, m.refreshServices())
		cmds = append(cmds, tea.Tick(time.Second*10, func(t time.Time) tea.Msg {
			return refreshServicesMsg{}
		}))

	case serviceOperationMsg:
		// Handle completed service operation
		m.handleOperationComplete(msg)
		m.processNextOperation()

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.SelectUp):
			if m.selectedIndex > 0 {
				m.selectedIndex--
				m.updateTableCursor()
			}

		case key.Matches(msg, m.keys.SelectDown):
			if m.selectedIndex < len(m.services)-1 {
				m.selectedIndex++
				m.updateTableCursor()
			}

		case key.Matches(msg, m.keys.ToggleDetails):
			m.showDetails = !m.showDetails

		case key.Matches(msg, m.keys.RefreshData):
			cmds = append(cmds, m.refreshServices())

		case key.Matches(msg, m.keys.StartService):
			if m.currentOp == nil && len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performServiceOperation(serviceName, "start"))
			}

		case key.Matches(msg, m.keys.StopService):
			if m.currentOp == nil && len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performServiceOperation(serviceName, "stop"))
			}

		case key.Matches(msg, m.keys.RestartService):
			if m.currentOp == nil && len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performServiceOperation(serviceName, "restart"))
			}

		case key.Matches(msg, m.keys.EnableService):
			if m.currentOp == nil && len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performServiceOperation(serviceName, "enable"))
			}

		case key.Matches(msg, m.keys.DisableService):
			if m.currentOp == nil && len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performServiceOperation(serviceName, "disable"))
			}

		case key.Matches(msg, m.keys.ViewLogs):
			if len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.viewServiceLogs(serviceName))
			}

		case key.Matches(msg, m.keys.HealthCheck):
			if len(m.services) > 0 {
				serviceName := m.services[m.selectedIndex].Name
				cmds = append(cmds, m.performHealthCheck(serviceName))
			}
		}
	}

	// Update table
	var tableCmd tea.Cmd
	m.table, tableCmd = m.table.Update(msg)
	if tableCmd != nil {
		cmds = append(cmds, tableCmd)
	}

	return m, tea.Batch(cmds...)
}

// View renders the services module
func (m *ServicesModule) View() string {
	if len(m.services) == 0 {
		return m.statusStyle.Render("Loading services...")
	}

	// Build header
	header := m.titleStyle.Render(" Services Management")

	// Add current operation status
	if m.currentOp != nil {
		// Capitalize first letter manually to avoid deprecated strings.Title
		operation := m.currentOp.operation
		if len(operation) > 0 {
			operation = strings.ToUpper(operation[:1]) + operation[1:]
		}
		opStatus := fmt.Sprintf("⚙️  %s %s...", operation, m.currentOp.serviceName)
		header += "\n" + m.statusStyle.Render(opStatus)
	}

	// Build main table view
	tableView := m.tableStyle.Render(m.table.View())

	// Build details view if enabled
	detailsView := ""
	if m.showDetails && len(m.services) > 0 {
		service := m.services[m.selectedIndex]
		detailsView = m.renderServiceDetails(service)
	}

	// Build help view
	helpView := m.help.ShortHelpView(m.keys.ShortHelp())

	// Combine all sections
	sections := []string{header, tableView}
	if detailsView != "" {
		sections = append(sections, detailsView)
	}
	sections = append(sections, helpView)

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// refreshServices updates the services data
func (m *ServicesModule) refreshServices() tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		logger := otelzap.Ctx(m.rc.Ctx)
		logger.Debug("Refreshing services data")

		var services []ServiceStatus

		for _, serviceName := range DelphiServices {
			status := m.getServiceStatus(serviceName)
			services = append(services, status)
		}

		m.services = services
		m.lastRefresh = time.Now()
		m.updateTableRows()

		logger.Debug("Services data refreshed",
			zap.Int("service_count", len(services)),
			zap.Time("last_refresh", m.lastRefresh))

		return refreshServicesMsg{}
	})
}

// getServiceStatus retrieves the current status of a service
func (m *ServicesModule) getServiceStatus(serviceName string) ServiceStatus {
	logger := otelzap.Ctx(m.rc.Ctx)

	status := ServiceStatus{
		Name:        serviceName,
		Status:      "⚫ not installed",
		IsActive:    false,
		IsEnabled:   false,
		LastUpdate:  time.Now(),
		CPU:         0,
		Memory:      0,
		Uptime:      "0s",
		PID:         0,
		Description: m.getServiceDescription(serviceName),
	}

	// Check if service exists
	if !eos_unix.ServiceExists(serviceName) {
		return status
	}

	// Check if service is active
	err := eos_unix.CheckServiceStatus(m.rc.Ctx, serviceName)
	if err == nil {
		status.Status = "🟢 active"
		status.IsActive = true
	} else {
		status.Status = "🔴 inactive"
		status.IsActive = false
	}

	// Check if service is enabled
	if m.isServiceEnabled(serviceName) {
		status.IsEnabled = true
	}

	// Get additional metrics if service is active
	if status.IsActive {
		status.CPU, status.Memory, status.Uptime, status.PID = m.getServiceMetrics(serviceName)
	}

	logger.Debug("Retrieved service status",
		zap.String("service", serviceName),
		zap.String("status", status.Status),
		zap.Bool("active", status.IsActive),
		zap.Bool("enabled", status.IsEnabled))

	return status
}

// getServiceDescription returns a description for the service
func (m *ServicesModule) getServiceDescription(serviceName string) string {
	descriptions := map[string]string{
		"delphi-listener":       "Webhook receiver for Wazuh alerts",
		"delphi-agent-enricher": "Agent metadata enrichment service",
		"llm-worker":            "LLM processing service",
		"prompt-ab-tester":      "A/B testing for prompt optimization",
		"ab-test-analyzer":      "A/B test analysis worker",
		"alert-to-db":           "Database operations for alerts",
		"email-structurer":      "Email structuring with prompt-aware parsing",
		"email-formatter":       "HTML/text email generation",
		"email-sender":          "SMTP delivery service",
	}

	if desc, exists := descriptions[serviceName]; exists {
		return desc
	}
	return "Delphi pipeline service"
}

// isServiceEnabled checks if a service is enabled
func (m *ServicesModule) isServiceEnabled(serviceName string) bool {
	cmd := exec.CommandContext(m.rc.Ctx, "systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "enabled"
}

// getServiceMetrics retrieves CPU, memory, uptime, and PID for an active service
func (m *ServicesModule) getServiceMetrics(serviceName string) (float64, int64, string, int) {
	// This would typically use systemctl show or parse /proc for real metrics
	// For now, return placeholder values
	_ = serviceName // Placeholder to avoid unused parameter warning
	return 0.0, 0, "0s", 0
}

// updateTableRows updates the table with current services data
func (m *ServicesModule) updateTableRows() {
	rows := make([]table.Row, len(m.services))

	for i, service := range m.services {
		enabledStr := "No"
		if service.IsEnabled {
			enabledStr = "Yes"
		}

		cpuStr := fmt.Sprintf("%.1f", service.CPU)
		memoryStr := fmt.Sprintf("%d MB", service.Memory)
		pidStr := fmt.Sprintf("%d", service.PID)
		if service.PID == 0 {
			pidStr = "-"
		}

		rows[i] = table.Row{
			service.Name,
			service.Status,
			enabledStr,
			cpuStr,
			memoryStr,
			service.Uptime,
			pidStr,
		}
	}

	m.table.SetRows(rows)
	m.updateTableCursor()
}

// updateTableCursor updates the table cursor position
func (m *ServicesModule) updateTableCursor() {
	if len(m.services) > 0 && m.selectedIndex < len(m.services) {
		m.table.SetCursor(m.selectedIndex)
	}
}

// renderServiceDetails renders detailed information for the selected service
func (m *ServicesModule) renderServiceDetails(service ServiceStatus) string {
	details := fmt.Sprintf(`Service Details: %s

Description: %s
Status: %s
Enabled: %v
CPU Usage: %.1f%%
Memory: %d MB
Uptime: %s
Process ID: %d
Last Updated: %s`,
		service.Name,
		service.Description,
		service.Status,
		service.IsEnabled,
		service.CPU,
		service.Memory,
		service.Uptime,
		service.PID,
		service.LastUpdate.Format("15:04:05"))

	return m.detailsStyle.Render(details)
}

// performServiceOperation performs a service operation asynchronously
func (m *ServicesModule) performServiceOperation(serviceName, operation string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		logger := otelzap.Ctx(m.rc.Ctx)
		logger.Info("Performing service operation",
			zap.String("service", serviceName),
			zap.String("operation", operation))

		m.currentOp = &serviceOperation{
			serviceName: serviceName,
			operation:   operation,
			inProgress:  true,
		}

		var err error
		var message string

		switch operation {
		case "start":
			err = eos_unix.StartSystemdUnitWithRetry(m.rc.Ctx, serviceName, 3, 2)
			message = fmt.Sprintf("Service %s started successfully", serviceName)
		case "stop":
			err = eos_unix.StopSystemdUnitWithRetry(m.rc.Ctx, serviceName, 3, 2)
			message = fmt.Sprintf("Service %s stopped successfully", serviceName)
		case "restart":
			err = eos_unix.RestartSystemdUnitWithRetry(m.rc.Ctx, serviceName, 3, 2)
			message = fmt.Sprintf("Service %s restarted successfully", serviceName)
		case "enable":
			err = m.enableService(serviceName)
			message = fmt.Sprintf("Service %s enabled successfully", serviceName)
		case "disable":
			err = m.disableService(serviceName)
			message = fmt.Sprintf("Service %s disabled successfully", serviceName)
		default:
			err = fmt.Errorf("unknown operation: %s", operation)
		}

		success := err == nil
		if err != nil {
			message = fmt.Sprintf("Failed to %s service %s: %v", operation, serviceName, err)
			logger.Error("Service operation failed",
				zap.String("service", serviceName),
				zap.String("operation", operation),
				zap.Error(err))
		} else {
			logger.Info("Service operation completed successfully",
				zap.String("service", serviceName),
				zap.String("operation", operation))
		}

		return serviceOperationMsg{
			serviceName: serviceName,
			operation:   operation,
			success:     success,
			message:     message,
			err:         err,
		}
	})
}

// handleOperationComplete handles the completion of a service operation
func (m *ServicesModule) handleOperationComplete(msg serviceOperationMsg) {
	if m.currentOp != nil && m.currentOp.serviceName == msg.serviceName {
		m.currentOp.inProgress = false
		m.currentOp.result = msg.message
		m.currentOp.err = msg.err
		m.currentOp = nil
	}

	// Refresh services data after operation
	go func() {
		time.Sleep(time.Second) // Brief delay to allow service state to settle
		m.refreshServices()
	}()
}

// processNextOperation processes the next queued operation
func (m *ServicesModule) processNextOperation() {
	if m.currentOp == nil && len(m.operationQueue) > 0 {
		// Process next operation from queue
		next := m.operationQueue[0]
		m.operationQueue = m.operationQueue[1:]
		m.performServiceOperation(next.serviceName, next.operation)
	}
}

// viewServiceLogs opens the service logs (placeholder implementation)
func (m *ServicesModule) viewServiceLogs(serviceName string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		logger := otelzap.Ctx(m.rc.Ctx)
		logger.Info("Viewing service logs",
			zap.String("service", serviceName))

		// This would typically open logs in a separate view or external tool
		// For now, just log the action
		return serviceOperationMsg{
			serviceName: serviceName,
			operation:   "view-logs",
			success:     true,
			message:     fmt.Sprintf("Opened logs for %s", serviceName),
		}
	})
}

// performHealthCheck performs a health check on the service
func (m *ServicesModule) performHealthCheck(serviceName string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		logger := otelzap.Ctx(m.rc.Ctx)
		logger.Info("Performing health check",
			zap.String("service", serviceName))

		// This would typically perform a comprehensive health check
		// For now, just check if the service is running
		err := eos_unix.CheckServiceStatus(m.rc.Ctx, serviceName)
		success := err == nil
		message := fmt.Sprintf("Health check for %s: %s", serviceName, map[bool]string{true: "Healthy", false: "Unhealthy"}[success])

		return serviceOperationMsg{
			serviceName: serviceName,
			operation:   "health-check",
			success:     success,
			message:     message,
			err:         err,
		}
	})
}

// Implement remaining DashboardModule interface methods

func (m *ServicesModule) KeyMap() []key.Binding {
	return []key.Binding{
		m.keys.StartService, m.keys.StopService, m.keys.RestartService,
		m.keys.EnableService, m.keys.DisableService, m.keys.ViewLogs,
		m.keys.HealthCheck, m.keys.RefreshData,
	}
}

func (m *ServicesModule) ShortHelp() []key.Binding {
	return m.keys.ShortHelp()
}

func (m *ServicesModule) FullHelp() [][]key.Binding {
	return m.keys.FullHelp()
}

func (m *ServicesModule) OnEnter() tea.Cmd {
	m.SetActive(true)
	return m.refreshServices()
}

func (m *ServicesModule) OnExit() tea.Cmd {
	m.SetActive(false)
	return nil
}

func (m *ServicesModule) Refresh() tea.Cmd {
	return m.refreshServices()
}

func (m *ServicesModule) CanRefresh() bool {
	return true
}

// enableService enables a systemd service
func (m *ServicesModule) enableService(serviceName string) error {
	cmd := exec.CommandContext(m.rc.Ctx, "systemctl", "enable", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable service %s: %w (output: %s)", serviceName, err, string(output))
	}
	return nil
}

// disableService disables a systemd service
func (m *ServicesModule) disableService(serviceName string) error {
	cmd := exec.CommandContext(m.rc.Ctx, "systemctl", "disable", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable service %s: %w (output: %s)", serviceName, err, string(output))
	}
	return nil
}
