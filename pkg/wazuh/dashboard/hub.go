/* pkg/wazuh/dashboard/hub.go */

package dashboard

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Hub manages the overall dashboard experience and module navigation
type Hub struct {
	// Core state
	rc       *eos_io.RuntimeContext
	db       *sql.DB
	registry *ModuleRegistry

	// Current state
	currentModule ModuleType
	width         int
	height        int

	// UI components
	help     help.Model
	keys     hubKeyMap
	showHelp bool

	// Status
	lastUpdate time.Time
	err        error
}

// hubKeyMap defines navigation keys for the dashboard hub
type hubKeyMap struct {
	ModulePipeline    key.Binding
	ModuleServices    key.Binding
	ModuleParsers     key.Binding
	ModuleAlerts      key.Binding
	ModulePerformance key.Binding
	ModuleOverview    key.Binding
	NextModule        key.Binding
	PrevModule        key.Binding
	Help              key.Binding
	Quit              key.Binding
	Refresh           key.Binding
}

// hubKeys defines the keyboard shortcuts for hub navigation
var hubKeys = hubKeyMap{
	ModulePipeline: key.NewBinding(
		key.WithKeys("f1"),
		key.WithHelp("F1", "pipeline"),
	),
	ModuleServices: key.NewBinding(
		key.WithKeys("f2"),
		key.WithHelp("F2", "services"),
	),
	ModuleParsers: key.NewBinding(
		key.WithKeys("f3"),
		key.WithHelp("F3", "parsers"),
	),
	ModuleAlerts: key.NewBinding(
		key.WithKeys("f4"),
		key.WithHelp("F4", "alerts"),
	),
	ModulePerformance: key.NewBinding(
		key.WithKeys("f5"),
		key.WithHelp("F5", "performance"),
	),
	ModuleOverview: key.NewBinding(
		key.WithKeys("f6"),
		key.WithHelp("F6", "overview"),
	),
	NextModule: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next module"),
	),
	PrevModule: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev module"),
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
		key.WithKeys("ctrl+r"),
		key.WithHelp("ctrl+r", "refresh all"),
	),
}

// ShortHelp returns the short help for hub navigation
func (k hubKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.NextModule, k.PrevModule, k.Help, k.Quit}
}

// FullHelp returns the full help for hub navigation
func (k hubKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.ModulePipeline, k.ModuleServices, k.ModuleParsers},
		{k.ModuleAlerts, k.ModulePerformance, k.ModuleOverview},
		{k.NextModule, k.PrevModule, k.Refresh},
		{k.Help, k.Quit},
	}
}

// NewHub creates a new dashboard hub
func NewHub(rc *eos_io.RuntimeContext, db *sql.DB) *Hub {
	return &Hub{
		rc:            rc,
		db:            db,
		registry:      NewModuleRegistry(),
		currentModule: ModuleOverview, // Start with overview
		help:          help.New(),
		keys:          hubKeys,
		lastUpdate:    time.Now(),
	}
}

// RegisterModule adds a module to the hub
func (h *Hub) RegisterModule(module DashboardModule) {
	h.registry.Register(module)
}

// GetCurrentModule returns the currently active module
func (h *Hub) GetCurrentModule() (DashboardModule, bool) {
	return h.registry.Get(h.currentModule)
}

// SwitchToModule switches to a specific module
func (h *Hub) SwitchToModule(moduleType ModuleType) tea.Cmd {
	// Exit current module
	var exitCmd tea.Cmd
	if currentModule, exists := h.registry.Get(h.currentModule); exists {
		exitCmd = currentModule.OnExit()
	}

	// Switch to new module
	h.currentModule = moduleType

	// Enter new module
	var enterCmd tea.Cmd
	if newModule, exists := h.registry.Get(h.currentModule); exists {
		newModule.OnResize(h.width, h.height)
		enterCmd = newModule.OnEnter()
	}

	return tea.Batch(exitCmd, enterCmd)
}

// Init initializes the dashboard hub
func (h *Hub) Init() tea.Cmd {
	var cmds []tea.Cmd

	// Initialize all modules
	for _, module := range h.registry.List() {
		cmds = append(cmds, module.Init())
	}

	// Enter the initial module
	if currentModule, exists := h.registry.Get(h.currentModule); exists {
		cmds = append(cmds, currentModule.OnEnter())
	}

	return tea.Batch(cmds...)
}

// Update handles hub-level events and delegates to modules
func (h *Hub) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle hub-level navigation
		switch {
		case key.Matches(msg, h.keys.Quit):
			return h, tea.Quit

		case key.Matches(msg, h.keys.Help):
			h.showHelp = !h.showHelp

		case key.Matches(msg, h.keys.ModulePipeline):
			cmd := h.SwitchToModule(ModulePipeline)
			return h, cmd

		case key.Matches(msg, h.keys.ModuleServices):
			cmd := h.SwitchToModule(ModuleServices)
			return h, cmd

		case key.Matches(msg, h.keys.ModuleParsers):
			cmd := h.SwitchToModule(ModuleParsers)
			return h, cmd

		case key.Matches(msg, h.keys.ModuleAlerts):
			cmd := h.SwitchToModule(ModuleAlerts)
			return h, cmd

		case key.Matches(msg, h.keys.ModulePerformance):
			cmd := h.SwitchToModule(ModulePerformance)
			return h, cmd

		case key.Matches(msg, h.keys.ModuleOverview):
			cmd := h.SwitchToModule(ModuleOverview)
			return h, cmd

		case key.Matches(msg, h.keys.NextModule):
			nextType := h.registry.NextModule(h.currentModule)
			cmd := h.SwitchToModule(nextType)
			return h, cmd

		case key.Matches(msg, h.keys.PrevModule):
			prevType := h.registry.PrevModule(h.currentModule)
			cmd := h.SwitchToModule(prevType)
			return h, cmd

		case key.Matches(msg, h.keys.Refresh):
			// Refresh all modules
			for _, module := range h.registry.List() {
				if module.CanRefresh() {
					cmds = append(cmds, module.Refresh())
				}
			}
			h.lastUpdate = time.Now()
			return h, tea.Batch(cmds...)
		}

	case tea.WindowSizeMsg:
		h.width = msg.Width
		h.height = msg.Height
		h.help.Width = msg.Width

		// Resize all modules
		for _, module := range h.registry.List() {
			module.OnResize(msg.Width, msg.Height)
		}
	}

	// Delegate to current module
	if currentModule, exists := h.registry.Get(h.currentModule); exists {
		updatedModule, moduleCmd := currentModule.Update(msg)

		// Replace the module in registry with updated version
		h.registry.Register(updatedModule)
		cmds = append(cmds, moduleCmd)
	}

	return h, tea.Batch(cmds...)
}

// View renders the dashboard hub
func (h *Hub) View() string {
	if h.width == 0 || h.height == 0 {
		return "Initializing dashboard..."
	}

	// Show help overlay if requested
	if h.showHelp {
		return h.renderHelpView()
	}

	// Build header with module navigation
	header := h.renderHeader()

	// Get current module content
	var content string
	if currentModule, exists := h.registry.Get(h.currentModule); exists {
		content = currentModule.View()
	} else {
		content = h.renderNoModuleView()
	}

	// Build footer with status and help
	footer := h.renderFooter()

	// Calculate available height for module content
	headerHeight := lipgloss.Height(header)
	footerHeight := lipgloss.Height(footer)
	contentHeight := h.height - headerHeight - footerHeight

	if contentHeight < 1 {
		return "Terminal too small"
	}

	// Ensure content fits in available space
	contentLines := strings.Split(content, "\n")
	if len(contentLines) > contentHeight {
		content = strings.Join(contentLines[:contentHeight], "\n")
	}

	return lipgloss.JoinVertical(
		lipgloss.Top,
		header,
		content,
		footer,
	)
}

// renderHeader creates the navigation header
func (h *Hub) renderHeader() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00ffff")).
		Background(lipgloss.Color("#1a1a2e")).
		Padding(0, 1)

	selectedTabStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#000000")).
		Background(lipgloss.Color("#00ffff")).
		Padding(0, 1)

	inactiveTabStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666666")).
		Padding(0, 1)

	title := titleStyle.Render(" Wazuh Dashboard Hub")

	// Build module tabs
	var tabs []string
	for _, moduleType := range h.registry.GetOrder() {
		if module, exists := h.registry.Get(moduleType); exists {
			style := inactiveTabStyle
			if moduleType == h.currentModule {
				style = selectedTabStyle
			}

			// Add health indicator
			indicator := "✓"
			if !module.IsHealthy() {
				indicator = "✗"
			}

			tab := fmt.Sprintf(" F%d:%s %s ", int(moduleType)+1, module.Name(), indicator)
			tabs = append(tabs, style.Render(tab))
		}
	}

	navigation := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)

	return lipgloss.JoinVertical(
		lipgloss.Top,
		title,
		navigation,
		strings.Repeat("─", h.width),
	)
}

// renderFooter creates the status and help footer
func (h *Hub) renderFooter() string {
	// Status information
	status := fmt.Sprintf("Last update: %s | Modules: %d",
		h.lastUpdate.Format("15:04:05"),
		h.registry.Count())

	// Help text
	helpText := h.help.ShortHelpView(h.keys.ShortHelp())

	// Error message if present
	errorText := ""
	if h.err != nil {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff0000")).
			Bold(true)
		errorText = errorStyle.Render("Error: " + h.err.Error())
	}

	// Build footer sections
	sections := []string{status}
	if errorText != "" {
		sections = append(sections, errorText)
	}
	sections = append(sections, helpText)

	footerContent := lipgloss.JoinHorizontal(
		lipgloss.Top,
		sections[0],
		strings.Repeat(" ", max(0, h.width-totalWidth(sections))),
		strings.Join(sections[1:], " | "),
	)

	return lipgloss.JoinVertical(
		lipgloss.Top,
		strings.Repeat("─", h.width),
		footerContent,
	)
}

// renderHelpView shows the help overlay
func (h *Hub) renderHelpView() string {
	helpContent := h.help.FullHelpView(h.keys.FullHelp())

	// Add module-specific help if current module exists
	if currentModule, exists := h.registry.Get(h.currentModule); exists {
		moduleHelp := h.help.FullHelpView(currentModule.FullHelp())
		helpContent = lipgloss.JoinVertical(
			lipgloss.Top,
			helpContent,
			"",
			fmt.Sprintf("=== %s Module ===", currentModule.Name()),
			moduleHelp,
		)
	}

	helpStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#3d5a80")).
		Padding(1).
		Margin(1)

	return lipgloss.Place(
		h.width,
		h.height,
		lipgloss.Center,
		lipgloss.Center,
		helpStyle.Render(helpContent),
	)
}

// renderNoModuleView shows when no module is available
func (h *Hub) renderNoModuleView() string {
	noModuleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#ffaa00")).
		Bold(true)

	return lipgloss.Place(
		h.width,
		h.height-10,
		lipgloss.Center,
		lipgloss.Center,
		noModuleStyle.Render("No modules available\nPress F1-F6 to navigate to available modules"),
	)
}

// Helper functions
func totalWidth(strings []string) int {
	total := 0
	for _, s := range strings {
		total += lipgloss.Width(s)
	}
	return total
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
