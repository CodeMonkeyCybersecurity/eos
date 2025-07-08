package zfs_management

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TUIState represents the current state of the TUI
type TUIState int

const (
	StateMenu TUIState = iota
	StateListPools
	StateListFilesystems
	StateExpandPool
	StateDestroyPool
	StateDestroyFilesystem
	StateConfirmDestroy
	StateInput
	StateResults
)

// TUIModel represents the bubbletea model for ZFS management
type TUIModel struct {
	state     TUIState
	list      list.Model
	textInput textinput.Model
	manager   *ZFSManager
	rc        *eos_io.RuntimeContext
	err       error

	// State for multi-step operations
	poolName       string
	device         string
	filesystemName string
	operation      string
	confirmTarget  string

	// Results
	listResult *ZFSListResult
	opResult   *ZFSOperationResult

	// UI dimensions
	width  int
	height int
}

// listItem represents an item in the menu list
type listItem struct {
	title       string
	description string
	key         string
	destructive bool
}

func (i listItem) Title() string       { return i.title }
func (i listItem) Description() string { return i.description }
func (i listItem) FilterValue() string { return i.title }

// NewTUIModel creates a new TUI model for ZFS management
func NewTUIModel(manager *ZFSManager, rc *eos_io.RuntimeContext) *TUIModel {
	// Create menu items
	items := make([]list.Item, len(ZFSMenuOptions))
	for i, option := range ZFSMenuOptions {
		items[i] = listItem{
			title:       option.Label,
			description: option.Description,
			key:         option.Key,
			destructive: option.Destructive,
		}
	}

	// Create list model
	menuList := list.New(items, list.NewDefaultDelegate(), 80, 20)
	menuList.Title = "ZFS Management"
	menuList.SetShowStatusBar(false)
	menuList.SetFilteringEnabled(false)

	// Create text input model
	ti := textinput.New()
	ti.Placeholder = "Enter value..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	return &TUIModel{
		state:     StateMenu,
		list:      menuList,
		textInput: ti,
		manager:   manager,
		rc:        rc,
	}
}

// Init initializes the TUI model
func (m *TUIModel) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model
func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 4)
		return m, nil
	case errMsg:
		m.err = msg.error
		m.state = StateResults
		return m, nil
	case poolsListedMsg:
		m.listResult = msg.ZFSListResult
		m.state = StateListPools
		return m, nil
	case filesystemsListedMsg:
		m.listResult = msg.ZFSListResult
		m.state = StateListFilesystems
		return m, nil
	case operationCompletedMsg:
		m.opResult = msg.ZFSOperationResult
		m.state = StateResults
		// Reset operation state
		m.poolName = ""
		m.device = ""
		m.filesystemName = ""
		m.operation = ""
		m.confirmTarget = ""
		return m, nil
	}

	return m.updateForState(msg)
}

// handleKeyPress handles key press events
func (m *TUIModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		if m.state == StateMenu {
			return m, tea.Quit
		}
		// Return to menu from other states
		m.state = StateMenu
		return m, nil
	case "enter":
		return m.handleEnterKey()
	case "esc":
		if m.state != StateMenu {
			m.state = StateMenu
			return m, nil
		}
		return m, tea.Quit
	}

	return m.updateForState(msg)
}

// handleEnterKey handles enter key press
func (m *TUIModel) handleEnterKey() (tea.Model, tea.Cmd) {
	switch m.state {
	case StateMenu:
		if selectedItem, ok := m.list.SelectedItem().(listItem); ok {
			return m.handleMenuSelection(selectedItem.key)
		}
	case StateInput:
		return m.handleInputSubmission()
	case StateConfirmDestroy:
		if strings.ToLower(m.textInput.Value()) == "yes" {
			return m.executeDestructiveOperation()
		} else {
			m.state = StateMenu
			return m, nil
		}
	case StateResults:
		m.state = StateMenu
		return m, nil
	}

	return m, nil
}

// handleMenuSelection handles menu item selection
func (m *TUIModel) handleMenuSelection(key string) (tea.Model, tea.Cmd) {
	logger := otelzap.Ctx(m.rc.Ctx)

	switch key {
	case "1": // List ZFS Pools
		m.state = StateListPools
		return m, m.listPoolsCmd()
	case "2": // List ZFS Filesystems
		m.state = StateListFilesystems
		return m, m.listFilesystemsCmd()
	case "3": // Expand Pool
		m.operation = "expand_pool"
		m.state = StateInput
		m.textInput.SetValue("")
		m.textInput.Placeholder = "Enter pool name to expand..."
		return m, nil
	case "4": // Destroy Pool
		m.operation = "destroy_pool"
		m.state = StateInput
		m.textInput.SetValue("")
		m.textInput.Placeholder = "Enter pool name to destroy..."
		return m, nil
	case "5": // Destroy Filesystem
		m.operation = "destroy_filesystem"
		m.state = StateInput
		m.textInput.SetValue("")
		m.textInput.Placeholder = "Enter filesystem name to destroy..."
		return m, nil
	case "q": // Quit
		return m, tea.Quit
	default:
		logger.Warn("Unknown menu selection", zap.String("key", key))
	}

	return m, nil
}

// handleInputSubmission handles input field submission
func (m *TUIModel) handleInputSubmission() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.textInput.Value())
	if value == "" {
		return m, nil
	}

	switch m.operation {
	case "expand_pool":
		if m.poolName == "" {
			m.poolName = value
			m.textInput.SetValue("")
			m.textInput.Placeholder = "Enter device path to add (e.g., /dev/sdY)..."
			return m, nil
		} else {
			m.device = value
			return m, m.expandPoolCmd()
		}
	case "destroy_pool":
		m.poolName = value
		m.confirmTarget = fmt.Sprintf("pool '%s'", value)
		return m.setupConfirmDestroy()
	case "destroy_filesystem":
		m.filesystemName = value
		m.confirmTarget = fmt.Sprintf("filesystem '%s'", value)
		return m.setupConfirmDestroy()
	}

	return m, nil
}

// setupConfirmDestroy sets up the confirmation dialog for destructive operations
func (m *TUIModel) setupConfirmDestroy() (tea.Model, tea.Cmd) {
	m.state = StateConfirmDestroy
	m.textInput.SetValue("")
	m.textInput.Placeholder = "Type 'yes' to confirm..."
	return m, nil
}

// executeDestructiveOperation executes a confirmed destructive operation
func (m *TUIModel) executeDestructiveOperation() (tea.Model, tea.Cmd) {
	switch m.operation {
	case "destroy_pool":
		return m, m.destroyPoolCmd()
	case "destroy_filesystem":
		return m, m.destroyFilesystemCmd()
	}

	m.state = StateMenu
	return m, nil
}

// updateForState updates the model based on current state
func (m *TUIModel) updateForState(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch m.state {
	case StateMenu:
		m.list, cmd = m.list.Update(msg)
	case StateInput, StateConfirmDestroy:
		m.textInput, cmd = m.textInput.Update(msg)
	case StateListPools, StateListFilesystems, StateResults:
		// For these states, any key press returns to menu
		if _, ok := msg.(tea.KeyMsg); ok {
			m.state = StateMenu
			m.err = nil
			m.listResult = nil
			m.opResult = nil
		}
	}

	return m, cmd
}

// Tea commands for async operations

func (m *TUIModel) listPoolsCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.manager.ListPools(m.rc)
		if err != nil {
			return errMsg{err}
		}
		return poolsListedMsg{result}
	}
}

func (m *TUIModel) listFilesystemsCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.manager.ListFilesystems(m.rc)
		if err != nil {
			return errMsg{err}
		}
		return filesystemsListedMsg{result}
	}
}

func (m *TUIModel) expandPoolCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.manager.ExpandPool(m.rc, m.poolName, m.device)
		if err != nil {
			return errMsg{err}
		}
		return operationCompletedMsg{result}
	}
}

func (m *TUIModel) destroyPoolCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.manager.DestroyPool(m.rc, m.poolName)
		if err != nil {
			return errMsg{err}
		}
		return operationCompletedMsg{result}
	}
}

func (m *TUIModel) destroyFilesystemCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.manager.DestroyFilesystem(m.rc, m.filesystemName)
		if err != nil {
			return errMsg{err}
		}
		return operationCompletedMsg{result}
	}
}

// Messages for tea updates

type errMsg struct{ error }
type poolsListedMsg struct{ *ZFSListResult }
type filesystemsListedMsg struct{ *ZFSListResult }
type operationCompletedMsg struct{ *ZFSOperationResult }

// View renders the TUI
func (m *TUIModel) View() string {
	var s strings.Builder

	switch m.state {
	case StateMenu:
		s.WriteString(m.list.View())
	case StateListPools:
		s.WriteString(m.renderPoolsList())
	case StateListFilesystems:
		s.WriteString(m.renderFilesystemsList())
	case StateInput:
		s.WriteString(m.renderInputView())
	case StateConfirmDestroy:
		s.WriteString(m.renderConfirmView())
	case StateResults:
		s.WriteString(m.renderResultsView())
	}

	if m.err != nil {
		s.WriteString(fmt.Sprintf("\n\nError: %v", m.err))
	}

	s.WriteString("\n\nPress 'q' to quit, 'esc' to go back")
	return s.String()
}

// Render functions for different views

func (m *TUIModel) renderPoolsList() string {
	if m.listResult == nil || len(m.listResult.Pools) == 0 {
		return "No ZFS pools found.\n\nPress any key to return to menu."
	}

	var s strings.Builder
	s.WriteString("ZFS Pools:\n")
	s.WriteString(strings.Repeat("=", 80) + "\n")
	s.WriteString(fmt.Sprintf("%-15s %-8s %-8s %-8s %-5s %-5s %-8s %-10s\n",
		"NAME", "SIZE", "ALLOC", "FREE", "FRAG", "CAP", "DEDUP", "HEALTH"))
	s.WriteString(strings.Repeat("-", 80) + "\n")

	for _, pool := range m.listResult.Pools {
		s.WriteString(fmt.Sprintf("%-15s %-8s %-8s %-8s %-5s %-5s %-8s %-10s\n",
			pool.Name, pool.Size, pool.Alloc, pool.Free, pool.Frag,
			pool.Cap, pool.Dedup, pool.Health))
	}

	s.WriteString("\nPress any key to return to menu.")
	return s.String()
}

func (m *TUIModel) renderFilesystemsList() string {
	if m.listResult == nil || len(m.listResult.Filesystems) == 0 {
		return "No ZFS filesystems found.\n\nPress any key to return to menu."
	}

	var s strings.Builder
	s.WriteString("ZFS Filesystems:\n")
	s.WriteString(strings.Repeat("=", 80) + "\n")
	s.WriteString(fmt.Sprintf("%-25s %-10s %-10s %-10s %-15s\n",
		"NAME", "USED", "AVAIL", "REFER", "MOUNTPOINT"))
	s.WriteString(strings.Repeat("-", 80) + "\n")

	for _, fs := range m.listResult.Filesystems {
		mountpoint := fs.Mountpoint
		if mountpoint == "" {
			mountpoint = "-"
		}
		s.WriteString(fmt.Sprintf("%-25s %-10s %-10s %-10s %-15s\n",
			fs.Name, fs.Used, fs.Available, fs.Refer, mountpoint))
	}

	s.WriteString("\nPress any key to return to menu.")
	return s.String()
}

func (m *TUIModel) renderInputView() string {
	var s strings.Builder

	switch m.operation {
	case "expand_pool":
		if m.poolName == "" {
			s.WriteString("Expand ZFS Pool - Step 1 of 2\n")
			s.WriteString("Enter the name of the pool to expand:\n\n")
		} else {
			s.WriteString(fmt.Sprintf("Expand ZFS Pool '%s' - Step 2 of 2\n", m.poolName))
			s.WriteString("Enter the device path to add to the pool:\n\n")
		}
	case "destroy_pool":
		s.WriteString("Destroy ZFS Pool\n")
		s.WriteString("WARNING: This will permanently destroy the pool and ALL data!\n")
		s.WriteString("Enter the name of the pool to destroy:\n\n")
	case "destroy_filesystem":
		s.WriteString("Destroy ZFS Filesystem\n")
		s.WriteString("WARNING: This will permanently destroy the filesystem and ALL data!\n")
		s.WriteString("Enter the name of the filesystem to destroy:\n\n")
	}

	s.WriteString(m.textInput.View())
	s.WriteString("\n\nPress Enter to continue, Esc to cancel")
	return s.String()
}

func (m *TUIModel) renderConfirmView() string {
	var s strings.Builder
	s.WriteString(" DESTRUCTIVE OPERATION CONFIRMATION\n")
	s.WriteString(strings.Repeat("=", 50) + "\n")
	s.WriteString(fmt.Sprintf("You are about to PERMANENTLY DESTROY %s\n", m.confirmTarget))
	s.WriteString("This action CANNOT be undone and will result in DATA LOSS!\n\n")
	s.WriteString("Type 'yes' to confirm this destructive operation:\n\n")
	s.WriteString(m.textInput.View())
	s.WriteString("\n\nPress Enter to continue, Esc to cancel")
	return s.String()
}

func (m *TUIModel) renderResultsView() string {
	if m.opResult == nil {
		return "No operation results to display.\n\nPress any key to return to menu."
	}

	var s strings.Builder
	s.WriteString(fmt.Sprintf("Operation: %s\n", m.opResult.Operation))
	s.WriteString(fmt.Sprintf("Target: %s\n", m.opResult.Target))
	s.WriteString(fmt.Sprintf("Timestamp: %s\n", m.opResult.Timestamp.Format("2006-01-02 15:04:05")))
	s.WriteString(strings.Repeat("=", 50) + "\n")

	if m.opResult.Success {
		s.WriteString(" Operation completed successfully!\n")
	} else {
		s.WriteString("❌ Operation failed!\n")
	}

	if m.opResult.Output != "" {
		s.WriteString(fmt.Sprintf("\nOutput:\n%s\n", m.opResult.Output))
	}

	if m.opResult.Error != "" {
		s.WriteString(fmt.Sprintf("\nError:\n%s\n", m.opResult.Error))
	}

	if m.opResult.DryRun {
		s.WriteString("\n This was a dry run - no actual changes were made.")
	}

	s.WriteString("\n\nPress any key to return to menu.")
	return s.String()
}

// RunZFSTUI runs the ZFS management TUI
func RunZFSTUI(manager *ZFSManager, rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting ZFS management TUI")

	model := NewTUIModel(manager, rc)
	program := tea.NewProgram(model, tea.WithAltScreen())

	if _, err := program.Run(); err != nil {
		logger.Error("TUI program failed", zap.Error(err))
		return fmt.Errorf("TUI program failed: %w", err)
	}

	return nil
}
