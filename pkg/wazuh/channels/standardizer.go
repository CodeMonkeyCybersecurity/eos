package wazuh_channels

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ChannelStandardizer handles notification channel standardization
type ChannelStandardizer struct {
	config  *ChannelStandardizerConfig
	changes []ChannelChange
	errors  []string
}

// NewChannelStandardizer creates a new channel standardizer
func NewChannelStandardizer(config *ChannelStandardizerConfig) *ChannelStandardizer {
	if config == nil {
		config = DefaultChannelStandardizerConfig()
	}

	return &ChannelStandardizer{
		config:  config,
		changes: make([]ChannelChange, 0),
		errors:  make([]string, 0),
	}
}

// StandardizeAll standardizes channels in all worker files
func (cs *ChannelStandardizer) StandardizeAll() *StandardizationResult {
	result := &StandardizationResult{
		Timestamp:      time.Now(),
		WorkersDir:     cs.config.WorkersDir,
		Changes:        make([]ChannelChange, 0),
		Errors:         make([]string, 0),
		FilesUpdated:   make([]string, 0),
		FilesSkipped:   make([]string, 0),
		BackupsCreated: make([]string, 0),
	}

	// Check if workers directory exists
	if _, err := os.Stat(cs.config.WorkersDir); os.IsNotExist(err) {
		result.Errors = append(result.Errors, fmt.Sprintf("Workers directory does not exist: %s", cs.config.WorkersDir))
		return result
	}

	// Process each worker file
	for workerFile, expectedConfig := range StandardWorkerConfigs {
		workerPath := filepath.Join(cs.config.WorkersDir, workerFile)

		if _, err := os.Stat(workerPath); os.IsNotExist(err) {
			result.FilesSkipped = append(result.FilesSkipped, workerFile+" (not found)")
			continue
		}

		if cs.shouldExcludeFile(workerFile) {
			result.FilesSkipped = append(result.FilesSkipped, workerFile+" (excluded)")
			continue
		}

		// Standardize the worker file
		updated, backupPath, err := cs.standardizeWorkerFile(workerPath, expectedConfig)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Error processing %s: %v", workerFile, err))
			continue
		}

		if updated {
			result.FilesUpdated = append(result.FilesUpdated, workerFile)
			if backupPath != "" {
				result.BackupsCreated = append(result.BackupsCreated, filepath.Base(backupPath))
			}
		} else {
			result.FilesSkipped = append(result.FilesSkipped, workerFile+" (already correct)")
		}
	}

	result.Changes = cs.changes
	result.Errors = append(result.Errors, cs.errors...)
	result.Success = len(result.Errors) == 0

	return result
}

// AnalyzeWorkers analyzes current worker configurations without making changes
func (cs *ChannelStandardizer) AnalyzeWorkers() ([]WorkerChannelInfo, error) {
	infos := make([]WorkerChannelInfo, 0)

	for workerFile, expectedConfig := range StandardWorkerConfigs {
		workerPath := filepath.Join(cs.config.WorkersDir, workerFile)

		info := WorkerChannelInfo{
			Filename:       workerFile,
			ListenChannels: make([]string, 0),
			NotifyChannels: make([]string, 0),
			Issues:         make([]string, 0),
		}

		if _, err := os.Stat(workerPath); os.IsNotExist(err) {
			info.Issues = append(info.Issues, "File not found")
			infos = append(infos, info)
			continue
		}

		// Analyze the file
		if err := cs.analyzeWorkerFile(workerPath, &info); err != nil {
			info.Issues = append(info.Issues, fmt.Sprintf("Analysis error: %v", err))
		}

		// Check if configuration is correct
		info.IsCorrect = cs.isConfigurationCorrect(info, expectedConfig)
		if !info.IsCorrect {
			cs.addConfigurationIssues(&info, expectedConfig)
		}

		infos = append(infos, info)
	}

	return infos, nil
}

// standardizeWorkerFile standardizes channels in a specific worker file
func (cs *ChannelStandardizer) standardizeWorkerFile(workerPath string, expectedConfig WorkerConfig) (bool, string, error) {
	content, err := os.ReadFile(workerPath)
	if err != nil {
		return false, "", err
	}

	originalContent := string(content)
	updatedContent := originalContent
	hasChanges := false

	// SECURITY P0 #1: Safe array access with explicit bounds check
	// Update LISTEN_CHANNEL definitions
	if len(expectedConfig.ListenChannels) > 0 {
		// Safe to access [0] - length verified above
		primaryListenChannel := expectedConfig.ListenChannels[0]
		newContent, changed := cs.updateListenChannelVariable(updatedContent, primaryListenChannel, workerPath)
		if changed {
			updatedContent = newContent
			hasChanges = true
		}
	}

	// Update NOTIFY_CHANNEL definitions
	if len(expectedConfig.NotifyChannels) > 0 {
		// Safe to access [0] - length verified above
		primaryNotifyChannel := expectedConfig.NotifyChannels[0]
		newContent, changed := cs.updateNotifyChannelVariable(updatedContent, primaryNotifyChannel, workerPath)
		if changed {
			updatedContent = newContent
			hasChanges = true
		}
	}

	// Update pg_notify calls
	for _, notifyChannel := range expectedConfig.NotifyChannels {
		newContent, changed := cs.updatePgNotifyCalls(updatedContent, notifyChannel, workerPath)
		if changed {
			updatedContent = newContent
			hasChanges = true
		}
	}

	// Update LISTEN statements
	for _, listenChannel := range expectedConfig.ListenChannels {
		newContent, changed := cs.updateListenStatements(updatedContent, listenChannel, workerPath)
		if changed {
			updatedContent = newContent
			hasChanges = true
		}
	}

	// Write changes if any were made and not in dry-run mode
	if hasChanges && !cs.config.DryRun {
		var backupPath string

		// Create backup if enabled
		if cs.config.CreateBackups {
			backupPath = workerPath + ".bak"
			if err := os.WriteFile(backupPath, []byte(originalContent), shared.ConfigFilePerm); err != nil {
				return false, "", fmt.Errorf("failed to create backup: %v", err)
			}
		}

		// Write updated content
		if err := os.WriteFile(workerPath, []byte(updatedContent), shared.ConfigFilePerm); err != nil {
			return false, backupPath, fmt.Errorf("failed to write updated file: %v", err)
		}

		return true, backupPath, nil
	}

	return hasChanges, "", nil
}

// updateListenChannelVariable updates LISTEN_CHANNEL variable definitions
func (cs *ChannelStandardizer) updateListenChannelVariable(content, channel, filepath string) (string, bool) {
	patterns := []string{
		`LISTEN_CHANNEL\s*=\s*["'][^"']*["']`,
		`LISTEN_CHANNEL\s*=\s*["'][^"']*["']`,
	}

	replacement := fmt.Sprintf(`LISTEN_CHANNEL = "%s"`, channel)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(content) {
			oldMatches := re.FindAllString(content, -1)
			newContent := re.ReplaceAllString(content, replacement)

			if newContent != content {
				// Record the change
				for _, oldMatch := range oldMatches {
					cs.changes = append(cs.changes, ChannelChange{
						File:      filepath,
						Type:      "listen_channel",
						OldValue:  oldMatch,
						NewValue:  replacement,
						Timestamp: time.Now(),
					})
				}
				return newContent, true
			}
		}
	}

	return content, false
}

// updateNotifyChannelVariable updates NOTIFY_CHANNEL variable definitions
func (cs *ChannelStandardizer) updateNotifyChannelVariable(content, channel, filepath string) (string, bool) {
	patterns := []string{
		`NOTIFY_CHANNEL\s*=\s*["'][^"']*["']`,
	}

	replacement := fmt.Sprintf(`NOTIFY_CHANNEL = "%s"`, channel)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(content) {
			oldMatches := re.FindAllString(content, -1)
			newContent := re.ReplaceAllString(content, replacement)

			if newContent != content {
				// Record the change
				for _, oldMatch := range oldMatches {
					cs.changes = append(cs.changes, ChannelChange{
						File:      filepath,
						Type:      "notify_channel",
						OldValue:  oldMatch,
						NewValue:  replacement,
						Timestamp: time.Now(),
					})
				}
				return newContent, true
			}
		}
	}

	return content, false
}

// updatePgNotifyCalls updates pg_notify function calls
func (cs *ChannelStandardizer) updatePgNotifyCalls(content, channel, filepath string) (string, bool) {
	// Pattern to match pg_notify calls with different channel names
	pattern := `pg_notify\s*\(\s*['"](?!` + regexp.QuoteMeta(channel) + `)[^'"]*['"]`
	re := regexp.MustCompile(pattern)

	if re.MatchString(content) {
		oldMatches := re.FindAllString(content, -1)
		replacement := fmt.Sprintf(`pg_notify('%s'`, channel)
		newContent := re.ReplaceAllString(content, replacement)

		if newContent != content {
			// Record the change
			for _, oldMatch := range oldMatches {
				cs.changes = append(cs.changes, ChannelChange{
					File:      filepath,
					Type:      "pg_notify",
					OldValue:  oldMatch,
					NewValue:  replacement,
					Timestamp: time.Now(),
				})
			}
			return newContent, true
		}
	}

	return content, false
}

// updateListenStatements updates LISTEN statements in SQL code
func (cs *ChannelStandardizer) updateListenStatements(content, channel, filepath string) (string, bool) {
	patterns := []string{
		`LISTEN\s+(?!` + regexp.QuoteMeta(channel) + `)\w+`,
		`cur\.execute\s*\(\s*["']LISTEN\s+(?!` + regexp.QuoteMeta(channel) + `)\w+["']\s*\)`,
	}

	hasChanges := false
	updatedContent := content

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(updatedContent) {
			oldMatches := re.FindAllString(updatedContent, -1)

			if strings.Contains(pattern, "cur.execute") {
				replacement := fmt.Sprintf(`cur.execute("LISTEN %s")`, channel)
				updatedContent = re.ReplaceAllString(updatedContent, replacement)
			} else {
				replacement := fmt.Sprintf(`LISTEN %s`, channel)
				updatedContent = re.ReplaceAllString(updatedContent, replacement)
			}

			if len(oldMatches) > 0 {
				hasChanges = true
				// Record the change
				for _, oldMatch := range oldMatches {
					cs.changes = append(cs.changes, ChannelChange{
						File:      filepath,
						Type:      "listen_statement",
						OldValue:  oldMatch,
						NewValue:  fmt.Sprintf("LISTEN %s", channel),
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return updatedContent, hasChanges
}

// analyzeWorkerFile analyzes a worker file to extract channel information
func (cs *ChannelStandardizer) analyzeWorkerFile(workerPath string, info *WorkerChannelInfo) error {
	file, err := os.Open(workerPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Use logger if available, otherwise print
			fmt.Printf("Warning: Failed to close file: %v\n", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Extract LISTEN_CHANNEL
		if match := regexp.MustCompile(`LISTEN_CHANNEL\s*=\s*["']([^"']+)["']`).FindStringSubmatch(line); len(match) > 1 {
			info.ListenChannels = append(info.ListenChannels, match[1])
		}

		// Extract NOTIFY_CHANNEL
		if match := regexp.MustCompile(`NOTIFY_CHANNEL\s*=\s*["']([^"']+)["']`).FindStringSubmatch(line); len(match) > 1 {
			info.NotifyChannels = append(info.NotifyChannels, match[1])
		}

		// Extract pg_notify calls
		if match := regexp.MustCompile(`pg_notify\s*\(\s*["']([^"']+)["']`).FindStringSubmatch(line); len(match) > 1 {
			channel := match[1]
			if !contains(info.NotifyChannels, channel) {
				info.NotifyChannels = append(info.NotifyChannels, channel)
			}
		}

		// Extract LISTEN statements
		if match := regexp.MustCompile(`LISTEN\s+(\w+)`).FindStringSubmatch(line); len(match) > 1 {
			channel := match[1]
			if !contains(info.ListenChannels, channel) {
				info.ListenChannels = append(info.ListenChannels, channel)
			}
		}
	}

	return scanner.Err()
}

// isConfigurationCorrect checks if the worker's configuration matches expectations
func (cs *ChannelStandardizer) isConfigurationCorrect(info WorkerChannelInfo, expected WorkerConfig) bool {
	// Check listen channels
	for _, expectedChannel := range expected.ListenChannels {
		if !contains(info.ListenChannels, expectedChannel) {
			return false
		}
	}

	// Check notify channels
	for _, expectedChannel := range expected.NotifyChannels {
		if !contains(info.NotifyChannels, expectedChannel) {
			return false
		}
	}

	// Check for unexpected channels
	if len(info.ListenChannels) != len(expected.ListenChannels) ||
		len(info.NotifyChannels) != len(expected.NotifyChannels) {
		return false
	}

	return true
}

// addConfigurationIssues adds specific issues to the worker info
func (cs *ChannelStandardizer) addConfigurationIssues(info *WorkerChannelInfo, expected WorkerConfig) {
	// Check for missing listen channels
	for _, expectedChannel := range expected.ListenChannels {
		if !contains(info.ListenChannels, expectedChannel) {
			info.Issues = append(info.Issues, fmt.Sprintf("Missing listen channel: %s", expectedChannel))
		}
	}

	// Check for missing notify channels
	for _, expectedChannel := range expected.NotifyChannels {
		if !contains(info.NotifyChannels, expectedChannel) {
			info.Issues = append(info.Issues, fmt.Sprintf("Missing notify channel: %s", expectedChannel))
		}
	}

	// Check for unexpected listen channels
	for _, actualChannel := range info.ListenChannels {
		if !contains(expected.ListenChannels, actualChannel) {
			info.Issues = append(info.Issues, fmt.Sprintf("Unexpected listen channel: %s", actualChannel))
		}
	}

	// Check for unexpected notify channels
	for _, actualChannel := range info.NotifyChannels {
		if !contains(expected.NotifyChannels, actualChannel) {
			info.Issues = append(info.Issues, fmt.Sprintf("Unexpected notify channel: %s", actualChannel))
		}
	}
}

// shouldExcludeFile checks if a file should be excluded based on patterns
func (cs *ChannelStandardizer) shouldExcludeFile(filename string) bool {
	for _, pattern := range cs.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
	}
	return false
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
