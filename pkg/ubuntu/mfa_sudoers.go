package ubuntu

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// parseSudoersComplete parses the main sudoers file and all includes
func (m *MFAManager) parseSudoersComplete() ([]SudoersEntry, error) {
	entries := []SudoersEntry{}

	// Parse main sudoers file
	mainEntries, err := m.parseSudoersFile("/etc/sudoers")
	if err != nil {
		return nil, fmt.Errorf("parse main sudoers: %w", err)
	}
	entries = append(entries, mainEntries...)

	// Parse includes from sudoers.d
	includePatterns := []string{
		"/etc/sudoers.d/*",
		"/usr/local/etc/sudoers.d/*",
	}

	for _, pattern := range includePatterns {
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			// Skip backup files and hidden files
			if strings.HasSuffix(file, "~") ||
				strings.HasPrefix(filepath.Base(file), ".") ||
				strings.HasSuffix(file, ".backup") ||
				strings.HasSuffix(file, ".orig") {
				continue
			}

			fileEntries, err := m.parseSudoersFile(file)
			if err != nil {
				m.logger.Warn("Failed to parse sudoers file",
					zap.String("file", file),
					zap.Error(err))
				continue
			}
			entries = append(entries, fileEntries...)
		}
	}

	m.logger.Info(" Parsed sudoers files",
		zap.Int("total_entries", len(entries)))

	return entries, nil
}

// parseSudoersFile parses a single sudoers file
func (m *MFAManager) parseSudoersFile(path string) ([]SudoersEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []SudoersEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle @include and @includedir directives
		if strings.HasPrefix(line, "@include") {
			if strings.HasPrefix(line, "@includedir") {
				// Parse directory includes
				parts := strings.Fields(line)
				if len(parts) == 2 {
					includeDir := parts[1]
					files, _ := filepath.Glob(filepath.Join(includeDir, "*"))
					for _, f := range files {
						if !strings.HasSuffix(f, "~") && !strings.HasPrefix(filepath.Base(f), ".") {
							subEntries, _ := m.parseSudoersFile(f)
							entries = append(entries, subEntries...)
						}
					}
				}
			}
			continue
		}

		// Parse regular sudoers entries
		entry, err := m.parseSudoersLine(line)
		if err != nil {
			m.logger.Warn("Failed to parse sudoers line",
				zap.String("file", path),
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	return entries, scanner.Err()
}

// parseSudoersLine parses a single sudoers user specification line
func (m *MFAManager) parseSudoersLine(line string) (*SudoersEntry, error) {
	// Remove continuation characters and normalize whitespace
	line = strings.ReplaceAll(line, "\\", " ")
	line = regexp.MustCompile(`\s+`).ReplaceAllString(line, " ")
	line = strings.TrimSpace(line)

	if line == "" {
		return nil, nil
	}

	// Skip directives that aren't user specifications
	if strings.HasPrefix(line, "Defaults") || strings.HasPrefix(line, "@") {
		return nil, nil
	}

	// Basic sudoers format: user hosts = (runas) commands
	// More complex: user hosts = (runas) NOPASSWD: commands

	// Split on '=' to separate user/hosts from runas/commands
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		// Not a user specification line
		return nil, nil
	}

	leftSide := strings.TrimSpace(parts[0])
	rightSide := strings.TrimSpace(parts[1])

	// Parse left side (user hosts)
	leftParts := strings.Fields(leftSide)
	if len(leftParts) < 2 {
		return nil, fmt.Errorf("incomplete user/hosts specification")
	}

	entry := &SudoersEntry{
		User:  leftParts[0],
		Hosts: leftParts[1:],
	}

	// Parse right side (runas) commands with optional tags
	if err := m.parseRunasAndCommands(rightSide, entry); err != nil {
		return nil, fmt.Errorf("parse runas/commands: %w", err)
	}

	return entry, nil
}

// parseRunasAndCommands parses the runas and commands portion with tags
func (m *MFAManager) parseRunasAndCommands(rightSide string, entry *SudoersEntry) error {
	// Look for runas specification in parentheses
	runasRegex := regexp.MustCompile(`^\(([^)]+)\)\s*(.*)$`)
	var remainder string

	if matches := runasRegex.FindStringSubmatch(rightSide); matches != nil {
		// Has runas specification
		runasSpec := strings.TrimSpace(matches[1])
		if runasSpec != "" {
			entry.RunAs = strings.Fields(runasSpec)
		}
		remainder = strings.TrimSpace(matches[2])
	} else {
		// No runas specification, defaults to root
		entry.RunAs = []string{"root"}
		remainder = rightSide
	}

	// Parse commands with optional tags
	return m.parseCommandsWithTags(remainder, entry)
}

// parseCommandsWithTags parses commands that may have tags like NOPASSWD:
func (m *MFAManager) parseCommandsWithTags(commandStr string, entry *SudoersEntry) error {
	// Handle multiple command specifications separated by commas
	commandSpecs := strings.Split(commandStr, ",")

	for _, spec := range commandSpecs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		// Look for tags followed by colon
		tagRegex := regexp.MustCompile(`^([A-Z_]+):\s*(.*)$`)

		if matches := tagRegex.FindStringSubmatch(spec); matches != nil {
			// Has tag
			tag := strings.TrimSpace(matches[1])
			commands := strings.TrimSpace(matches[2])

			entry.Tags = append(entry.Tags, tag)

			if commands != "" {
				entry.Commands = append(entry.Commands, commands)
			}
		} else {
			// No tag, just commands
			entry.Commands = append(entry.Commands, spec)
		}
	}

	return nil
}

// validateSudoersFile validates sudoers syntax using visudo
func (m *MFAManager) validateSudoersFile(filename string) error {
	// Use visudo to check syntax
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "visudo",
		Args:    []string{"-c", "-f", filename},
	})

	if err != nil {
		return fmt.Errorf("visudo validation failed: %s", output)
	}

	return nil
}

// getSudoersFingerprint creates a fingerprint of current sudoers configuration
func (m *MFAManager) getSudoersFingerprint() (string, error) {
	entries, err := m.parseSudoersComplete()
	if err != nil {
		return "", err
	}

	var fingerprint strings.Builder
	for _, entry := range entries {
		fingerprint.WriteString(fmt.Sprintf("%s|%v|%v|%v|%v\n",
			entry.User,
			entry.Hosts,
			entry.RunAs,
			entry.Commands,
			entry.Tags))
	}

	return fingerprint.String(), nil
}

// verifySudoersIntegrity ensures sudoers configuration wasn't corrupted
func (m *MFAManager) verifySudoersIntegrity(originalFingerprint string) error {
	currentFingerprint, err := m.getSudoersFingerprint()
	if err != nil {
		return fmt.Errorf("get current fingerprint: %w", err)
	}

	if originalFingerprint != currentFingerprint {
		m.logger.Warn("Sudoers configuration changed during MFA setup",
			zap.String("original_hash", fmt.Sprintf("%x", md5.Sum([]byte(originalFingerprint)))),
			zap.String("current_hash", fmt.Sprintf("%x", md5.Sum([]byte(currentFingerprint)))))
		// This is a warning, not an error - configuration may have legitimately changed
	}

	// Validate all sudoers files are syntactically correct
	files := []string{"/etc/sudoers"}
	sudoersDFiles, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, sudoersDFiles...)

	for _, file := range files {
		if err := m.validateSudoersFile(file); err != nil {
			return fmt.Errorf("sudoers validation failed for %s: %w", file, err)
		}
	}

	return nil
}
