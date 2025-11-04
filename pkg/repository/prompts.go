package repository

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// PromptRepoOptions interactively gathers repository metadata from the operator.
func PromptRepoOptions(path string, opts *RepoOptions, prefs *RepoPreferences) (*RepoOptions, error) {
	if opts == nil {
		opts = &RepoOptions{}
	}

	reader := bufio.NewReader(os.Stdin)
	dirName := filepath.Base(path)

	nameDefault := firstNonEmpty(opts.Name, dirName)
	fmt.Printf("Repository name [%s]: ", nameDefault)
	text, err := readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read repository name: %w", err)
	}
	if text != "" {
		// Validate repository name before accepting it
		if err := ValidateRepoName(text); err != nil {
			return nil, fmt.Errorf("invalid repository name: %w", err)
		}
		opts.Name = text
	} else {
		// Also validate default name (directory name might be invalid)
		if err := ValidateRepoName(nameDefault); err != nil {
			return nil, fmt.Errorf("default repository name '%s' is invalid: %w\nPlease specify a valid name explicitly", nameDefault, err)
		}
		opts.Name = nameDefault
	}

	fmt.Print("Description (optional): ")
	text, err = readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read description: %w", err)
	}
	if text != "" {
		opts.Description = text
	}

	privateDefault := opts.Private
	if prefs != nil && prefs.RememberPrivate {
		privateDefault = prefs.DefaultPrivate
	}
	privatePrompt := "Make repository private? [y/N]: "
	if privateDefault {
		privatePrompt = "Make repository private? [Y/n]: "
	}
	fmt.Print(privatePrompt)
	text, err = readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read private setting: %w", err)
	}
	if text != "" {
		privateDefault = parseYesNo(text, privateDefault)
	}
	opts.Private = privateDefault

	orgDefault := opts.Organization
	if orgDefault == "" && prefs != nil {
		orgDefault = prefs.Organization
	}
	if orgDefault != "" {
		fmt.Printf("Create under organization [%s]: ", orgDefault)
	} else {
		fmt.Print("Create under organization? (leave empty for personal): ")
	}
	text, err = readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read organization: %w", err)
	}
	if text != "" {
		opts.Organization = text
	} else if orgDefault != "" {
		opts.Organization = orgDefault
	}

	branchDefault := firstNonEmpty(opts.Branch, "main")
	text, err = promptWithExplicitDefault(reader, "Default branch name", branchDefault)
	if err != nil {
		return nil, fmt.Errorf("failed to read branch name: %w", err)
	}
	if text != "" {
		opts.Branch = text
	} else {
		opts.Branch = branchDefault
	}

	remoteDefault := firstNonEmpty(opts.Remote, "origin")
	text, err = promptWithExplicitDefault(reader, "Remote name", remoteDefault)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote name: %w", err)
	}
	if text != "" {
		opts.Remote = text
	} else {
		opts.Remote = remoteDefault
	}

	return opts, nil
}

// sanitizeInput removes ANSI escape sequences and control characters.
// Defense against CVE-2024-56803 (Ghostty), CVE-2024-58251 (BusyBox) class vulnerabilities.
// SECURITY: Terminal escape sequences can be weaponized to:
// - Modify terminal window title and inject commands (CVE-2024-56803)
// - Cause denial of service / terminal lockup (CVE-2024-58251)
// - Create clickable links that execute arbitrary commands
// RATIONALE: Applications must validate untrusted input per NIST SP 800-53 (SI-10).
func sanitizeInput(text string) string {
	var result strings.Builder
	inEscape := false

	for _, r := range text {
		// Detect ANSI escape sequence start (ESC character 0x1b)
		if r == '\x1b' {
			inEscape = true
			continue
		}

		// Skip characters until escape sequence ends
		if inEscape {
			// ANSI escape sequences end with a letter (A-Z, a-z)
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false // Escape sequence terminator
			}
			continue
		}

		// Only allow printable characters + basic whitespace
		// Blocks control characters (ASCII < 32 except tab/space)
		if unicode.IsPrint(r) || r == ' ' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}

// readLine reads a line from the reader, sanitizes it, and returns it.
// CRITICAL: Returns error instead of silently discarding it (no more _ discards).
// This enables forensics and proper error handling.
func readLine(reader *bufio.Reader) (string, error) {
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return sanitizeInput(text), nil
}

func parseYesNo(value string, defaultVal bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultVal
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func promptWithExplicitDefault(reader *bufio.Reader, label, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	return readLine(reader)
}
