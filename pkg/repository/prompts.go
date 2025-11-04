package repository

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	if text := readLine(reader); text != "" {
		opts.Name = text
	} else {
		opts.Name = nameDefault
	}

	fmt.Print("Description (optional): ")
	if text := readLine(reader); text != "" {
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
	if text := readLine(reader); text != "" {
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
	if text := readLine(reader); text != "" {
		opts.Organization = text
	} else if orgDefault != "" {
		opts.Organization = orgDefault
	}

	branchDefault := firstNonEmpty(opts.Branch, "main")
	if text := promptWithExplicitDefault(reader, "Default branch name", branchDefault); text != "" {
		opts.Branch = text
	} else {
		opts.Branch = branchDefault
	}

	remoteDefault := firstNonEmpty(opts.Remote, "origin")
	if text := promptWithExplicitDefault(reader, "Remote name", remoteDefault); text != "" {
		opts.Remote = text
	} else {
		opts.Remote = remoteDefault
	}

	return opts, nil
}

func readLine(reader *bufio.Reader) string {
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
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

func promptWithExplicitDefault(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	return readLine(reader)
}
