// pkg/utils/input.go
package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"

	"golang.org/x/term"
)

// PromptInput displays a prompt and reads user input.
func PromptInput(prompt, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// promptPassword displays a prompt and reads a password without echoing.
func PromptPassword(prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, "********")
	} else {
		fmt.Printf("%s: ", prompt)
	}
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("")
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultVal
	}
	return pass
}


func ConfirmDelphiConfig(cfg delphi.DelphiConfig) delphi.DelphiConfig {
	fmt.Println("Current configuration:")
	fmt.Printf("  Protocol:      %s\n", cfg.Protocol)
	fmt.Printf("  FQDN:          %s\n", cfg.FQDN)
	fmt.Printf("  Port:          %s\n", cfg.Port)
	fmt.Printf("  APIUser:      %s\n", cfg.APIUser)
	if cfg.APIPassword != "" {
		fmt.Printf("  APIPassword:  %s\n", "********")
	} else {
		fmt.Printf("  APIPassword:  \n")
	}
	fmt.Printf("  LatestVersion: %s\n", cfg.LatestVersion)

	answer := strings.ToLower(PromptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.Protocol = PromptInput("  Protocol", cfg.Protocol)
		cfg.FQDN = PromptInput("  FQDN", cfg.FQDN)
		cfg.Port = PromptInput("  Port", cfg.Port)
		cfg.APIUser = PromptInput("  APIUser", cfg.APIUser)
		cfg.APIPassword = PromptPassword("  APIPassword", cfg.APIPassword)
		cfg.LatestVersion = PromptInput("  LatestVersion", cfg.LatestVersion)

		if err := delphi.SaveDelphiConfig(&cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration updated.")
	}
	return cfg
}

func ReadLine() string {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func YesOrNo() bool {
	text := ReadLine()
	return strings.ToLower(text) == "y" || strings.ToLower(text) == "yes"
}
