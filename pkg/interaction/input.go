package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// PromptWithDefault prompts the user and returns their response or a default value if empty.
func PromptWithDefault(label, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [%s]: ", label, defaultValue)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultValue
	}
	return text
}

// PromptRequired prompts the user for input and loops until a non-empty string is entered.
func PromptRequired(label string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s: ", label)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
		fmt.Println("Input cannot be empty.")
	}
}

// PromptPassword hides user input and returns the entered password.
func PromptPassword(label string) (string, error) {
	fmt.Printf("%s: ", label)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

// PromptPasswordWithDefault hides user input and returns password or default if blank.
func PromptPasswordWithDefault(label, defaultValue string) (string, error) {
	fmt.Printf("%s [%s]: ", label, "********")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultValue, nil
	}
	return pass, nil
}

// PromptSecrets prompts the user for n secret values (like unseal keys), hiding input.
// It returns a slice of strings (one per secret).
func PromptSecrets(prompt string, count int) ([]string, error) {
	secrets := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		label := fmt.Sprintf("%s %d", prompt, i)
		fmt.Printf("%s: ", label)
		secret, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", label, err)
		}
		secrets = append(secrets, strings.TrimSpace(string(secret)))
	}
	return secrets, nil
}
