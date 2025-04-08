// pkg/interaction/input.go

package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// promptPassword displays a prompt and reads a password without echoing.
func promptPassword(prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		return "", err
	}
	fmt.Println("")
	pass := strings.TrimSpace(string(bytePassword))
	return pass, nil
}

// PromptRequired prompts the user for input and returns the trimmed value.
// It keeps asking until a non-empty string is entered.
func promptRequired(label string) string {
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

// PromptWithDefault prompts the user and returns their response or a default value if empty.
func promptWithDefault(label, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [%s]: ", label, defaultValue)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultValue
	}
	return text
}
