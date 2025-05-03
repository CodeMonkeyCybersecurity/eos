package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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
