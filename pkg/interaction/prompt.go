// pkg/interaction/prompt.go
package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// PromptSelect shows a list of choices and returns the selected value.
func PromptSelect(prompt string, options []string) string {
	fmt.Println(prompt)
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter choice number: ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		for i, option := range options {
			if text == fmt.Sprintf("%d", i+1) {
				return option
			}
		}
		fmt.Println("Invalid selection. Please try again.")
	}
}

func PromptYesNo(prompt string, defaultYes bool) bool {
	def := "Y/n"
	if !defaultYes {
		def = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, def)
	input := readLine()
	input = strings.TrimSpace(strings.ToLower(input))

	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

func PromptConfirmOrValue(prompt, defaultValue string) string {
	if PromptYesNo(fmt.Sprintf("%s (default: %s)?", prompt, defaultValue), true) {
		return defaultValue
	}
	fmt.Print("Enter directory path: ")
	return readLine()
}

func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
