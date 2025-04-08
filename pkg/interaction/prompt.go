// pkg/interaction/prompt.go
package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PromptSelect shows a list of options and returns the chosen value.
func promptSelect(prompt string, options []string) string {
	fmt.Println(prompt)
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter choice number: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		idx, err := strconv.Atoi(choice)
		if err == nil && idx >= 1 && idx <= len(options) {
			return options[idx-1]
		}
		fmt.Println("Invalid selection. Please try again.")
	}
}

// PromptYesNo asks a yes/no question, optionally defaulting to yes or no.
func promptYesNo(prompt string, defaultYes bool) bool {
	def := "Y/n"
	if !defaultYes {
		def = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, def)
	reader := bufio.NewReader(os.Stdin)
	input, _ := readLine(reader, "")

	switch strings.ToLower(strings.TrimSpace(input)) {
	case "", "y", "yes":
		return defaultYes || input == "y" || input == "yes"
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// PromptConfirmOrValue asks the user to accept a default value or enter a new one.
func promptConfirmOrValue(prompt, defaultValue string) string {
	if PromptYesNo(fmt.Sprintf("%s (default: %s)?", prompt, defaultValue), true) {
		return defaultValue
	}
	fmt.Print("Enter value: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := readLine(reader, "")
	return input
}

// PromptInputs collects one or more lines of input with labels like "Field", "Field 1", etc.
func promptInputs(reader *bufio.Reader, label string, n int) ([]string, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid input count: %d", n)
	}
	inputs := make([]string, n)
	for i := 0; i < n; i++ {
		prompt := label
		if n > 1 {
			prompt = fmt.Sprintf("%s %d", label, i+1)
		}
		fmt.Print(prompt + ": ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return inputs[:i], fmt.Errorf("failed to read input for '%s': %w", prompt, err)
		}
		inputs[i] = strings.TrimSpace(text)
	}
	return inputs, nil
}

// PromptInput displays a prompt and reads user input.
func promptInput(prompt, defaultVal string) string {
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
