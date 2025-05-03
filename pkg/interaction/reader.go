// pkg/interaction/reader.go

package interaction

import (
	"bufio"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ReadLine prompts the user with a label and returns a trimmed line of input.
func ReadLine(reader *bufio.Reader, label string) (string, error) {
	zap.L().Debug("📝 Prompting user for input", zap.String("label", label))
	fmt.Print(label + ": ")

	text, err := reader.ReadString('\n')
	if err != nil {
		zap.L().Error("❌ Failed to read user input", zap.Error(err))
		return "", err
	}

	value := strings.TrimSpace(text)
	zap.L().Debug("📥 User input received", zap.String("value", value))
	return value, nil
}

// ReadLines prompts for multiple labeled inputs.
func ReadLines(reader *bufio.Reader, label string, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid input count: %d", count)
	}
	values := make([]string, count)
	for i := 0; i < count; i++ {
		prompt := label
		if count > 1 {
			prompt = fmt.Sprintf("%s %d", label, i+1)
		}
		val, err := ReadLine(reader, prompt)
		if err != nil {
			return values[:i], fmt.Errorf("error reading '%s': %w", prompt, err)
		}
		values[i] = val
	}
	return values, nil
}
