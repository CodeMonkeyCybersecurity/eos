/* pkg/interaction/reader.go */

package interaction

import (
	"bufio"
	"fmt"
	"strings"
)

func readLine(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label + ": ")
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func readLines(reader *bufio.Reader, label string, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid input count: %d", count)
	}
	values := make([]string, count)
	for i := 0; i < count; i++ {
		prompt := label
		if count > 1 {
			prompt = fmt.Sprintf("%s %d", label, i+1)
		}
		val, err := readLine(reader, prompt)
		if err != nil {
			return values[:i], fmt.Errorf("error reading '%s': %w", prompt, err)
		}
		values[i] = val
	}
	return values, nil
}
