// pkg/logger/writer.go

package logger

import (
	"fmt"
	"strings"
)

func PrintLastNLines(content string, n int) {
	lines := strings.Split(content, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, line := range lines {
		fmt.Println(line)
	}
}
