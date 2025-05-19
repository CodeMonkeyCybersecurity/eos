// pkg/execute/helpers.go

package execute

import (
	"strings"
	"time"
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func defaultTimeout(t time.Duration) time.Duration {
	if t > 0 {
		return t
	}
	return 30 * time.Second
}

func buildCommandString(command string, args ...string) string {
	return command + " " + strings.Join(args, " ")
}
