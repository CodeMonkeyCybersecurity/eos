// pkg/interaction/reader.go

package interaction

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadLine prompts the user with a label and returns a trimmed line of input.
func ReadLine(ctx context.Context, reader *bufio.Reader, label string) (string, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("📝 Prompting user for input", zap.String("label", label))

	// Use os.Stderr for user-facing prompts to preserve stdout for automation
	_, _ = fmt.Fprint(os.Stderr, label+": ")

	text, err := reader.ReadString('\n')
	if err != nil {
		otelzap.Ctx(ctx).Error("❌ Failed to read user input", zap.Error(err))
		return "", err
	}

	value := strings.TrimSpace(text)
	otelzap.Ctx(ctx).Debug("📥 User input received", zap.String("value", value))
	return value, nil
}

// ReadLines prompts for multiple labeled inputs.
func ReadLines(rc *eos_io.RuntimeContext, reader *bufio.Reader, label string, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid input count: %d", count)
	}
	values := make([]string, count)
	for i := 0; i < count; i++ {
		prompt := label
		if count > 1 {
			prompt = fmt.Sprintf("%s %d", label, i+1)
		}
		val, err := ReadLine(rc.Ctx, reader, prompt)
		if err != nil {
			return values[:i], fmt.Errorf("error reading '%s': %w", prompt, err)
		}
		values[i] = val
	}
	return values, nil
}
