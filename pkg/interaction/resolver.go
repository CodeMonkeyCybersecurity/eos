/* pkg/interaction/resolver.go */

package interaction

import (
	"bufio"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Resolve prompts the user with a yes/no question and returns their response.
// P0 COMPLIANCE: Uses structured logging instead of fmt.Print*
func Resolve(rc *eos_io.RuntimeContext, prompt string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: " + prompt + " (y/N)")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes", nil
}

// ResolveObject prompts the user to confirm an object's summary.
// P0 COMPLIANCE: Uses structured logging instead of fmt.Print*
func ResolveObject(rc *eos_io.RuntimeContext, c Confirmable) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(c.Summary())
	return Resolve(rc, "Are these values correct?")
}
