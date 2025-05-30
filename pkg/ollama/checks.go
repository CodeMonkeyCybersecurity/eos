// pkg/ollama/checks.go

package ollama

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

func isWebUIContainerRunningOnPort3000(rc *eos_io.RuntimeContext) bool {
	out, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "{{.Names}} {{.Ports}}"},
	})
	if err != nil {
		return false
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		// Example: "open-webui 0.0.0.0:3000->8080/tcp"
		if strings.Contains(line, "3000->8080") && strings.Contains(line, "open-webui") {
			return true
		}
	}
	return false
}
