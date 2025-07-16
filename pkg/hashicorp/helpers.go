// pkg/hashicorp/helpers.go

package hashicorp

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/prompt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// isToolInstalled checks if a HashiCorp tool is already installed
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// installPrerequisitesWithPrompt installs prerequisites with user confirmation
func installPrerequisitesWithPrompt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we need root privileges
	if platform.DetectLinuxDistro(rc) != "" && os.Geteuid() != 0 {
		return prompt.RequireRoot(rc, "HashiCorp tool installation")
	}

	// Check which prerequisites are missing
	prerequisites := []string{"wget", "gpg", "lsb-release"}
	missingPrereqs := []string{}

	for _, prereq := range prerequisites {
		if !prompt.CheckDependency(prereq) {
			missingPrereqs = append(missingPrereqs, prereq)
		}
	}

	if len(missingPrereqs) == 0 {
		logger.Info("All prerequisites already installed")
		return nil
	}

	// Prompt user to install missing prerequisites
	fmt.Printf("\n⚠️  The following prerequisites are missing: %v\n", missingPrereqs)
	fmt.Println("These are required to install HashiCorp tools from the official repository.")

	install, err := prompt.YesNo(rc, "Would you like to install these prerequisites?", true)
	if err != nil {
		return err
	}

	if !install {
		fmt.Println("\n❌ Prerequisites are required for HashiCorp tool installation.")
		fmt.Println("   Please install them manually and try again.")
		return fmt.Errorf("prerequisites not installed")
	}

	// Install prerequisites
	return installPrerequisites(rc)
}
