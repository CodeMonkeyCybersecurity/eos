// pkg/docker/images.go

package docker

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

//
//---------------------------- IMAGE FUNCTIONS ---------------------------- //
//

// RemoveImages removes the specified Docker images.
// It logs a warning if an image cannot be removed, but continues with the others.
func RemoveImages(images []string) error {
	for _, image := range images {
		if err := execute.Execute("docker", "rmi", image); err != nil {
			zap.L().Warn("Failed to remove docker image", zap.Error(err))
			return fmt.Errorf("failed to remove docker image")
		}
	}
	return nil
}
