// pkg/docker/images.go

package container

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
//---------------------------- IMAGE FUNCTIONS ---------------------------- //
//

// RemoveImages removes the specified Docker images.
// It logs a warning if an image cannot be removed, but continues with the others.
func RemoveImages(rc *eos_io.RuntimeContext, images []string) error {
	for _, image := range images {
		if err := execute.RunSimple(rc.Ctx, "docker", "rmi", image); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to remove docker image", zap.Error(err))
			return fmt.Errorf("failed to remove docker image")
		}
	}
	return nil
}
