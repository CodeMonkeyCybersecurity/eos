// pkg/docker/images.go

package docker

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

//
//---------------------------- IMAGE FUNCTIONS ---------------------------- //
//

// RemoveImages removes the specified Docker images.
// It logs a warning if an image cannot be removed, but continues with the others.
func RemoveImages(images []string) error {
	for _, image := range images {
		if err := execute.Execute("docker", "rmi", image); err != nil {
		} else {
		}
	}
	return nil
}
