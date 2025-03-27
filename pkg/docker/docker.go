// pkg/docker/docker.go

package docker

import (
	"go.uber.org/zap"

	"eos/pkg/execute"
	"eos/pkg/logger"
)

var log = logger.L()

func runDockerAction(action string, args ...string) error {
	fullArgs := append([]string{action}, args...)
	if err := execute.Execute("docker", fullArgs...); err != nil {
		log.Warn("Docker action failed", zap.String("action", action), zap.Strings("args", args), zap.Error(err))
		return err
	}
	log.Info("Docker action succeeded", zap.String("action", action), zap.Strings("args", args))
	return nil
}
