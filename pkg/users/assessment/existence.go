package assessment

import (
	"fmt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UserExistence checks if user already exists on target systems
// Migrated from cmd/create/user.go assessUserExistence
func UserExistence(rc *eos_io.RuntimeContext, target, username string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing user existence",
		zap.String("username", username),
		zap.String("target", target))

	// INTERVENE - User existence check requires administrator intervention
	logger.Warn("User existence check requires administrator intervention - HashiCorp stack cannot query system users directly",
		zap.String("username", username),
		zap.String("target", target))

	// EVALUATE - Return escalation error
	return fmt.Errorf("user existence check requires administrator intervention - HashiCorp stack cannot query system users directly")
}
