package remote

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewConfig creates a new RemoteConfig with defaults
// Migrated from cmd/self/git/remote.go package-level variable initialization
func NewConfig() *RemoteConfig {
	return &RemoteConfig{}
}

// SetDefaultPath sets the default path to current working directory if not specified
// Migrated from cmd/self/git/remote.go repeated path resolution logic
func (c *RemoteConfig) SetDefaultPath(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if path needs to be set
	if c.Path != "" {
		logger.Debug("🗂️ Path already configured", zap.String("path", c.Path))
		return nil
	}
	
	// INTERVENE - Set default path to current directory
	logger.Debug("🗂️ Setting default path to current working directory")
	
	var err error
	c.Path, err = os.Getwd()
	if err != nil {
		logger.Error("❌ Failed to get current directory", zap.Error(err))
		return err
	}
	
	// EVALUATE - Log successful path resolution
	logger.Debug("✅ Default path set successfully", zap.String("path", c.Path))
	return nil
}

// ValidateAddOperation validates configuration for add operation
// Migrated from cmd/self/git/remote.go add command validation logic
func (c *RemoteConfig) ValidateAddOperation(args []string) error {
	// ASSESS - Check if name and URL are provided via args
	if len(args) >= 2 && c.AddName == "" && c.AddURL == "" {
		c.AddName = args[0]
		c.AddURL = args[1]
	}
	
	// EVALUATE - Validate required fields
	if c.AddName == "" || c.AddURL == "" {
		return &ValidationError{
			Operation: "add",
			Message:   "both remote name and URL are required",
		}
	}
	
	return nil
}

// ValidateSetURLOperation validates configuration for set-url operation
// Migrated from cmd/self/git/remote.go set-url command validation logic
func (c *RemoteConfig) ValidateSetURLOperation(args []string) error {
	// ASSESS - Check if name and URL are provided via args
	if len(args) >= 2 && c.SetURLName == "" && c.SetURLURL == "" {
		c.SetURLName = args[0]
		c.SetURLURL = args[1]
	}
	
	// EVALUATE - Validate required fields
	if c.SetURLName == "" || c.SetURLURL == "" {
		return &ValidationError{
			Operation: "set-url",
			Message:   "both remote name and new URL are required",
		}
	}
	
	return nil
}

// ValidateRemoveOperation validates configuration for remove operation
// Migrated from cmd/self/git/remote.go remove command validation logic
func (c *RemoteConfig) ValidateRemoveOperation(args []string) error {
	// ASSESS - Check if name is provided via args
	if len(args) >= 1 && c.RemoveName == "" {
		c.RemoveName = args[0]
	}
	
	// EVALUATE - Validate required fields
	if c.RemoveName == "" {
		return &ValidationError{
			Operation: "remove",
			Message:   "remote name is required",
		}
	}
	
	return nil
}

// ValidateRenameOperation validates configuration for rename operation
// Migrated from cmd/self/git/remote.go rename command validation logic
func (c *RemoteConfig) ValidateRenameOperation(args []string) error {
	// ASSESS - Check if names are provided via args
	if len(args) >= 2 && c.RenameOldName == "" && c.RenameNewName == "" {
		c.RenameOldName = args[0]
		c.RenameNewName = args[1]
	}
	
	// EVALUATE - Validate required fields
	if c.RenameOldName == "" || c.RenameNewName == "" {
		return &ValidationError{
			Operation: "rename",
			Message:   "both old and new remote names are required",
		}
	}
	
	return nil
}

// ValidationError represents a validation error for remote operations
type ValidationError struct {
	Operation string
	Message   string
}

func (e *ValidationError) Error() string {
	return e.Message
}