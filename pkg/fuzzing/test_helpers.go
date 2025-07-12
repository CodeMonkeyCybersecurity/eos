package fuzzing

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap/zaptest"
)

// NewTestContext creates a RuntimeContext suitable for testing
func NewTestContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	
	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        logger,
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    t.Name(),
		Attributes: make(map[string]string),
	}
}