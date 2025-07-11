// pkg/hetzner/client.go

package hetzner

import (
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"
)

// TODO: Refactor Hetzner package to follow Eos standards:
// 1. Accept *eos_io.RuntimeContext instead of *zap.Logger
// 2. Use otelzap.Ctx(rc.Ctx) for logging instead of direct zap usage
// 3. Consider using shared.HTTPClient for API calls if not using hcloud SDK
// 4. Add proper error handling instead of log.Fatal
// 5. Use eos_err.NewUserError for missing token instead of fatal
// 6. Consider integrating with shared configuration management for API tokens

// NewClient initializes a Hetzner API client using the HETZNER_TOKEN env var
func NewCloudClient(log *zap.Logger) *hcloud.Client {
	token := os.Getenv("HETZNER_TOKEN")
	if token == "" {
		log.Fatal(" HETZNER_TOKEN environment variable not set")
	}
	log.Info(" Creating Hetzner client")
	return hcloud.NewClient(hcloud.WithToken(token))
}
