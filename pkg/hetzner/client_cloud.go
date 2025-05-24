// pkg/hetzner/client.go

package hetzner

import (
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"
)

// NewClient initializes a Hetzner API client using the HETZNER_TOKEN env var
func NewCloudClient(log *zap.Logger) *hcloud.Client {
	token := os.Getenv("HETZNER_TOKEN")
	if token == "" {
		log.Fatal("🚫 HETZNER_TOKEN environment variable not set")
	}
	log.Info("🔐 Creating Hetzner client")
	return hcloud.NewClient(hcloud.WithToken(token))
}
