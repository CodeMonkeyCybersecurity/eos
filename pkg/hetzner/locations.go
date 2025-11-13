// pkg/hetzner/client.go

package hetzner

import (
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllLocations(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	locations, err := client.Location.All(rc.Ctx)
	if err != nil {
		log.Error(" Failed to retrieve locations", zap.Error(err))
		return cerr.Wrap(err, "failed to retrieve locations")
	}

	for _, loc := range locations {
		log.Info("📍 Location", zap.String("name", loc.Name), zap.String("city", loc.City), zap.String("country", loc.Country))
	}
	return nil
}

func GetALocation(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	loc, _, err := client.Location.GetByID(rc.Ctx, id)
	if err != nil {
		log.Error(" Failed to get location", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get location")
	}

	log.Info("📍 Location details", zap.String("name", loc.Name), zap.String("city", loc.City), zap.String("country", loc.Country))
	return nil
}

func GetAllDatacentres(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	dcs, err := client.Datacenter.All(rc.Ctx)
	if err != nil {
		log.Error(" Failed to retrieve datacenters", zap.Error(err))
		return cerr.Wrap(err, "failed to retrieve datacenters")
	}

	for _, dc := range dcs {
		log.Info(" Datacenter", zap.String("name", dc.Name), zap.String("location", dc.Location.Name))
	}
	return nil
}

func GetADatacentre(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	dc, _, err := client.Datacenter.GetByID(rc.Ctx, id)
	if err != nil {
		log.Error(" Failed to get datacenter", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get datacenter")
	}

	log.Info(" Datacenter details", zap.String("name", dc.Name), zap.String("description", dc.Description), zap.String("location", dc.Location.Name))
	return nil
}
