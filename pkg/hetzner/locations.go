// pkg/hetzner/client.go

package hetzner

import (
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
)

func GetAllLocations(ctx *eosio.RuntimeContext) error {
	log := ctx.Logger()
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	locations, err := client.Location.All(ctx.Ctx)
	if err != nil {
		log.Error("❌ Failed to retrieve locations", zap.Error(err))
		return cerr.Wrap(err, "failed to retrieve locations")
	}

	for _, loc := range locations {
		log.Info("📍 Location", zap.String("name", loc.Name), zap.String("city", loc.City), zap.String("country", loc.Country))
	}
	return nil
}

func GetALocation(ctx *eosio.RuntimeContext, id int64) error {
	log := ctx.Logger()
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	loc, _, err := client.Location.GetByID(ctx.Ctx, id)
	if err != nil {
		log.Error("❌ Failed to get location", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get location")
	}

	log.Info("📍 Location details", zap.String("name", loc.Name), zap.String("city", loc.City), zap.String("country", loc.Country))
	return nil
}

func GetAllDatacentres(ctx *eosio.RuntimeContext) error {
	log := ctx.Logger()
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	dcs, err := client.Datacenter.All(ctx.Ctx)
	if err != nil {
		log.Error("❌ Failed to retrieve datacenters", zap.Error(err))
		return cerr.Wrap(err, "failed to retrieve datacenters")
	}

	for _, dc := range dcs {
		log.Info("🏢 Datacenter", zap.String("name", dc.Name), zap.String("location", dc.Location.Name))
	}
	return nil
}

func GetADatacentre(ctx *eosio.RuntimeContext, id int64) error {
	log := ctx.Logger()
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	dc, _, err := client.Datacenter.GetByID(ctx.Ctx, id)
	if err != nil {
		log.Error("❌ Failed to get datacenter", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get datacenter")
	}

	log.Info("🏢 Datacenter details", zap.String("name", dc.Name), zap.String("description", dc.Description), zap.String("location", dc.Location.Name))
	return nil
}
