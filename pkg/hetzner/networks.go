package hetzner

import (
	"net"
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllNetworks(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	networks, err := client.Network.All(rc.Ctx)
	if err != nil {
		log.Error(" Failed to list networks", zap.Error(err))
		return cerr.Wrap(err, "failed to list networks")
	}

	for _, n := range networks {
		log.Info("🌐 Network", zap.String("name", n.Name), zap.Int64("id", n.ID))
	}
	return nil
}

func CreateANetwork(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	result, _, err := client.Network.Create(rc.Ctx, hcloud.NetworkCreateOpts{
		ExposeRoutesToVSwitch: false,
		IPRange: &net.IPNet{
			IP:   net.ParseIP("10.0.0.0"),
			Mask: net.CIDRMask(16, 32),
		},
		Labels: map[string]string{
			"environment":    "prod",
			"example.com/my": "label",
			"just-a-key":     "",
		},
		Name: "mynet",
		Routes: []hcloud.NetworkRoute{
			{
				Destination: &net.IPNet{
					IP:   net.ParseIP("10.100.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: net.ParseIP("10.0.1.1"),
			},
		},
		Subnets: []hcloud.NetworkSubnet{
			{
				IPRange: &net.IPNet{
					IP:   net.ParseIP("10.0.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
				NetworkZone: hcloud.NetworkZoneEUCentral,
				Type:        hcloud.NetworkSubnetTypeCloud,
				VSwitchID:   1000,
			},
		},
	})
	if err != nil {
		log.Error(" Failed to create network", zap.Error(err))
		return cerr.Wrap(err, "failed to create network")
	}

	log.Info(" Network created", zap.String("name", result.Name), zap.Int64("id", result.ID))
	return nil
}

func GetANetwork(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	network, _, err := client.Network.GetByID(rc.Ctx, id)
	if err != nil {
		log.Error(" Failed to get network", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get network")
	}
	if network == nil {
		log.Warn("No network found", zap.Int64("id", id))
		return nil
	}

	log.Info(" Network info", zap.String("name", network.Name), zap.Int64("id", network.ID))
	return nil
}

func UpdateANetwork(rc *eos_io.RuntimeContext, id int64, newName string) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	updated, _, err := client.Network.Update(rc.Ctx, &hcloud.Network{ID: id}, hcloud.NetworkUpdateOpts{
		ExposeRoutesToVSwitch: hcloud.Ptr(false),
		Name:                  newName,
		Labels: map[string]string{
			"environment":    "prod",
			"example.com/my": "label",
			"just-a-key":     "",
		},
	})
	if err != nil {
		log.Error(" Failed to update network", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to update network")
	}

	log.Info("✏️ Network updated", zap.String("name", updated.Name), zap.Int64("id", updated.ID))
	return nil
}

func DeleteANetwork(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	_, err := client.Network.Delete(rc.Ctx, &hcloud.Network{ID: id})
	if err != nil {
		log.Error(" Failed to delete network", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to delete network")
	}

	log.Info("🗑️ Network deleted", zap.Int64("id", id))
	return nil
}
