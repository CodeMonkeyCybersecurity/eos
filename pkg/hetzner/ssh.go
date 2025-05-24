package hetzner

import (
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
)

func GetAllSshKeys(ctx *eosio.RuntimeContext) error {
	log := ctx.Logger()
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	keys, err := client.SSHKey.All(ctx.Ctx)
	if err != nil {
		log.Error("❌ Failed to list SSH keys", zap.Error(err))
		return cerr.Wrap(err, "failed to list ssh keys")
	}

	for _, key := range keys {
		log.Info("🔑 SSH key", zap.String("name", key.Name), zap.Int64("id", key.ID))
	}
	return nil
}

func CreateSshKey(ctx *eosio.RuntimeContext, name string, publicKey string) error {
	log := ctx.Logger()
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	key, _, err := client.SSHKey.Create(ctx.Ctx, hcloud.SSHKeyCreateOpts{
		Name:      name,
		PublicKey: publicKey,
		Labels: map[string]string{
			"environment": "prod",
		},
	})
	if err != nil {
		log.Error("❌ Failed to create SSH key", zap.Error(err))
		return cerr.Wrap(err, "failed to create ssh key")
	}

	log.Info("✅ SSH key created", zap.String("name", key.Name), zap.Int64("id", key.ID))
	return nil
}

func GetAnSshKey(ctx *eosio.RuntimeContext, id int64) error {
	log := ctx.Logger()
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	key, _, err := client.SSHKey.GetByID(ctx.Ctx, id)
	if err != nil {
		log.Error("❌ Failed to get SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get ssh key")
	}
	if key == nil {
		log.Warn("⚠️ SSH key not found", zap.Int64("id", id))
		return nil
	}

	log.Info("🔍 SSH key found", zap.String("name", key.Name), zap.Int64("id", key.ID))
	return nil
}

func UpdateAnSshKey(ctx *eosio.RuntimeContext, id int64, newName string) error {
	log := ctx.Logger()
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	updated, _, err := client.SSHKey.Update(ctx.Ctx, &hcloud.SSHKey{ID: id}, hcloud.SSHKeyUpdateOpts{
		Name: newName, // ✅ pass as string, not *string
		Labels: map[string]string{
			"environment": "prod",
		},
	})
	if err != nil {
		log.Error("❌ Failed to update SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to update ssh key")
	}

	log.Info("✏️ SSH key updated", zap.String("name", updated.Name), zap.Int64("id", updated.ID))
	return nil
}

func DeleteAnSshKey(ctx *eosio.RuntimeContext, id int64) error {
	log := ctx.Logger()
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	_, err := client.SSHKey.Delete(ctx.Ctx, &hcloud.SSHKey{ID: id})
	if err != nil {
		log.Error("❌ Failed to delete SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to delete ssh key")
	}

	log.Info("🗑️ SSH key deleted", zap.Int64("id", id))
	return nil
}
