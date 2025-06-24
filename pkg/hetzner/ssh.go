package hetzner

import (
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllSshKeys(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	keys, err := client.SSHKey.All(rc.Ctx)
	if err != nil {
		log.Error(" Failed to list SSH keys", zap.Error(err))
		return cerr.Wrap(err, "failed to list ssh keys")
	}

	for _, key := range keys {
		log.Info(" SSH key", zap.String("name", key.Name), zap.Int64("id", key.ID))
	}
	return nil
}

func CreateSshKey(rc *eos_io.RuntimeContext, name string, publicKey string) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	key, _, err := client.SSHKey.Create(rc.Ctx, hcloud.SSHKeyCreateOpts{
		Name:      name,
		PublicKey: publicKey,
		Labels: map[string]string{
			"environment": "prod",
		},
	})
	if err != nil {
		log.Error(" Failed to create SSH key", zap.Error(err))
		return cerr.Wrap(err, "failed to create ssh key")
	}

	log.Info(" SSH key created", zap.String("name", key.Name), zap.Int64("id", key.ID))
	return nil
}

func GetAnSshKey(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	key, _, err := client.SSHKey.GetByID(rc.Ctx, id)
	if err != nil {
		log.Error(" Failed to get SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get ssh key")
	}
	if key == nil {
		log.Warn("SSH key not found", zap.Int64("id", id))
		return nil
	}

	log.Info(" SSH key found", zap.String("name", key.Name), zap.Int64("id", key.ID))
	return nil
}

func UpdateAnSshKey(rc *eos_io.RuntimeContext, id int64, newName string) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	updated, _, err := client.SSHKey.Update(rc.Ctx, &hcloud.SSHKey{ID: id}, hcloud.SSHKeyUpdateOpts{
		Name: newName, //  pass as string, not *string
		Labels: map[string]string{
			"environment": "prod",
		},
	})
	if err != nil {
		log.Error(" Failed to update SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to update ssh key")
	}

	log.Info(" SSH key updated", zap.String("name", updated.Name), zap.Int64("id", updated.ID))
	return nil
}

func DeleteAnSshKey(rc *eos_io.RuntimeContext, id int64) error {
	log := otelzap.Ctx(rc.Ctx)
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	_, err := client.SSHKey.Delete(rc.Ctx, &hcloud.SSHKey{ID: id})
	if err != nil {
		log.Error(" Failed to delete SSH key", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to delete ssh key")
	}

	log.Info(" SSH key deleted", zap.Int64("id", id))
	return nil
}
