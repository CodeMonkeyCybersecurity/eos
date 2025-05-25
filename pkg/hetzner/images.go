package hetzner

import (
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllImages(ctx *eos_io.RuntimeContext) error {
	log := ctx.Log
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	images, err := client.Image.All(ctx.Ctx)
	if err != nil {
		log.Error("❌ Failed to retrieve images", zap.Error(err))
		return cerr.Wrap(err, "failed to retrieve images")
	}

	for _, img := range images {
		log.Info("📸 Image", zap.String("name", img.Name), zap.Int64("id", img.ID), zap.String("type", string(img.Type)))
	}
	return nil
}

func GetAnImage(ctx *eos_io.RuntimeContext, id int64) error {
	log := ctx.Log
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	image, _, err := client.Image.GetByID(ctx.Ctx, id)
	if err != nil {
		log.Error("❌ Failed to get image", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to get image")
	}

	if image == nil {
		log.Warn("⚠️ Image not found", zap.Int64("id", id))
		return nil
	}

	log.Info("📷 Retrieved image", zap.String("name", image.Name), zap.Int64("id", image.ID), zap.String("status", string(image.Status)))
	return nil
}

func UpdateAnImage(ctx *eos_io.RuntimeContext, id int64, newDesc string) error {
	log := ctx.Log
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	updated, _, err := client.Image.Update(ctx.Ctx, &hcloud.Image{ID: id}, hcloud.ImageUpdateOpts{
		Description: hcloud.Ptr(newDesc),
		Labels: map[string]string{
			"environment":    "prod",
			"example.com/my": "label",
			"just-a-key":     "",
		},
		Type: hcloud.ImageTypeSnapshot,
	})
	if err != nil {
		log.Error("❌ Failed to update image", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to update image")
	}

	log.Info("📝 Image updated", zap.String("name", updated.Name), zap.Int64("id", updated.ID))
	return nil
}

func DeleteAnImage(ctx *eos_io.RuntimeContext, id int64) error {
	log := ctx.Log
	client := hcloud.NewClient(hcloud.WithToken(os.Getenv("HCLOUD_TOKEN")))

	_, err := client.Image.Delete(ctx.Ctx, &hcloud.Image{ID: id})
	if err != nil {
		log.Error("❌ Failed to delete image", zap.Int64("id", id), zap.Error(err))
		return cerr.Wrap(err, "failed to delete image")
	}

	log.Info("🗑️ Image deleted", zap.Int64("id", id))
	return nil
}
