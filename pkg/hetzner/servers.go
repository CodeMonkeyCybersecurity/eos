// pkg/hetzner/servers.go

package hetzner

import (
	"context"
	"os"
	"time"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllServers(ctx *eos_io.RuntimeContext) error {
	log := ctx.Log
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	servers, err := client.Server.All(ctx.Ctx)
	if err != nil {
		log.Error("Failed to get all servers", zap.Error(err))
		return cerr.Wrap(err, "failed to get all servers")
	}

	log.Info("📋 Total servers found", zap.Int("count", len(servers)))
	for _, s := range servers {
		log.Info("🖥️ Server", zap.String("name", s.Name), zap.Int64("id", s.ID))
	}
	return nil
}

func ListServersFiltered(ctx context.Context, client *hcloud.Client, log *zap.Logger, opts hcloud.ServerListOpts) ([]*hcloud.Server, error) {
	servers, _, err := client.Server.List(ctx, opts)
	if err != nil {
		log.Error("Failed to list filtered servers", zap.Error(err))
		return nil, err
	}
	log.Info("📋 Retrieved servers", zap.Int("count", len(servers)))
	return servers, nil
}

func CreateServer(ctx context.Context, client *hcloud.Client, log *zap.Logger, opts hcloud.ServerCreateOpts) (*hcloud.Server, *hcloud.Action, error) {
	result, _, err := client.Server.Create(ctx, opts)
	if err != nil {
		log.Error("Failed to create server", zap.Error(err))
		return nil, nil, err
	}
	log.Info("🆕 Server created", zap.String("name", result.Server.Name), zap.Int64("id", result.Server.ID))
	return result.Server, result.Action, nil
}

func GetAServer(ctx context.Context, client *hcloud.Client, log *zap.Logger, id int64) (*hcloud.Server, error) {
	server, _, err := client.Server.GetByID(ctx, id)
	if err != nil {
		log.Error("Failed to fetch server by ID", zap.Int64("id", id), zap.Error(err))
		return nil, err
	}
	if server == nil {
		log.Warn("No server found with ID", zap.Int64("id", id))
	}
	return server, nil
}

func UpdateServer(ctx context.Context, client *hcloud.Client, log *zap.Logger, server *hcloud.Server, name string, labels map[string]string) (*hcloud.Server, error) {
	opts := hcloud.ServerUpdateOpts{
		Name:   name, // fixed: use string, not *string
		Labels: labels,
	}
	updated, _, err := client.Server.Update(ctx, server, opts)
	if err != nil {
		log.Error("Failed to update server", zap.String("name", server.Name), zap.Error(err))
		return nil, err
	}
	log.Info("✏️ Server updated", zap.String("new_name", name))
	return updated, nil
}

func DeleteServer(ctx context.Context, client *hcloud.Client, log *zap.Logger, server *hcloud.Server) (*hcloud.ServerDeleteResult, error) {
	result, _, err := client.Server.DeleteWithResult(ctx, server)
	if err != nil {
		log.Error("Failed to delete server", zap.String("name", server.Name), zap.Error(err))
		return nil, err
	}
	log.Info("🗑️ Server deletion triggered", zap.Int64("id", server.ID))
	return result, nil
}

func GetServerMetrics(ctx context.Context, client *hcloud.Client, log *zap.Logger, server *hcloud.Server, metric string, start, end time.Time, step int) (*hcloud.ServerMetrics, error) {
	opts := hcloud.ServerGetMetricsOpts{
		Start: start,
		End:   end,
		Step:  step,
	}
	metrics, _, err := client.Server.GetMetrics(ctx, server, opts)
	if err != nil {
		log.Error("Failed to fetch server metrics", zap.String("metric", metric), zap.Error(err))
		return nil, err
	}
	log.Info("📈 Server metrics fetched", zap.String("metric", metric), zap.Time("start", start), zap.Time("end", end))
	return metrics, nil
}
