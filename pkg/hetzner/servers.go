// pkg/hetzner/servers.go

package hetzner

import (
	"os"
	"time"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func GetAllServers(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	servers, err := client.Server.All(rc.Ctx)
	if err != nil {
		log.Error("Failed to get all servers", zap.Error(err))
		return cerr.Wrap(err, "failed to get all servers")
	}

	log.Info(" Total servers found", zap.Int("count", len(servers)))
	for _, s := range servers {
		log.Info(" Server", zap.String("name", s.Name), zap.Int64("id", s.ID))
	}
	return nil
}

func ListServersFiltered(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, opts hcloud.ServerListOpts) ([]*hcloud.Server, error) {
	servers, _, err := client.Server.List(rc.Ctx, opts)
	if err != nil {
		log.Error("Failed to list filtered servers", zap.Error(err))
		return nil, err
	}
	log.Info(" Retrieved servers", zap.Int("count", len(servers)))
	return servers, nil
}

func CreateServer(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, opts hcloud.ServerCreateOpts) (*hcloud.Server, *hcloud.Action, error) {
	result, _, err := client.Server.Create(rc.Ctx, opts)
	if err != nil {
		log.Error("Failed to create server", zap.Error(err))
		return nil, nil, err
	}
	log.Info("🆕 Server created", zap.String("name", result.Server.Name), zap.Int64("id", result.Server.ID))
	return result.Server, result.Action, nil
}

func GetAServer(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, id int64) (*hcloud.Server, error) {
	server, _, err := client.Server.GetByID(rc.Ctx, id)
	if err != nil {
		log.Error("Failed to fetch server by ID", zap.Int64("id", id), zap.Error(err))
		return nil, err
	}
	if server == nil {
		log.Warn("No server found with ID", zap.Int64("id", id))
	}
	return server, nil
}

func UpdateServer(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, server *hcloud.Server, name string, labels map[string]string) (*hcloud.Server, error) {
	opts := hcloud.ServerUpdateOpts{
		Name:   name, // fixed: use string, not *string
		Labels: labels,
	}
	updated, _, err := client.Server.Update(rc.Ctx, server, opts)
	if err != nil {
		log.Error("Failed to update server", zap.String("name", server.Name), zap.Error(err))
		return nil, err
	}
	log.Info(" Server updated", zap.String("new_name", name))
	return updated, nil
}

func DeleteServer(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, server *hcloud.Server) (*hcloud.ServerDeleteResult, error) {
	result, _, err := client.Server.DeleteWithResult(rc.Ctx, server)
	if err != nil {
		log.Error("Failed to delete server", zap.String("name", server.Name), zap.Error(err))
		return nil, err
	}
	log.Info(" Server deletion triggered", zap.Int64("id", server.ID))
	return result, nil
}

func GetServerMetrics(rc *eos_io.RuntimeContext, client *hcloud.Client, log *zap.Logger, server *hcloud.Server, metric string, start, end time.Time, step int) (*hcloud.ServerMetrics, error) {
	opts := hcloud.ServerGetMetricsOpts{
		Start: start,
		End:   end,
		Step:  step,
	}
	metrics, _, err := client.Server.GetMetrics(rc.Ctx, server, opts)
	if err != nil {
		log.Error("Failed to fetch server metrics", zap.String("metric", metric), zap.Error(err))
		return nil, err
	}
	log.Info("📈 Server metrics fetched", zap.String("metric", metric), zap.Time("start", start), zap.Time("end", end))
	return metrics, nil
}
