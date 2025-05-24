// pkg/hetzner/floating_ips.go

package hetzner

import (
	"context"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.uber.org/zap"
)

func ListFloatingIPs(ctx context.Context, client *hcloud.Client) ([]*hcloud.FloatingIP, error) {
	ips, _, err := client.FloatingIP.List(ctx, hcloud.FloatingIPListOpts{})
	if err != nil {
		zap.L().Error("Failed to list floating IPs", zap.Error(err))
		return nil, err
	}
	zap.L().Info("📡 Floating IPs retrieved", zap.Int("count", len(ips)))
	return ips, nil
}

func CreateFloatingIP(ctx context.Context, client *hcloud.Client, ipType hcloud.FloatingIPType, homeLocation *hcloud.Location) (*hcloud.FloatingIP, error) {
	opts := hcloud.FloatingIPCreateOpts{
		Type:         ipType,
		HomeLocation: homeLocation,
	}
	result, _, err := client.FloatingIP.Create(ctx, opts)
	if err != nil {
		zap.L().Error("Failed to create floating IP", zap.Error(err))
		return nil, err
	}
	zap.L().Info("✅ Floating IP created", zap.String("ip", result.FloatingIP.IP.String()))
	return result.FloatingIP, nil
}

func AssignFloatingIP(ctx context.Context, client *hcloud.Client, ip *hcloud.FloatingIP, server *hcloud.Server) error {
	_, _, err := client.FloatingIP.Assign(ctx, ip, server)
	if err != nil {
		zap.L().Error("Failed to assign floating IP", zap.String("ip", ip.IP.String()), zap.String("server", server.Name), zap.Error(err))
		return err
	}
	zap.L().Info("🔗 Floating IP assigned", zap.String("ip", ip.IP.String()), zap.String("server", server.Name))
	return nil
}

func UnassignFloatingIP(ctx context.Context, client *hcloud.Client, ip *hcloud.FloatingIP) error {
	_, _, err := client.FloatingIP.Unassign(ctx, ip)
	if err != nil {
		zap.L().Error("Failed to unassign floating IP", zap.String("ip", ip.IP.String()), zap.Error(err))
		return err
	}
	zap.L().Info("🔌 Floating IP unassigned", zap.String("ip", ip.IP.String()))
	return nil
}

func DeleteFloatingIP(ctx context.Context, client *hcloud.Client, ip *hcloud.FloatingIP) error {
	_, err := client.FloatingIP.Delete(ctx, ip)
	if err != nil {
		zap.L().Error("Failed to delete floating IP", zap.String("ip", ip.IP.String()), zap.Error(err))
		return err
	}
	zap.L().Info("🗑️ Floating IP deleted", zap.String("ip", ip.IP.String()))
	return nil
}

func ChangeFloatingIPRDNS(ctx context.Context, client *hcloud.Client, ip *hcloud.FloatingIP, dnsPtr string) error {
	ipStr := ip.IP.String()
	_, _, err := client.FloatingIP.ChangeDNSPtr(ctx, ip, ipStr, &dnsPtr)
	if err != nil {
		zap.L().Error("Failed to change reverse DNS", zap.String("ip", ipStr), zap.Error(err))
		return err
	}
	zap.L().Info("🔁 Reverse DNS updated", zap.String("ip", ipStr), zap.String("rdns", dnsPtr))
	return nil
}
