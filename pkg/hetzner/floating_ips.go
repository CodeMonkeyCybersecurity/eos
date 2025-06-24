// pkg/hetzner/floating_ips.go

package hetzner

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func ListFloatingIPs(rc *eos_io.RuntimeContext, client *hcloud.Client) ([]*hcloud.FloatingIP, error) {
	ips, _, err := client.FloatingIP.List(rc.Ctx, hcloud.FloatingIPListOpts{})
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to list floating IPs", zap.Error(err))
		return nil, err
	}
	otelzap.Ctx(rc.Ctx).Info(" Floating IPs retrieved", zap.Int("count", len(ips)))
	return ips, nil
}

func CreateFloatingIP(rc *eos_io.RuntimeContext, client *hcloud.Client, ipType hcloud.FloatingIPType, homeLocation *hcloud.Location) (*hcloud.FloatingIP, error) {
	opts := hcloud.FloatingIPCreateOpts{
		Type:         ipType,
		HomeLocation: homeLocation,
	}
	result, _, err := client.FloatingIP.Create(rc.Ctx, opts)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create floating IP", zap.Error(err))
		return nil, err
	}
	otelzap.Ctx(rc.Ctx).Info(" Floating IP created", zap.String("ip", result.FloatingIP.IP.String()))
	return result.FloatingIP, nil
}

func AssignFloatingIP(rc *eos_io.RuntimeContext, client *hcloud.Client, ip *hcloud.FloatingIP, server *hcloud.Server) error {
	_, _, err := client.FloatingIP.Assign(rc.Ctx, ip, server)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to assign floating IP", zap.String("ip", ip.IP.String()), zap.String("server", server.Name), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("🔗 Floating IP assigned", zap.String("ip", ip.IP.String()), zap.String("server", server.Name))
	return nil
}

func UnassignFloatingIP(rc *eos_io.RuntimeContext, client *hcloud.Client, ip *hcloud.FloatingIP) error {
	_, _, err := client.FloatingIP.Unassign(rc.Ctx, ip)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to unassign floating IP", zap.String("ip", ip.IP.String()), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("🔌 Floating IP unassigned", zap.String("ip", ip.IP.String()))
	return nil
}

func DeleteFloatingIP(rc *eos_io.RuntimeContext, client *hcloud.Client, ip *hcloud.FloatingIP) error {
	_, err := client.FloatingIP.Delete(rc.Ctx, ip)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to delete floating IP", zap.String("ip", ip.IP.String()), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("🗑️ Floating IP deleted", zap.String("ip", ip.IP.String()))
	return nil
}

func ChangeFloatingIPRDNS(rc *eos_io.RuntimeContext, client *hcloud.Client, ip *hcloud.FloatingIP, dnsPtr string) error {
	ipStr := ip.IP.String()
	_, _, err := client.FloatingIP.ChangeDNSPtr(rc.Ctx, ip, ipStr, &dnsPtr)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to change reverse DNS", zap.String("ip", ipStr), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("🔁 Reverse DNS updated", zap.String("ip", ipStr), zap.String("rdns", dnsPtr))
	return nil
}
