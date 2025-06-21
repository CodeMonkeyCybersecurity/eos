package inspect

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiscoverHetzner gathers Hetzner Cloud infrastructure information
func (i *Inspector) DiscoverHetzner() (*HetznerInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info("☁️ Starting Hetzner Cloud discovery")

	// Check if hcloud CLI is installed
	if !i.commandExists("hcloud") {
		return nil, fmt.Errorf("hcloud CLI not found")
	}

	// Check if hcloud is configured
	if output, err := i.runCommand("hcloud", "context", "active"); err != nil || output == "" {
		return nil, fmt.Errorf("hcloud CLI not configured (no active context)")
	}

	info := &HetznerInfo{}

	// Discover servers
	if servers, err := i.discoverHetznerServers(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner servers", zap.Error(err))
	} else {
		info.Servers = servers
		logger.Info("🖥️ Discovered Hetzner servers", zap.Int("count", len(servers)))
	}

	// Discover networks
	if networks, err := i.discoverHetznerNetworks(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner networks", zap.Error(err))
	} else {
		info.Networks = networks
		logger.Info("🌐 Discovered Hetzner networks", zap.Int("count", len(networks)))
	}

	// Discover firewalls
	if firewalls, err := i.discoverHetznerFirewalls(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner firewalls", zap.Error(err))
	} else {
		info.Firewalls = firewalls
		logger.Info("🔒 Discovered Hetzner firewalls", zap.Int("count", len(firewalls)))
	}

	// Discover load balancers
	if lbs, err := i.discoverHetznerLoadBalancers(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner load balancers", zap.Error(err))
	} else {
		info.LoadBalancers = lbs
		logger.Info("⚖️ Discovered Hetzner load balancers", zap.Int("count", len(lbs)))
	}

	// Discover volumes
	if volumes, err := i.discoverHetznerVolumes(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner volumes", zap.Error(err))
	} else {
		info.Volumes = volumes
		logger.Info("💾 Discovered Hetzner volumes", zap.Int("count", len(volumes)))
	}

	// Discover floating IPs
	if fips, err := i.discoverHetznerFloatingIPs(); err != nil {
		logger.Warn("⚠️ Failed to discover Hetzner floating IPs", zap.Error(err))
	} else {
		info.FloatingIPs = fips
		logger.Info("🌐 Discovered Hetzner floating IPs", zap.Int("count", len(fips)))
	}

	logger.Info("✅ Hetzner discovery completed")
	return info, nil
}

// discoverHetznerServers discovers Hetzner cloud servers
func (i *Inspector) discoverHetznerServers() ([]HetznerServer, error) {
	var servers []HetznerServer

	output, err := i.runCommand("hcloud", "server", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudServers []struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		Created    string `json:"created"`
		ServerType struct {
			Name string `json:"name"`
		} `json:"server_type"`
		Image struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"image"`
		Datacenter struct {
			Name     string `json:"name"`
			Location struct {
				Name string `json:"name"`
			} `json:"location"`
		} `json:"datacenter"`
		PublicNet struct {
			IPv4 struct {
				IP string `json:"ip"`
			} `json:"ipv4"`
			IPv6 struct {
				IP string `json:"ip"`
			} `json:"ipv6"`
		} `json:"public_net"`
		PrivateNet []struct {
			IP string `json:"ip"`
		} `json:"private_net"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudServers); err != nil {
		return nil, fmt.Errorf("failed to parse server JSON: %w", err)
	}

	for _, srv := range hcloudServers {
		server := HetznerServer{
			ID:         srv.ID,
			Name:       srv.Name,
			Status:     srv.Status,
			ServerType: srv.ServerType.Name,
			Image:      srv.Image.Name,
			Datacenter: srv.Datacenter.Name,
			Location:   srv.Datacenter.Location.Name,
			PublicIP:   srv.PublicNet.IPv4.IP,
			Labels:     srv.Labels,
		}

		// Parse created time
		if t, err := time.Parse(time.RFC3339, srv.Created); err == nil {
			server.Created = t
		}

		// Collect private IPs
		for _, pnet := range srv.PrivateNet {
			server.PrivateIPs = append(server.PrivateIPs, pnet.IP)
		}

		servers = append(servers, server)
	}

	return servers, nil
}

// discoverHetznerNetworks discovers Hetzner networks
func (i *Inspector) discoverHetznerNetworks() ([]HetznerNetwork, error) {
	var networks []HetznerNetwork

	output, err := i.runCommand("hcloud", "network", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudNetworks []struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		IPRange string `json:"ip_range"`
		Subnets []struct {
			Type        string `json:"type"`
			IPRange     string `json:"ip_range"`
			NetworkZone string `json:"network_zone"`
		} `json:"subnets"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudNetworks); err != nil {
		return nil, fmt.Errorf("failed to parse network JSON: %w", err)
	}

	for _, net := range hcloudNetworks {
		network := HetznerNetwork{
			ID:      net.ID,
			Name:    net.Name,
			IPRange: net.IPRange,
			Labels:  net.Labels,
		}

		for _, subnet := range net.Subnets {
			network.Subnets = append(network.Subnets, HetznerSubnet{
				Type:        subnet.Type,
				NetworkZone: subnet.NetworkZone,
				IPRange:     subnet.IPRange,
			})
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// discoverHetznerFirewalls discovers Hetzner firewalls
func (i *Inspector) discoverHetznerFirewalls() ([]HetznerFirewall, error) {
	var firewalls []HetznerFirewall

	output, err := i.runCommand("hcloud", "firewall", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudFirewalls []struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Rules []struct {
			Direction      string   `json:"direction"`
			Protocol       string   `json:"protocol"`
			Port           *string  `json:"port"`
			SourceIPs      []string `json:"source_ips"`
			DestinationIPs []string `json:"destination_ips"`
		} `json:"rules"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudFirewalls); err != nil {
		return nil, fmt.Errorf("failed to parse firewall JSON: %w", err)
	}

	for _, fw := range hcloudFirewalls {
		firewall := HetznerFirewall{
			ID:     fw.ID,
			Name:   fw.Name,
			Labels: fw.Labels,
		}

		for _, rule := range fw.Rules {
			fwRule := HetznerFirewallRule{
				Direction:      rule.Direction,
				Protocol:       rule.Protocol,
				SourceIPs:      rule.SourceIPs,
				DestinationIPs: rule.DestinationIPs,
			}
			if rule.Port != nil {
				fwRule.Port = *rule.Port
			}
			firewall.Rules = append(firewall.Rules, fwRule)
		}

		firewalls = append(firewalls, firewall)
	}

	return firewalls, nil
}

// discoverHetznerLoadBalancers discovers Hetzner load balancers
func (i *Inspector) discoverHetznerLoadBalancers() ([]HetznerLoadBalancer, error) {
	var loadBalancers []HetznerLoadBalancer

	output, err := i.runCommand("hcloud", "load-balancer", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudLBs []struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		PublicNet struct {
			IPv4 struct {
				IP string `json:"ip"`
			} `json:"ipv4"`
		} `json:"public_net"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
		LoadBalancerType struct {
			Name string `json:"name"`
		} `json:"load_balancer_type"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudLBs); err != nil {
		return nil, fmt.Errorf("failed to parse load balancer JSON: %w", err)
	}

	for _, lb := range hcloudLBs {
		loadBalancer := HetznerLoadBalancer{
			ID:       lb.ID,
			Name:     lb.Name,
			PublicIP: lb.PublicNet.IPv4.IP,
			Location: lb.Location.Name,
			Type:     lb.LoadBalancerType.Name,
			Labels:   lb.Labels,
		}
		loadBalancers = append(loadBalancers, loadBalancer)
	}

	return loadBalancers, nil
}

// discoverHetznerVolumes discovers Hetzner volumes
func (i *Inspector) discoverHetznerVolumes() ([]HetznerVolume, error) {
	var volumes []HetznerVolume

	output, err := i.runCommand("hcloud", "volume", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudVolumes []struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Size     int    `json:"size"`
		Server   *int   `json:"server"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudVolumes); err != nil {
		return nil, fmt.Errorf("failed to parse volume JSON: %w", err)
	}

	for _, vol := range hcloudVolumes {
		volume := HetznerVolume{
			ID:       vol.ID,
			Name:     vol.Name,
			Size:     vol.Size,
			Server:   vol.Server,
			Location: vol.Location.Name,
			Labels:   vol.Labels,
		}
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// discoverHetznerFloatingIPs discovers Hetzner floating IPs
func (i *Inspector) discoverHetznerFloatingIPs() ([]HetznerFloatingIP, error) {
	var floatingIPs []HetznerFloatingIP

	output, err := i.runCommand("hcloud", "floating-ip", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var hcloudFIPs []struct {
		ID           int    `json:"id"`
		Name         string `json:"name"`
		IP           string `json:"ip"`
		Type         string `json:"type"`
		Server       *int   `json:"server"`
		HomeLocation struct {
			Name string `json:"name"`
		} `json:"home_location"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.Unmarshal([]byte(output), &hcloudFIPs); err != nil {
		return nil, fmt.Errorf("failed to parse floating IP JSON: %w", err)
	}

	for _, fip := range hcloudFIPs {
		floatingIP := HetznerFloatingIP{
			ID:       fip.ID,
			Name:     fip.Name,
			IP:       fip.IP,
			Type:     fip.Type,
			Server:   fip.Server,
			Location: fip.HomeLocation.Name,
			Labels:   fip.Labels,
		}
		floatingIPs = append(floatingIPs, floatingIP)
	}

	return floatingIPs, nil
}
