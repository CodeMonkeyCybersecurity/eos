// Package tailscale provides a wrapper around the Tailscale local API
// for discovering and managing Tailscale network peers.
//
// This package uses the official Tailscale Go SDK instead of shelling out
// to the CLI, providing a more robust and maintainable interface.
package tailscale

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

// Client wraps the Tailscale local API client with Eos-specific functionality
type Client struct {
	client *local.Client
	ctx    context.Context
	logger otelzap.LoggerWithCtx
}

// Peer represents a discovered Tailscale peer with relevant information
type Peer struct {
	ID           string
	HostName     string
	DNSName      string
	TailscaleIPs []netip.Addr
	Online       bool
	OS           string
}

// Status represents the current Tailscale network status
type Status struct {
	Self         *Peer
	Peers        map[string]*Peer
	TailscaleIPs []netip.Addr
}

// NewClient creates a new Tailscale client using the local API
func NewClient(rc *eos_io.RuntimeContext) (*Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create local client - connects to local tailscaled daemon
	localClient := &local.Client{}

	// Verify connection by getting status
	ctx := rc.Ctx
	_, err := localClient.Status(ctx)
	if err != nil {
		return nil, eos_err.NewUserError(
			"Failed to connect to Tailscale daemon. Is Tailscale running?\n" +
				"  Check status: sudo systemctl status tailscaled\n" +
				"  Start service: sudo systemctl start tailscaled\n" +
				"  Install Tailscale: eos create tailscale")
	}

	logger.Debug("Connected to Tailscale local API")

	return &Client{
		client: localClient,
		ctx:    ctx,
		logger: logger,
	}, nil
}

// GetStatus retrieves the current Tailscale network status
func (c *Client) GetStatus() (*Status, error) {
	c.logger.Debug("Fetching Tailscale status from local API")

	status, err := c.client.Status(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	// Convert to our Status type
	result := &Status{
		Peers:        make(map[string]*Peer),
		TailscaleIPs: status.TailscaleIPs,
	}

	// Convert self
	if status.Self != nil {
		result.Self = convertPeerStatus(status.Self)
	}

	// Convert peers
	for _, peer := range status.Peer {
		converted := convertPeerStatus(peer)
		result.Peers[converted.ID] = converted
	}

	c.logger.Debug("Tailscale status retrieved",
		zap.Int("peer_count", len(result.Peers)),
		zap.String("self_hostname", result.Self.HostName))

	return result, nil
}

// FindPeerByHostname finds a peer by hostname (flexible matching)
// Matches against both HostName and DNSName (e.g., "vhost7" or "vhost7.taild785bf.ts.net")
func (c *Client) FindPeerByHostname(hostname string) (*Peer, error) {
	status, err := c.GetStatus()
	if err != nil {
		return nil, err
	}

	// Try exact match first (case-insensitive)
	for _, peer := range status.Peers {
		if strings.EqualFold(peer.HostName, hostname) {
			c.logger.Debug("Found peer by exact hostname match",
				zap.String("search", hostname),
				zap.String("found", peer.HostName))
			return peer, nil
		}
	}

	// Try DNS name prefix match (e.g., "vhost7" matches "vhost7.taild785bf.ts.net")
	searchPrefix := strings.ToLower(hostname) + "."
	for _, peer := range status.Peers {
		if strings.HasPrefix(strings.ToLower(peer.DNSName), searchPrefix) {
			c.logger.Debug("Found peer by DNS name prefix match",
				zap.String("search", hostname),
				zap.String("found_hostname", peer.HostName),
				zap.String("found_dns", peer.DNSName))
			return peer, nil
		}
	}

	// No match - provide helpful error with available peers
	var availableHosts []string
	for _, peer := range status.Peers {
		availableHosts = append(availableHosts, peer.HostName)
	}

	return nil, eos_err.NewUserError(
		"Node '%s' not found on Tailscale network.\n"+
			"Available nodes: %s\n"+
			"Tip: Use exact hostname or DNS name",
		hostname, strings.Join(availableHosts, ", "))
}

// GetPeerIP returns the primary IPv4 address for a peer
func (c *Client) GetPeerIP(peer *Peer) (string, error) {
	for _, ip := range peer.TailscaleIPs {
		if ip.Is4() {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("peer '%s' has no IPv4 address", peer.HostName)
}

// GetSelfIP returns this node's primary Tailscale IPv4 address
func (c *Client) GetSelfIP() (string, error) {
	status, err := c.GetStatus()
	if err != nil {
		return "", err
	}

	if status.Self == nil {
		return "", fmt.Errorf("self peer information not available")
	}

	return c.GetPeerIP(status.Self)
}

// VerifyPeerOnline checks if a peer is online and reachable
func (c *Client) VerifyPeerOnline(peer *Peer) error {
	if !peer.Online {
		return eos_err.NewUserError(
			"Node '%s' is offline on Tailscale network.\n"+
				"Check status: tailscale status\n"+
				"The node may be powered off or disconnected.",
			peer.HostName)
	}
	return nil
}

// ListPeers returns all peers with optional filtering
func (c *Client) ListPeers(onlineOnly bool) ([]*Peer, error) {
	status, err := c.GetStatus()
	if err != nil {
		return nil, err
	}

	var peers []*Peer
	for _, peer := range status.Peers {
		if onlineOnly && !peer.Online {
			continue
		}
		peers = append(peers, peer)
	}

	c.logger.Debug("Listed Tailscale peers",
		zap.Int("total_count", len(status.Peers)),
		zap.Int("filtered_count", len(peers)),
		zap.Bool("online_only", onlineOnly))

	return peers, nil
}

// convertPeerStatus converts ipnstate.PeerStatus to our Peer type
func convertPeerStatus(ps *ipnstate.PeerStatus) *Peer {
	peer := &Peer{
		ID:           string(ps.ID), // StableNodeID is a string type alias
		HostName:     ps.HostName,
		DNSName:      ps.DNSName,
		TailscaleIPs: ps.TailscaleIPs,
		Online:       ps.Online,
		OS:           ps.OS,
	}
	return peer
}
