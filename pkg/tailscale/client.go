// Package tailscale provides a wrapper around the Tailscale local API
// for discovering and managing Tailscale network peers.
//
// TEMPORARY STUB (Go 1.24 compatibility):
// The full implementation requires tailscale.com v1.88+ which needs Go 1.25.3+
// This stub allows the project to build with Go 1.24.7
// Original implementation backed up to client.go.go125-original
// Will be restored when upgrading to Go 1.25+
package tailscale

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Client wraps the Tailscale local API client with Eos-specific functionality
type Client struct {
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
	return nil, eos_err.NewUserError(
		"Tailscale client not available (Go 1.24 compatibility stub).\n" +
			"This feature requires Go 1.25+ to use the official Tailscale SDK.\n" +
			"Upgrade Go to 1.25+ to restore Tailscale integration functionality.")
}

// GetStatus retrieves the current Tailscale network status
func (c *Client) GetStatus() (*Status, error) {
	return nil, fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}

// FindPeerByHostname finds a peer by hostname (flexible matching)
func (c *Client) FindPeerByHostname(hostname string) (*Peer, error) {
	return nil, fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}

// GetPeerIP returns the primary IPv4 address for a peer
func (c *Client) GetPeerIP(peer *Peer) (string, error) {
	return "", fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}

// GetSelfIP returns this node's primary Tailscale IPv4 address
func (c *Client) GetSelfIP() (string, error) {
	return "", fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}

// VerifyPeerOnline checks if a peer is online and reachable
func (c *Client) VerifyPeerOnline(peer *Peer) error {
	return fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}

// ListPeers returns all peers with optional filtering
func (c *Client) ListPeers(onlineOnly bool) ([]*Peer, error) {
	return nil, fmt.Errorf("tailscale client not available (Go 1.24 compatibility stub)")
}
