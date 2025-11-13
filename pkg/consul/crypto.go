// pkg/consul/crypto.go
package consul

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateGossipKey generates a new gossip encryption key for Consul
func GenerateGossipKey() (string, error) {
	// Consul requires a 32-byte (256-bit) key
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Encode to base64 as required by Consul
	encoded := base64.StdEncoding.EncodeToString(key)

	return encoded, nil
}
