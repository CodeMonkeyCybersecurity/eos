// pkg/docker/network.go

package docker

import (
	"eos/pkg/config"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

//
//---------------------------- NETWORK FUNCTIONS ---------------------------- //
//

// EnsureArachneNetwork checks if the Docker network exists, and creates it if not.
func EnsureArachneNetwork() error {
	networkName := config.DockerNetworkName
	ipv4 := config.DockerIPv4Subnet
	ipv6 := config.DockerIPv6Subnet

	if err := CheckIfDockerInstalled(); err != nil {
		return fmt.Errorf("Docker is not installed or not in PATH: %w", err)
	}

	if networkName == "" || ipv4 == "" || ipv6 == "" {
		return fmt.Errorf("one or more required config values are missing: networkName=%q, ipv4=%q, ipv6=%q", networkName, ipv4, ipv6)
	}

	// Check if the network exists
	cmd := exec.Command("docker", "network", "inspect", networkName)
	if err := cmd.Run(); err == nil {
		log.Info("Docker network already exists", zap.String("network", networkName))
		return nil
	}

	// Create the network with IPv4 and IPv6 subnets
	createCmd := exec.Command("docker", "network", "create",
		"--driver", "bridge",
		"--subnet", ipv4,
		"--ipv6",
		"--subnet", ipv6,
		networkName,
	)

	output, err := createCmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to create Docker network", zap.String("network", networkName), zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("failed to create network %s: %v, output: %s", networkName, err, output)
	}

	log.Info("Created Docker network", zap.String("network", networkName))
	return nil
}
