package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Node represents a Ceph node with its hostname and IP.
type Node struct {
	Hostname string
	IP       string
}

var (
	// primary is the node that will be bootstrapped.
	primary = Node{Hostname: "ceph-node1", IP: "10.0.0.101"}

	// additional nodes to add to the cluster.
	nodes = []Node{
		{Hostname: "ceph-node2", IP: "10.0.0.102"},
		{Hostname: "ceph-node3", IP: "10.0.0.103"},
	}
)

// runCommand executes a command with given arguments and prints its output.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	log.Printf("Running: %s %s\nOutput:\n%s", name, strings.Join(args, " "), output)
	if err != nil {
		return fmt.Errorf("error running %s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}

func main() {
	log.Println("Starting Ceph deployment automation using cephadm...")

	// 1. Bootstrap the cluster on the primary node.
	// (This command must be run on the primary node.)
	// It uses the primary node's public IP.
	bootstrapCmd := []string{"cephadm", "bootstrap", "--mon-ip", primary.IP}
	log.Printf("Bootstrapping Ceph cluster on primary node %s (%s)...", primary.Hostname, primary.IP)
	if err := runCommand(bootstrapCmd[0], bootstrapCmd[1:]...); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}

	// 2. Add additional nodes to the cluster.
	for _, node := range nodes {
		// Copy the cephadm public key to the node.
		// Note: This assumes key-based auth is in place; adjust if necessary.
		copyIDCmd := []string{"ssh-copy-id", "-f", "-i", "/etc/ceph/ceph.pub", fmt.Sprintf("root@%s", node.IP)}
		log.Printf("Copying cephadm SSH key to %s (%s)...", node.Hostname, node.IP)
		if err := runCommand(copyIDCmd[0], copyIDCmd[1:]...); err != nil {
			log.Printf("Warning: ssh-copy-id for %s failed: %v", node.Hostname, err)
		}

		// Add the node to the Ceph cluster.
		addHostCmd := []string{"ceph", "orch", "host", "add", node.Hostname, node.IP}
		log.Printf("Adding node %s (%s) to the Ceph cluster...", node.Hostname, node.IP)
		if err := runCommand(addHostCmd[0], addHostCmd[1:]...); err != nil {
			log.Fatalf("Failed to add node %s: %v", node.Hostname, err)
		}
	}

	// 3. Deploy additional MONs (we want one on each node).
	// Build a comma-separated list of hostnames including the primary.
	allNodes := []string{primary.Hostname}
	for _, node := range nodes {
		allNodes = append(allNodes, node.Hostname)
	}
	placement := strings.Join(allNodes, ",")
	applyMonCmd := []string{"ceph", "orch", "apply", "mon", "--placement", placement}
	log.Printf("Deploying monitor daemons on hosts: %s...", placement)
	if err := runCommand(applyMonCmd[0], applyMonCmd[1:]...); err != nil {
		log.Fatalf("Failed to deploy MONs: %v", err)
	}

	// 4. Deploy additional Manager daemons (set total count to 2).
	applyMgrCmd := []string{"ceph", "orch", "apply", "mgr", "2"}
	log.Println("Deploying manager daemons (2 total)...")
	if err := runCommand(applyMgrCmd[0], applyMgrCmd[1:]...); err != nil {
		log.Fatalf("Failed to deploy MGRs: %v", err)
	}

	// 5. Deploy OSDs on all available devices on all hosts.
	applyOSDCmd := []string{"ceph", "orch", "apply", "osd", "--all-available-devices"}
	log.Println("Deploying OSDs on all available devices on all hosts...")
	if err := runCommand(applyOSDCmd[0], applyOSDCmd[1:]...); err != nil {
		log.Fatalf("Failed to deploy OSDs: %v", err)
	}

	// (Optional) 6. Deploy CephFS (MDS) if you want to use the filesystem.
	// This example creates a CephFS volume named "myfs" on two hosts.
	// Note: Ceph will automatically create the underlying pools.
	cephfsCmd := []string{"ceph", "fs", "volume", "create", "myfs", "--placement", fmt.Sprintf("%s,%s", primary.Hostname, nodes[0].Hostname)}
	log.Println("Deploying CephFS (MDS) with volume name 'myfs'...")
	if err := runCommand(cephfsCmd[0], cephfsCmd[1:]...); err != nil {
		log.Printf("Warning: Failed to deploy CephFS (MDS): %v", err)
	}

	// (Optional) 7. Deploy RADOS Gateway (RGW) if you want object storage.
	// This example deploys an RGW instance on the second node.
	rgwCmd := []string{"ceph", "orch", "apply", "rgw", "myrgw", "--placement", nodes[0].Hostname}
	log.Println("Deploying RADOS Gateway (RGW) on", nodes[0].Hostname)
	if err := runCommand(rgwCmd[0], rgwCmd[1:]...); err != nil {
		log.Printf("Warning: Failed to deploy RGW: %v", err)
	}

	log.Println("Ceph deployment automation complete!")
}
