package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Node represents a Ceph node with its hostname and IP.
type Node struct {
	Hostname string
	IP       string
}

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

// checkExecutable ensures that the given executable is available in PATH.
func checkExecutable(executable string) error {
	_, err := exec.LookPath(executable)
	if err != nil {
		return fmt.Errorf("executable %q not found in PATH", executable)
	}
	return nil
}

// getUserNodes prompts the user to enter the total number of nodes and their IP addresses.
// It returns a slice of Node structures.
func getUserNodes() ([]Node, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the total number of nodes in the cluster (minimum 1): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read number of nodes: %v", err)
	}
	input = strings.TrimSpace(input)
	count, err := strconv.Atoi(input)
	if err != nil || count < 1 {
		return nil, fmt.Errorf("invalid number of nodes: %s", input)
	}

	nodes := make([]Node, count)
	for i := 0; i < count; i++ {
		defaultHostname := fmt.Sprintf("ceph-node%d", i+1)
		fmt.Printf("Enter IP address for %s: ", defaultHostname)
		ip, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read IP for %s: %v", defaultHostname, err)
		}
		ip = strings.TrimSpace(ip)
		nodes[i] = Node{Hostname: defaultHostname, IP: ip}
	}
	return nodes, nil
}

func main() {
	log.Println("Starting Ceph deployment automation using cephadm...")


	// Check if cephadm is available in PATH.
	if err := checkExecutable("cephadm"); err != nil {
	    log.Printf("cephadm not found in PATH. Attempting to install cephadm via apt...");
	    // Update apt package list.
	    aptUpdateCmd := exec.Command("sudo", "apt", "update")
	    if output, err := aptUpdateCmd.CombinedOutput(); err != nil {
	        log.Fatalf("Failed to update apt: %v, output: %s", err, string(output))
	    }
	    // Install cephadm via apt.
	    aptInstallCmd := exec.Command("sudo", "apt", "install", "-y", "cephadm")
	    if output, err := aptInstallCmd.CombinedOutput(); err != nil {
	        log.Fatalf("Failed to install cephadm via apt: %v, output: %s", err, string(output))
	    }
	    log.Println("cephadm successfully installed via apt.");
	    // Re-check if cephadm is now available.
	    if err := checkExecutable("cephadm"); err != nil {
	        log.Fatalf("Pre-check failed even after apt installation: %v", err)
	    }
	}
	
	// Check if cephadm is available in PATH.
	if err := checkExecutable("cephadm"); err != nil {
		log.Fatalf("Pre-check failed: %v", err)
	}

	// Get nodes from user input.
	userNodes, err := getUserNodes()
	if err != nil {
		log.Fatalf("Error obtaining nodes: %v", err)
	}
	// The first node will be the primary (bootstrapped) node.
	primary := userNodes[0]
	// Additional nodes are any remaining nodes.
	additionalNodes := userNodes[1:]

	// 1. Bootstrap the cluster on the primary node.
	bootstrapCmd := []string{"cephadm", "bootstrap", "--mon-ip", primary.IP}
	log.Printf("Bootstrapping Ceph cluster on primary node %s (%s)...", primary.Hostname, primary.IP)
	if err := runCommand(bootstrapCmd[0], bootstrapCmd[1:]...); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}

	// 2. Add additional nodes to the cluster.
	for _, node := range additionalNodes {
		// Copy the cephadm public key to the node.
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

	// 3. Deploy additional MONs (one on each node).
	allNodes := make([]string, len(userNodes))
	for i, node := range userNodes {
		allNodes[i] = node.Hostname
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
	if len(userNodes) >= 2 {
		cephfsCmd := []string{"ceph", "fs", "volume", "create", "myfs", "--placement", fmt.Sprintf("%s,%s", primary.Hostname, userNodes[1].Hostname)}
		log.Println("Deploying CephFS (MDS) with volume name 'myfs'...")
		if err := runCommand(cephfsCmd[0], cephfsCmd[1:]...); err != nil {
			log.Printf("Warning: Failed to deploy CephFS (MDS): %v", err)
		}
	} else {
		log.Println("Skipping CephFS deployment (need at least 2 nodes).")
	}

	// (Optional) 7. Deploy RADOS Gateway (RGW) if you want object storage.
	if len(userNodes) >= 2 {
		rgwCmd := []string{"ceph", "orch", "apply", "rgw", "myrgw", "--placement", userNodes[1].Hostname}
		log.Printf("Deploying RADOS Gateway (RGW) on %s...", userNodes[1].Hostname)
		if err := runCommand(rgwCmd[0], rgwCmd[1:]...); err != nil {
			log.Printf("Warning: Failed to deploy RGW: %v", err)
		}
	} else {
		log.Println("Skipping RGW deployment (need at least 2 nodes).")
	}

	log.Println("Ceph deployment automation complete!")
}
