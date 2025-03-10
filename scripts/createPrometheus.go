package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Running command: %s %v", name, args)
	return cmd.Run()
}

func runShellCommand(command string) (string, error) {
	log.Printf("Running shell command: %s", command)
	cmd := exec.Command("sh", "-c", command)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	output := outBuf.String() + errBuf.String()
	if err != nil {
		log.Printf("Shell command error: %s", output)
		return output, err
	}
	return output, nil
}

func main() {
	// 1. Create dedicated prometheus user and directories
	if err := runCommand("useradd", "--no-create-home", "--shell", "/bin/false", "prometheus"); err != nil {
		// useradd returns non-zero if the user already exists. Log a warning.
		log.Printf("Warning: Could not add user 'prometheus': %v", err)
	}

	dirs := []string{"/etc/prometheus", "/var/lib/prometheus"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating directory %s: %v", dir, err)
		}
		// Set directory ownership to prometheus user
		if err := runCommand("chown", "prometheus:prometheus", dir); err != nil {
			log.Fatalf("Error changing ownership of %s: %v", dir, err)
		}
	}

	// 2. Download and extract Prometheus using latest release from GitHub
	promDir := "/tmp/prometheus"
	// Create /tmp/prometheus directory
	if err := os.MkdirAll(promDir, 0755); err != nil {
		log.Fatalf("Error creating directory %s: %v", promDir, err)
	}

	// Build and run the shell command to download the latest linux-amd64 tarball
	downloadCmd := `curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest \
	  | grep browser_download_url \
	  | grep linux-amd64 \
	  | cut -d '"' -f 4 \
	  | wget -P /tmp/prometheus -qi -`
	log.Printf("Downloading latest Prometheus release...")
	output, err := runShellCommand(downloadCmd)
	if err != nil {
		log.Fatalf("Error downloading Prometheus: %v. Output: %s", err, output)
	}

	// Locate the downloaded tarball in /tmp/prometheus
	tarFiles, err := filepath.Glob(filepath.Join(promDir, "prometheus*.tar.gz"))
	if err != nil || len(tarFiles) == 0 {
		log.Fatalf("No Prometheus tar.gz file found in %s", promDir)
	}
	tarball := tarFiles[0]
	log.Printf("Found tarball: %s", tarball)

	// Extract the tarball into the same /tmp/prometheus directory
	if err := runCommand("tar", "-xvf", tarball, "-C", promDir); err != nil {
		log.Fatalf("Error extracting tarball: %v", err)
	}

	// Locate the extracted directory (assumes name starts with "prometheus-")
	extractedDirs, err := filepath.Glob(filepath.Join(promDir, "prometheus-*"))
	if err != nil || len(extractedDirs) == 0 {
		log.Fatalf("No extracted Prometheus directory found in %s", promDir)
	}
	extractDir := extractedDirs[0]
	log.Printf("Using extracted directory: %s", extractDir)

	// 3. Install Prometheus binaries and configuration files
	// Copy binaries (prometheus and promtool) to /usr/local/bin
	binaries := []string{"prometheus", "promtool"}
	for _, bin := range binaries {
		src := filepath.Join(extractDir, bin)
		dst := filepath.Join("/usr/local/bin", bin)
		if err := runCommand("cp", src, dst); err != nil {
			log.Fatalf("Error copying binary %s: %v", bin, err)
		}
		if err := runCommand("chown", "prometheus:prometheus", dst); err != nil {
			log.Fatalf("Error setting ownership for %s: %v", dst, err)
		}
	}

	// Copy configuration file
	srcConfig := filepath.Join(extractDir, "prometheus.yml")
	dstConfig := "/etc/prometheus/prometheus.yml"
	if err := runCommand("cp", srcConfig, dstConfig); err != nil {
		log.Fatalf("Error copying configuration file: %v", err)
	}

	// Set ownership for configuration directories
	if err := runCommand("chown", "-R", "prometheus:prometheus", "/etc/prometheus"); err != nil {
		log.Fatalf("Error setting ownership for /etc/prometheus: %v", err)
	}
	if err := runCommand("chown", "-R", "prometheus:prometheus", "/var/lib/prometheus"); err != nil {
		log.Fatalf("Error setting ownership for /var/lib/prometheus: %v", err)
	}

	// 4. Create systemd service file for Prometheus (without consoles options)
	serviceContent := `[Unit]
Description=Prometheus Monitoring
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/
  --web.listen-address=0.0.0.0:9091

[Install]
WantedBy=multi-user.target
`
	servicePath := "/etc/systemd/system/prometheus.service"
	if err := ioutil.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		log.Fatalf("Error writing systemd service file: %v", err)
	}

	// 5. Reload systemd daemon, enable, and start Prometheus service
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		log.Fatalf("Error reloading systemd: %v", err)
	}

	if err := runCommand("systemctl", "enable", "prometheus"); err != nil {
		log.Fatalf("Error enabling Prometheus service: %v", err)
	}

	if err := runCommand("systemctl", "start", "prometheus"); err != nil {
		log.Fatalf("Error starting Prometheus service: %v", err)
	}

	log.Println("Prometheus installation and service setup complete!")
}
