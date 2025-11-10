package moni

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GenerateSSLCerts generates SSL certificates if missing
// ASSESS: Check if certificates exist and are valid
// INTERVENE: Generate new certificates if needed
// EVALUATE: Verify certificates were created successfully
func GenerateSSLCerts(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 1: SSL Certificate Generation")

	certFile := filepath.Join(MoniCertsDir, "server.crt")
	keyFile := filepath.Join(MoniCertsDir, "server.key")

	// ASSESS: Check if certificates exist and are valid
	if fileExists(certFile) && fileExists(keyFile) {
		// Check if still valid (not expired)
		ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
		defer cancel()

		output, err := execute.Run(ctx, execute.Options{
			Command: "openssl",
			Args:    []string{"x509", "-in", certFile, "-noout", "-checkend", "0"},
			Capture: true,
		})

		if err == nil {
			logger.Info("SSL certificates already exist and are valid")
			return nil
		}

		logger.Warn("Existing certificates are invalid or expired, regenerating",
			zap.String("reason", output))
	}

	// INTERVENE: Generate new certificates
	logger.Info("Generating SSL certificates...")

	// Create certs directory
	if err := os.MkdirAll(MoniCertsDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	// Generate self-signed certificate
	output, err := execute.Run(ctx, execute.Options{
		Command: "openssl",
		Args: []string{
			"req", "-new", "-x509", "-days", "365",
			"-nodes", "-text",
			"-out", certFile,
			"-keyout", keyFile,
			"-subj", "/CN=postgres",
		},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to generate SSL certificates: %s: %w", output, err)
	}

	// Set initial permissions (will be fixed in next phase)
	if err := os.Chmod(certFile, CertCrtPerms); err != nil {
		return fmt.Errorf("failed to set certificate permissions: %w", err)
	}

	if err := os.Chmod(keyFile, TempKeyPerms); err != nil {
		return fmt.Errorf("failed to set key permissions: %w", err)
	}

	// EVALUATE: Verify certificates were created
	if !fileExists(certFile) || !fileExists(keyFile) {
		return fmt.Errorf("certificates were not created successfully")
	}

	logger.Info("SSL certificates generated successfully",
		zap.String("certificate", certFile),
		zap.String("private_key", keyFile))

	return nil
}

// DetectPostgresImages detects PostgreSQL images from docker-compose.yml
func DetectPostgresImages(rc *eos_io.RuntimeContext) ([]PostgresImage, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Detecting PostgreSQL images from docker-compose.yml")

	if !fileExists(MoniDockerCompose) {
		logger.Warn("docker-compose.yml not found", zap.String("path", MoniDockerCompose))
		return nil, nil
	}

	// Read and parse docker-compose.yml
	data, err := os.ReadFile(MoniDockerCompose)
	if err != nil {
		return nil, fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}

	if err := yaml.Unmarshal(data, &compose); err != nil {
		logger.Warn("Failed to parse docker-compose.yml, using grep fallback", zap.Error(err))
		return grepFallbackDetection(rc)
	}

	var images []PostgresImage

	for serviceName, service := range compose.Services {
		image := service.Image
		imageLower := strings.ToLower(image)

		isPostgres := strings.Contains(imageLower, "postgres") ||
			strings.Contains(imageLower, "pgvector") ||
			strings.Contains(imageLower, "postgresql")

		if !isPostgres {
			continue
		}

		// Determine expected UID based on image type
		expectedUID := StandardUID
		if strings.Contains(imageLower, "alpine") {
			expectedUID = CertOwnerGID // 70 for Alpine
		}

		img := PostgresImage{
			Service:     serviceName,
			Image:       image,
			ExpectedUID: expectedUID,
		}

		// Try to get actual UID from running container
		containerName := fmt.Sprintf("bionicgpt-%s", serviceName)
		if actualUID := checkContainerPostgresUID(rc, containerName); actualUID > 0 {
			img.ActualUID = actualUID
			if actualUID != expectedUID {
				logger.Warn("UID mismatch detected",
					zap.String("service", serviceName),
					zap.Int("expected", expectedUID),
					zap.Int("actual", actualUID))
			}
		}

		images = append(images, img)
		logger.Debug("Found PostgreSQL service",
			zap.String("service", serviceName),
			zap.String("image", image),
			zap.Int("expected_uid", expectedUID))
	}

	return images, nil
}

// checkContainerPostgresUID checks the UID of postgres user inside a running container
func checkContainerPostgresUID(rc *eos_io.RuntimeContext, containerName string) int {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", containerName, "id", "-u", "postgres"},
		Capture: true,
	})

	if err != nil {
		return 0
	}

	uid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return 0
	}

	return uid
}

// grepFallbackDetection uses grep to find postgres references
func grepFallbackDetection(rc *eos_io.RuntimeContext) ([]PostgresImage, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Using grep fallback for postgres detection")

	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "grep",
		Args:    []string{"-i", "postgres", MoniDockerCompose},
		Capture: true,
	})

	if err != nil {
		return nil, nil
	}

	if output != "" {
		logger.Debug("Found postgres references (fallback detection)")
	}

	return nil, nil
}

// TestCertReadability tests if postgres user can read the certificate
// SHIFT-LEFT v2: Test before deploying
func TestCertReadability(rc *eos_io.RuntimeContext, image string, uid int, certPath string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Testing certificate readability",
		zap.String("image", image),
		zap.Int("uid", uid),
		zap.String("cert", certPath))

	if certPath == "" {
		certPath = filepath.Join(MoniCertsDir, "server.key")
	}

	if !fileExists(certPath) {
		logger.Error("Certificate not found", zap.String("path", certPath))
		return false
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	absPath, err := filepath.Abs(certPath)
	if err != nil {
		logger.Error("Failed to get absolute path", zap.Error(err))
		return false
	}

	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm",
			"--user", "postgres",
			"-v", fmt.Sprintf("%s:/test.key:ro", absPath),
			image,
			"cat", "/test.key",
		},
		Capture: true,
	})

	success := err == nil
	if success {
		logger.Debug("Certificate is readable", zap.String("image", image))
	} else {
		logger.Warn("Certificate is NOT readable", zap.String("image", image))
	}

	return success
}

// DetermineCertStrategy determines optimal certificate strategy
func DetermineCertStrategy(rc *eos_io.RuntimeContext, images []PostgresImage) string {
	logger := otelzap.Ctx(rc.Ctx)

	if len(images) == 0 {
		logger.Info("No PostgreSQL images detected - using default strategy")
		return StrategySingleUID70
	}

	var alpineImages, standardImages []PostgresImage
	for _, img := range images {
		if strings.Contains(strings.ToLower(img.Image), "alpine") {
			alpineImages = append(alpineImages, img)
		} else {
			standardImages = append(standardImages, img)
		}
	}

	logger.Info("Determining optimal certificate strategy",
		zap.Int("alpine_containers", len(alpineImages)),
		zap.Int("standard_containers", len(standardImages)))

	for _, img := range alpineImages {
		logger.Info("Alpine container detected",
			zap.String("service", img.Service),
			zap.String("image", img.Image))
	}
	for _, img := range standardImages {
		logger.Info("Standard container detected",
			zap.String("service", img.Service),
			zap.String("image", img.Image))
	}

	// If only one type, use simple strategy
	if len(standardImages) == 0 {
		logger.Info("Strategy: Single cert with UID 70 (Alpine only)")
		return StrategySingleUID70
	}

	if len(alpineImages) == 0 {
		logger.Info("Strategy: Single cert with UID 999 (standard only)")
		return StrategySingleUID70
	}

	// Mixed containers - use separate certs
	logger.Info("Strategy: Separate certificate directories (mixed)")
	return StrategySeparateCerts
}

// FixCertPermissionsImmediate fixes certificate permissions for Alpine containers
func FixCertPermissionsImmediate(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Fixing certificate permissions for Alpine PostgreSQL containers")

	keyFile := filepath.Join(MoniCertsDir, "server.key")
	certFile := filepath.Join(MoniCertsDir, "server.crt")

	images, err := DetectPostgresImages(rc)
	if err != nil {
		return fmt.Errorf("failed to detect postgres images: %w", err)
	}

	var alpineImages, standardImages []PostgresImage
	for _, img := range images {
		if strings.Contains(strings.ToLower(img.Image), "alpine") {
			alpineImages = append(alpineImages, img)
		} else {
			standardImages = append(standardImages, img)
		}
	}

	if len(alpineImages) > 0 {
		logger.Info("Setting permissions for Alpine containers",
			zap.Int("owner_uid", CertOwnerUID),
			zap.Int("owner_gid", CertOwnerGID),
			zap.String("key_perms", fmt.Sprintf("%o", CertKeyPerms)))

		// Set owner:group to 0:70 (root:postgres)
		if err := runSudo(rc, "chown", "0:70", keyFile); err != nil {
			return fmt.Errorf("failed to chown key file: %w", err)
		}

		if err := runSudo(rc, "chown", "0:0", certFile); err != nil {
			return fmt.Errorf("failed to chown cert file: %w", err)
		}

		// Set permissions
		if err := runSudo(rc, "chmod", "640", keyFile); err != nil {
			return fmt.Errorf("failed to chmod key file: %w", err)
		}

		if err := runSudo(rc, "chmod", "644", certFile); err != nil {
			return fmt.Errorf("failed to chmod cert file: %w", err)
		}

		logger.Info("Permissions updated successfully")

		// Test with Alpine container
		if len(alpineImages) > 0 {
			testImage := alpineImages[0].Image
			if TestCertReadability(rc, testImage, CertOwnerGID, "") {
				logger.Info("Alpine (UID 70) can read the key")
			} else {
				return fmt.Errorf("alpine (UID 70) CANNOT read the key")
			}
		}

		return nil
	}

	// Only standard containers
	logger.Info("Only standard PostgreSQL containers detected, using 0:999 640 permissions")

	if err := runSudo(rc, "chown", "0:999", keyFile); err != nil {
		return fmt.Errorf("failed to chown key file: %w", err)
	}

	if err := runSudo(rc, "chown", "0:0", certFile); err != nil {
		return fmt.Errorf("failed to chown cert file: %w", err)
	}

	if err := runSudo(rc, "chmod", "640", keyFile); err != nil {
		return fmt.Errorf("failed to chmod key file: %w", err)
	}

	if err := runSudo(rc, "chmod", "644", certFile); err != nil {
		return fmt.Errorf("failed to chmod cert file: %w", err)
	}

	logger.Info("Permissions updated successfully")
	return nil
}

// ValidateAndFixCertPermissions validates and fixes SSL certificate permissions
func ValidateAndFixCertPermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 2: Certificate Permission Validation & Fix")

	keyFile := filepath.Join(MoniCertsDir, "server.key")
	if !fileExists(keyFile) {
		return fmt.Errorf("certificate files don't exist")
	}

	// Detect PostgreSQL images and determine strategy
	images, err := DetectPostgresImages(rc)
	if err != nil {
		return fmt.Errorf("failed to detect postgres images: %w", err)
	}

	strategy := DetermineCertStrategy(rc, images)

	// Implement the strategy
	if strategy == StrategySeparateCerts {
		logger.Info("Implementing separate certificate directories strategy")
		if err := createSeparateCertDirs(rc, images); err != nil {
			return fmt.Errorf("failed to create separate certificate directories: %w", err)
		}
	} else {
		logger.Info("Implementing single certificate strategy")
		if err := FixCertPermissionsImmediate(rc); err != nil {
			return fmt.Errorf("failed to fix certificate permissions: %w", err)
		}
	}

	logger.Info("Certificate permissions validated and working",
		zap.String("strategy", strategy))

	return nil
}

// createSeparateCertDirs creates separate certificate directories for mixed containers
func createSeparateCertDirs(rc *eos_io.RuntimeContext, images []PostgresImage) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating separate certificate directories")

	sourceKey := filepath.Join(MoniCertsDir, "server.key")
	sourceCrt := filepath.Join(MoniCertsDir, "server.crt")

	if !fileExists(sourceKey) || !fileExists(sourceCrt) {
		return fmt.Errorf("source certificates not found in ./certs/")
	}

	// Create directories
	if err := os.MkdirAll(MoniCertsAlpineDir, 0755); err != nil {
		return fmt.Errorf("failed to create alpine certs dir: %w", err)
	}

	if err := os.MkdirAll(MoniCertsStandardDir, 0755); err != nil {
		return fmt.Errorf("failed to create standard certs dir: %w", err)
	}

	logger.Info("Certificate directories created",
		zap.String("alpine", MoniCertsAlpineDir),
		zap.String("standard", MoniCertsStandardDir))

	// Copy certificates
	alpineKey := filepath.Join(MoniCertsAlpineDir, "server.key")
	alpineCrt := filepath.Join(MoniCertsAlpineDir, "server.crt")
	standardKey := filepath.Join(MoniCertsStandardDir, "server.key")
	standardCrt := filepath.Join(MoniCertsStandardDir, "server.crt")

	for _, pair := range []struct{ src, dst string }{
		{sourceKey, alpineKey},
		{sourceCrt, alpineCrt},
		{sourceKey, standardKey},
		{sourceCrt, standardCrt},
	} {
		if err := runSudo(rc, "cp", pair.src, pair.dst); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", pair.src, pair.dst, err)
		}
	}

	logger.Info("Certificates copied")

	// Set permissions for Alpine (UID 70)
	logger.Info("Setting permissions for Alpine containers (UID 70)")
	if err := runSudo(rc, "chown", "0:70", alpineKey); err != nil {
		return err
	}
	if err := runSudo(rc, "chmod", "640", alpineKey); err != nil {
		return err
	}
	if err := runSudo(rc, "chown", "0:0", alpineCrt); err != nil {
		return err
	}
	if err := runSudo(rc, "chmod", "644", alpineCrt); err != nil {
		return err
	}

	// Set permissions for Standard (UID 999)
	logger.Info("Setting permissions for standard containers (UID 999)")
	if err := runSudo(rc, "chown", "999:999", standardKey); err != nil {
		return err
	}
	if err := runSudo(rc, "chmod", "600", standardKey); err != nil {
		return err
	}
	if err := runSudo(rc, "chown", "0:0", standardCrt); err != nil {
		return err
	}
	if err := runSudo(rc, "chmod", "644", standardCrt); err != nil {
		return err
	}

	// Test readability
	logger.Info("Testing readability")

	var alpineImages, standardImages []PostgresImage
	for _, img := range images {
		if strings.Contains(strings.ToLower(img.Image), "alpine") {
			alpineImages = append(alpineImages, img)
		} else {
			standardImages = append(standardImages, img)
		}
	}

	allReadable := true

	if len(alpineImages) > 0 {
		testImage := alpineImages[0].Image
		if TestCertReadability(rc, testImage, CertOwnerGID, alpineKey) {
			logger.Info("Alpine can read certificate", zap.String("cert", alpineKey))
		} else {
			logger.Error("Alpine CANNOT read certificate", zap.String("cert", alpineKey))
			allReadable = false
		}
	}

	if len(standardImages) > 0 {
		testImage := standardImages[0].Image
		if TestCertReadability(rc, testImage, StandardUID, standardKey) {
			logger.Info("Standard can read certificate", zap.String("cert", standardKey))
		} else {
			logger.Error("Standard CANNOT read certificate", zap.String("cert", standardKey))
			allReadable = false
		}
	}

	if !allReadable {
		return fmt.Errorf("certificate readability test failed")
	}

	return nil
}

// runSudo runs a command with sudo
func runSudo(rc *eos_io.RuntimeContext, command string, args ...string) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	fullArgs := append([]string{command}, args...)
	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    fullArgs,
		Capture: true,
	})

	return err
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
