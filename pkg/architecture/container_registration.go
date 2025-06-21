// Package architecture provides container registration for all domain services
package architecture

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	cryptoInfra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/crypto"
	fileopsInfra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/fileops"
	"go.uber.org/zap"
)

// RegisterFileOperationsServices registers all file operations related services
func RegisterFileOperationsServices(builder *ContainerBuilder) *ContainerBuilder {
	// Register infrastructure implementations
	builder.WithSingleton("fileops:file_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		return fileopsInfra.NewFileSystemOperations(logger), nil
	})

	builder.WithSingleton("fileops:path_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		return fileopsInfra.NewPathOperations(), nil
	})

	builder.WithSingleton("fileops:safe_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		return fileopsInfra.NewSafeFileOperations(logger), nil
	})

	builder.WithSingleton("fileops:template_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		fileOps, _ := GetTyped[fileops.FileOperations](c, "fileops:file_operations")
		return fileopsInfra.NewTemplateOperations(fileOps, logger), nil
	})

	// Register archive operations (stub for now)
	builder.WithSingleton("fileops:archive_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		// TODO: Implement archive operations
		return nil, fmt.Errorf("archive operations not implemented yet")
	})

	// Register domain service
	builder.WithSingleton("fileops:service", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		fileOps, _ := GetTyped[fileops.FileOperations](c, "fileops:file_operations")
		pathOps, _ := GetTyped[fileops.PathOperations](c, "fileops:path_operations")
		templateOps, _ := GetTyped[fileops.TemplateOperations](c, "fileops:template_operations")
		safeOps, _ := GetTyped[fileops.SafeOperations](c, "fileops:safe_operations")
		
		// Archive ops is optional for now
		var archiveOps fileops.ArchiveOperations
		if ops, err := GetTyped[fileops.ArchiveOperations](c, "fileops:archive_operations"); err == nil {
			archiveOps = ops
		}

		return fileops.NewService(fileOps, pathOps, templateOps, archiveOps, safeOps, logger), nil
	})

	return builder
}

// RegisterCryptoServices registers all cryptographic related services
func RegisterCryptoServices(builder *ContainerBuilder) *ContainerBuilder {
	// Register infrastructure implementations
	builder.WithSingleton("crypto:hash_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		return cryptoInfra.NewHashOperations(logger), nil
	})

	builder.WithSingleton("crypto:encryption_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		return cryptoInfra.NewEncryptionOperations(logger), nil
	})

	builder.WithSingleton("crypto:random_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		return cryptoInfra.NewRandomOperations(), nil
	})

	builder.WithSingleton("crypto:secure_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		return cryptoInfra.NewSecureOperations(logger), nil
	})

	// Key management with file-based fallback
	builder.WithSingleton("crypto:key_management", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		fileOps, _ := GetTyped[fileops.FileOperations](c, "fileops:file_operations")
		pathOps, _ := GetTyped[fileops.PathOperations](c, "fileops:path_operations")
		
		// Use secure key storage directory
		keyDir := "/var/lib/eos/keys"
		return cryptoInfra.NewFileBasedKeyManagement(keyDir, fileOps, pathOps, logger), nil
	})

	// Stub implementations for now
	builder.WithSingleton("crypto:signature_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		// TODO: Implement signature operations
		return nil, fmt.Errorf("signature operations not implemented yet")
	})

	builder.WithSingleton("crypto:certificate_operations", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		// TODO: Implement certificate operations
		return nil, fmt.Errorf("certificate operations not implemented yet")
	})

	// Register crypto policy
	builder.WithInstance("crypto:policy", crypto.DefaultCryptoPolicy())

	// Register domain service
	builder.WithSingleton("crypto:service", func(ctx context.Context, c *EnhancedContainer) (interface{}, error) {
		logger, _ := GetTyped[*zap.Logger](c, "logger")
		hashOps, _ := GetTyped[crypto.HashOperations](c, "crypto:hash_operations")
		encryptOps, _ := GetTyped[crypto.EncryptionOperations](c, "crypto:encryption_operations")
		randomOps, _ := GetTyped[crypto.RandomOperations](c, "crypto:random_operations")
		secureOps, _ := GetTyped[crypto.SecureOperations](c, "crypto:secure_operations")
		keyMgmt, _ := GetTyped[crypto.KeyManagement](c, "crypto:key_management")
		policy, _ := GetTyped[crypto.CryptoPolicy](c, "crypto:policy")
		
		// Optional services
		var signatureOps crypto.SignatureOperations
		var certOps crypto.CertificateOperations
		
		if ops, err := GetTyped[crypto.SignatureOperations](c, "crypto:signature_operations"); err == nil {
			signatureOps = ops
		}
		if ops, err := GetTyped[crypto.CertificateOperations](c, "crypto:certificate_operations"); err == nil {
			certOps = ops
		}

		return crypto.NewService(
			hashOps, encryptOps, signatureOps, certOps,
			randomOps, secureOps, keyMgmt, policy, logger,
		), nil
	})

	return builder
}

// CreateApplicationContainer creates a fully configured application container
func CreateApplicationContainer(ctx context.Context, logger *zap.Logger) (*EnhancedContainer, error) {
	builder := NewContainerBuilder(ctx, logger)

	// Register core services
	builder.WithInstance("logger", logger)

	// Register domain services
	RegisterFileOperationsServices(builder)
	RegisterCryptoServices(builder)
	
	// TODO: Register additional domain services
	// RegisterSystemInfoServices(builder)
	// RegisterParseServices(builder)
	// RegisterStringUtilsServices(builder)

	// Build and validate container
	container, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build application container: %w", err)
	}

	return container, nil
}

// Example usage showing migration from old helper functions to new domain services
func ExampleMigration() {
	ctx := context.Background()
	logger := zap.NewExample()

	// Create container
	container, err := CreateApplicationContainer(ctx, logger)
	if err != nil {
		panic(err)
	}

	// Get file operations service
	fileService, err := GetTyped[*fileops.Service](container, "fileops:service")
	if err != nil {
		panic(err)
	}

	// Old way (direct helper function):
	// shared.SafeRemove("/tmp/test.txt")

	// New way (using domain service):
	_ = fileService.SafeWriteFile(ctx, "/tmp/test.txt", []byte("test"), 0644)

	// Old way (direct utils function):
	// utils.ReplaceTokensInAllFiles("/path", replacements)

	// New way (using domain service):
	data := fileops.TemplateData{
		Variables: map[string]string{
			"APP_NAME": "eos",
			"VERSION":  "1.0.0",
		},
	}
	_ = fileService.ProcessTemplateDirectory(ctx, "/templates", "/output", data, nil)

	// Get crypto service
	cryptoService, err := GetTyped[*crypto.Service](container, "crypto:service")
	if err != nil {
		panic(err)
	}

	// Old way (direct crypto function):
	// crypto.HashString("data", "sha256")

	// New way (using domain service):
	result, _ := cryptoService.HashData(ctx, []byte("data"), crypto.SHA256)
	fmt.Printf("Hash: %s\n", result.Hash)

	// Old way (direct password generation):
	// crypto.GeneratePassword(16)

	// New way (using domain service with policy enforcement):
	password, _ := cryptoService.GenerateSecurePassword(ctx, 16)
	fmt.Printf("Generated password: %s\n", password)
}