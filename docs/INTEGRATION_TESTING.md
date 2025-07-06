# Integration Testing Framework

This document describes the comprehensive integration testing framework built for the Eos project.

## Overview

The integration testing framework provides end-to-end testing capabilities that connect all well-tested components together, ensuring they work correctly in realistic scenarios.

## Framework Components

### 1. IntegrationTestSuite (`pkg/testutil/integration.go`)

The core orchestration framework that provides:

- **Environment Setup**: Automated test environment configuration
- **Mock Services**: HTTP transport mocking for external services
- **Resource Management**: Temporary directories, certificates, and cleanup
- **Context Management**: Runtime context creation and lifecycle management
- **Command Execution**: Cobra command testing with timeouts
- **Scenario Orchestration**: Step-by-step test execution with validation

#### Key Features:

```go
// Create a test suite
suite := testutil.NewIntegrationTestSuite(t, "test-name")

// Add mock services
suite.WithVaultMock()
suite.WithDockerMock()

// Create runtime contexts
rc := suite.CreateTestContext("command-name")

// Execute commands with timeout
err := suite.ExecuteCommandWithTimeout(cmd, args, timeout)
```

### 2. Predefined Scenarios (`pkg/testutil/scenarios.go`)

Ready-to-use test scenarios for common workflows:

- **VaultHealthCheckScenario()**: Vault client and authentication testing
- **FileSecurityScenario()**: File permission and secure operations testing
- **RuntimeContextLifecycleScenario()**: Context creation, attributes, and cleanup
- **ErrorHandlingScenario()**: Panic recovery and security validation

#### Usage:

```go
scenario := testutil.VaultHealthCheckScenario()
suite.RunScenario(scenario)
```

### 3. Test Patterns

Reusable patterns for common testing needs:

- **MockServicePattern**: External service mocking
- **FileSystemPattern**: File operation testing
- **ConcurrencyPattern**: Concurrent operation testing

## Integration Test Structure

### Test Scenarios

Each scenario consists of:

```go
type TestScenario struct {
    Name        string
    Description string
    Setup       func(*IntegrationTestSuite)     // Optional setup
    Steps       []TestStep                      // Execution steps
    Cleanup     func(*IntegrationTestSuite)     // Optional cleanup
}
```

### Test Steps

Individual steps with validation:

```go
type TestStep struct {
    Name        string
    Description string
    Action      func(*IntegrationTestSuite) error
    Validation  func(*IntegrationTestSuite) error  // Optional
    Timeout     time.Duration
}
```

## Available Integration Tests

### Core Integration Tests (`integration_test.go`)

1. **TestEosIntegration_VaultAuthenticationWorkflow**
   - Vault client setup
   - Authentication orchestration
   - Error handling validation

2. **TestEosIntegration_CommandWrapperFlow**
   - CLI command execution
   - Panic recovery testing
   - Telemetry integration

3. **TestEosIntegration_ConfigurationManagement**
   - Configuration file handling
   - Runtime context attributes
   - File system operations

4. **TestEosIntegration_ErrorHandlingFlow**
   - Error categorization
   - Context cancellation
   - Security validation

5. **TestEosIntegration_TelemetryAndLogging**
   - Telemetry span creation
   - Contextual logging
   - Observability features

6. **TestEosIntegration_MultiComponentWorkflow**
   - Multi-service integration
   - Component interaction
   - Resilience testing

### Scenario-Based Tests (`integration_scenarios_test.go`)

1. **TestIntegrationScenarios_VaultHealthCheck**
2. **TestIntegrationScenarios_FileSecurityOperations**
3. **TestIntegrationScenarios_RuntimeContextLifecycle**
4. **TestIntegrationScenarios_ErrorHandling**
5. **TestIntegrationScenarios_CombinedWorkflow**

## Running Integration Tests

### Run all integration tests:
```bash
go test -v ./integration_test.go ./integration_scenarios_test.go
```

### Run specific test:
```bash
go test -v ./integration_test.go -run TestEosIntegration_VaultAuthenticationWorkflow
```

### Run scenario-based tests:
```bash
go test -v ./integration_scenarios_test.go -run TestIntegrationScenarios_VaultHealthCheck
```

## Test Environment

The framework automatically sets up:

- **Temporary directories** for test data
- **Mock TLS certificates** for secure connections
- **Environment variables** for test configuration
- **Mock HTTP transports** for external services
- **Cleanup handlers** for resource management

### Environment Variables Set:

- `Eos_TEST_MODE=true`
- `VAULT_SKIP_VERIFY=true`
- `VAULT_ADDR=http://127.0.0.1:8200`
- `VAULT_CACERT=<temp-cert-path>`
- `Eos_DATA_DIR=<temp-data-dir>`
- `Eos_LOG_LEVEL=debug`

## Mock Services

### Vault Mock Transport
- Health check endpoints
- Authentication endpoints
- Token validation

### Docker Mock Transport
- Container listing
- Image management
- Status checking

### Wazuh Mock Transport
- User management
- Role management
- Policy management

## Best Practices

### 1. Test Isolation
- Each test suite gets its own temporary environment
- Automatic cleanup prevents test interference
- Environment variables are restored after tests

### 2. Timeout Management
- All test steps have configurable timeouts
- Default timeout: 30 seconds
- Context cancellation for long-running operations

### 3. Error Handling
- Comprehensive error validation
- Security-focused error message checking
- Panic recovery testing

### 4. Resource Management
- Automatic cleanup of test resources
- Proper context lifecycle management
- Memory and goroutine leak prevention

## Writing New Integration Tests

### 1. Create a Test Suite
```go
func TestMyIntegration(t *testing.T) {
    suite := testutil.NewIntegrationTestSuite(t, "my-test")
    suite.WithVaultMock() // Optional mock services
    
    // Your test logic here
}
```

### 2. Define a Custom Scenario
```go
scenario := testutil.TestScenario{
    Name: "my_custom_scenario",
    Steps: []testutil.TestStep{
        {
            Name: "step_1",
            Action: func(s *testutil.IntegrationTestSuite) error {
                // Your test logic
                return nil
            },
            Timeout: 10 * time.Second,
        },
    },
}

suite.RunScenario(scenario)
```

### 3. Use Predefined Patterns
```go
pattern := testutil.MockServicePattern("myservice", myMockTransport)
scenario := testutil.TestScenario{
    Setup: func(s *testutil.IntegrationTestSuite) {
        pattern.Setup(s)
    },
    // ... rest of scenario
}
```

## Framework Benefits

1. **Comprehensive Coverage**: Tests end-to-end workflows
2. **Realistic Scenarios**: Uses actual component integration
3. **Isolation**: Each test runs in isolated environment
4. **Reusability**: Predefined scenarios and patterns
5. **Maintainability**: Structured approach with clear separation
6. **Debugging**: Detailed step-by-step execution with timeouts
7. **Security Focus**: Validates security properties in integration
8. **Performance**: Concurrent execution support and timeout management

## Future Enhancements

- Add more predefined scenarios for specific workflows
- Extend mock services for additional external dependencies
- Add performance benchmarking capabilities
- Implement test result reporting and metrics
- Add support for distributed testing scenarios


--- 
scripts/ migration 

Migration Plan: Legacy Scripts to Eos Framework

  Executive Summary

  I propose a phased migration approach that transforms 80+ 
  legacy scripts across 7 languages into secure, modular Go
  functions within the Eos framework. The migration
  prioritizes Vault integration for secrets management,
  Terraform for infrastructure provisioning, and Nomad for 
  service orchestration, following the
  assessment→intervention→evaluation model.

  Phase 1: High-Priority Security & Infrastructure (Weeks 1-4)

  1.1 Vault Integration - Credential Management

  Target Scripts: changeDefaultCredentials.sh, deployNewDb.py,
   installPostgreSQL.sh

  Implementation Strategy:
  // Assessment: Check current credential storage
  func AssessCredentialSecurity(rc *eos_io.RuntimeContext) 
  error {
      logger := otelzap.Ctx(rc.Ctx)
      // Scan for plaintext credentials
      // Validate Vault connectivity
      // Report security gaps
  }

  // Intervention: Migrate to Vault
  func MigrateCredentialsToVault(rc *eos_io.RuntimeContext) 
  error {
      // Generate secure credentials
      // Store in Vault with appropriate policies
      // Configure dynamic secret engines
  }

  // Evaluation: Verify secure implementation
  func ValidateVaultIntegration(rc *eos_io.RuntimeContext) 
  error {
      // Test credential retrieval
      // Verify access policies
      // Confirm audit logging
  }

  1.2 Terraform Infrastructure Provisioning

  Target Scripts: installTailscale.sh, installTraefik.py,
  setupHeadscale.sh

  Implementation Strategy:
  // pkg/infrastructure/tailscale.go
  func DeployTailscaleInfrastructure(rc 
  *eos_io.RuntimeContext, config TailscaleConfig) error {
      // Assessment: Validate prerequisites and connectivity
      if err := assessTailscaleRequirements(rc, config); err
  != nil {
          return eos_err.Wrap(err, "tailscale prerequisites 
  not met")
      }

      // Intervention: Apply Terraform configuration
      if err := applyTerraformPlan(rc, "tailscale", config);
  err != nil {
          return eos_err.Wrap(err, "terraform apply failed")
      }

      // Evaluation: Verify deployment and connectivity
      return validateTailscaleDeployment(rc, config)
  }

  1.3 Container Management Consolidation

  Target Scripts: docker/backup*.mjs (8 files)

  New Package: pkg/container/backup.go
  func BackupDockerEnvironment(rc *eos_io.RuntimeContext, opts
   BackupOptions) error {
      logger := otelzap.Ctx(rc.Ctx)

      // Assessment: Inventory Docker resources
      inventory, err := assessDockerResources(rc)
      if err != nil {
          return err
      }
      logger.Info("Docker environment assessed",
  zap.Int("containers", inventory.ContainerCount))

      // Intervention: Execute parallel backups
      backupTasks := []BackupTask{
          {Type: "containers", Func: backupContainers},
          {Type: "volumes", Func: backupVolumes},
          {Type: "networks", Func: backupNetworks},
          {Type: "images", Func: backupImages},
      }

      for _, task := range backupTasks {
          if err := task.Func(rc, opts); err != nil {
              return eos_err.Wrap(err, fmt.Sprintf("%s backup 
  failed", task.Type))
          }
      }

      // Evaluation: Verify backup integrity
      return validateBackupIntegrity(rc, opts)
  }

  Phase 2: System Management & Security (Weeks 5-8)

  2.1 Security Hardening Suite

  Target Scripts: disableSSHIntoRoot.py, setupTerminal2FA.sh,
  updatePermissions.py

  New Package: pkg/security/hardening.go
  func HardenSystemSecurity(rc *eos_io.RuntimeContext, profile
   SecurityProfile) error {
      hardeningSteps := []HardeningStep{
          {Name: "SSH Configuration", Func:
  hardenSSHConfiguration},
          {Name: "Two-Factor Authentication", Func:
  setupTwoFactorAuth},
          {Name: "File Permissions", Func:
  auditAndFixPermissions},
          {Name: "Firewall Rules", Func: configureFirewall},
      }

      for _, step := range hardeningSteps {
          // Assessment: Check current security state
          currentState, err := step.AssessmentFunc(rc)
          if err != nil {
              return eos_err.Wrap(err, fmt.Sprintf("assessment
   failed for %s", step.Name))
          }

          // Intervention: Apply security measures (with 
  backup)
          if err := createSecurityBackup(rc, step.Name); err
  != nil {
              return err
          }

          if err := step.Func(rc, profile); err != nil {
              rollbackErr := restoreSecurityBackup(rc,
  step.Name)
              return eos_err.Wrap(err, fmt.Sprintf("hardening 
  failed for %s, rollback: %v", step.Name, rollbackErr))
          }

          // Evaluation: Verify security improvements
          if err := step.ValidationFunc(rc, currentState); err
   != nil {
              return eos_err.Wrap(err, fmt.Sprintf("validation
   failed for %s", step.Name))
          }
      }

      return nil
  }

  2.2 System Service Management

  Target Scripts: manageServices.py, manageCron.py

  Enhanced Package: pkg/eos_unix/services.go
  func ManageSystemServices(rc *eos_io.RuntimeContext, 
  operations []ServiceOperation) error {
      logger := otelzap.Ctx(rc.Ctx)

      for _, op := range operations {
          // Assessment: Check service current state
          currentState, err := assessServiceState(rc,
  op.ServiceName)
          if err != nil {
              return eos_err.Wrap(err, fmt.Sprintf("cannot 
  assess %s", op.ServiceName))
          }

          logger.Info("Service state assessed",
              zap.String("service", op.ServiceName),
              zap.String("current_state",
  currentState.Status),
              zap.String("desired_action", op.Action))

          // Intervention: Execute service operation
          if err := executeServiceOperation(rc, op); err !=
  nil {
              return eos_err.Wrap(err, fmt.Sprintf("operation 
  %s failed for %s", op.Action, op.ServiceName))
          }

          // Evaluation: Verify operation success
          if err := validateServiceOperation(rc, op,
  currentState); err != nil {
              return eos_err.Wrap(err, fmt.Sprintf("validation
   failed for %s %s", op.Action, op.ServiceName))
          }
      }

      return nil
  }

  Phase 3: Advanced Infrastructure & Monitoring (Weeks 9-12)

  3.1 Nomad Service Orchestration

  Target Scripts: deployWazuh.sh, installGrafana.py,
  installMattermost.py

  New Package: pkg/orchestration/nomad.go
  func DeployServiceWithNomad(rc *eos_io.RuntimeContext, 
  service ServiceDefinition) error {
      logger := otelzap.Ctx(rc.Ctx)

      // Assessment: Validate Nomad cluster and dependencies
      clusterHealth, err := assessNomadCluster(rc)
      if err != nil {
          return eos_err.Wrap(err, "nomad cluster assessment 
  failed")
      }

      if !clusterHealth.Ready {
          return eos_err.New("nomad cluster not ready for 
  deployment")
      }

      // Intervention: Deploy service via Nomad
      jobSpec, err := generateNomadJobSpec(service)
      if err != nil {
          return eos_err.Wrap(err, "job specification 
  generation failed")
      }

      deploymentID, err := deployNomadJob(rc, jobSpec)
      if err != nil {
          return eos_err.Wrap(err, "nomad deployment failed")
      }

      logger.Info("Service deployment initiated",
          zap.String("service", service.Name),
          zap.String("deployment_id", deploymentID))

      // Evaluation: Verify service health and accessibility
      return validateServiceDeployment(rc, service,
  deploymentID)
  }

  3.2 Database Management Integration

  Target Scripts: PostgreSQL/*.py, PostgreSQL/*.sh

  Enhanced Package: pkg/database/postgresql.go
  func ManagePostgreSQLInstance(rc *eos_io.RuntimeContext, 
  config PostgreSQLConfig) error {
      logger := otelzap.Ctx(rc.Ctx)

      // Assessment: Check PostgreSQL state and requirements
      dbState, err := assessPostgreSQLState(rc, config)
      if err != nil {
          return eos_err.Wrap(err, "postgresql assessment 
  failed")
      }

      // Intervention: Configure database with Vault 
  integration
      if !dbState.Installed {
          if err := installPostgreSQL(rc, config); err != nil
  {
              return eos_err.Wrap(err, "postgresql 
  installation failed")
          }
      }

      // Configure dynamic credentials via Vault
      if err := configureVaultDynamicSecrets(rc, config); err
  != nil {
          return eos_err.Wrap(err, "vault integration failed")
      }

      // Evaluation: Verify database functionality and 
  security
      return validatePostgreSQLSetup(rc, config)
  }

  Implementation Guidelines

  1. Package Structure

  pkg/
  ├── infrastructure/     # Network infrastructure (Tailscale,
   Traefik, Headscale)
  ├── security/          # Security hardening and compliance
  ├── orchestration/     # Nomad and container orchestration
  ├── database/          # Database management (PostgreSQL,
  etc.)
  ├── backup/           # Unified backup operations
  └── config/           # Configuration validation and
  management

  2. Command Integration

  // cmd/create.go - Enhanced with script functionality
  var createInfrastructureCmd = &cobra.Command{
      Use:   "infrastructure [service]",
      Short: "Deploy infrastructure services with Terraform",
      Run: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd 
  *cobra.Command, args []string) error {
          return infrastructure.DeployService(rc, args[0])
      }),
  }

  // cmd/secure.go - New command for security hardening
  var secureSystemCmd = &cobra.Command{
      Use:   "system 
  [--profile=baseline|intermediate|advanced]",
      Short: "Harden system security configuration",
      Run: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd 
  *cobra.Command, args []string) error {
          profile, _ := cmd.Flags().GetString("profile")
          return security.HardenSystemSecurity(rc,
  security.GetProfile(profile))
      }),
  }

  3. Configuration Management

  # eos-config.yaml - Migration configuration
  migration:
    scripts:
      enabled: true
      legacy_path: "./scripts"
      backup_before_migration: true

    vault:
      dynamic_secrets: true
      rotation_interval: "24h"

    terraform:
      state_backend: "consul"
      workspace_prefix: "eos-"

    nomad:
      datacenter: "dc1"
      namespace: "eos"

  Success Metrics

  Security Improvements

  - 100% credential elimination from plaintext storage
  - Automated secret rotation for all services
  - Comprehensive audit trails for all security operations

  Operational Efficiency

  - 80% reduction in manual deployment steps
  - Automated rollback capabilities for all infrastructure
  changes
  - Centralized logging and monitoring for all operations

  Reliability Enhancements

  - Infrastructure as Code for all deployments
  - Health checking and auto-recovery for services
  - Consistent state management across environments

  This migration plan transforms the legacy script collection
  into a modern, secure, and maintainable infrastructure
  management platform while preserving all existing
  functionality and adding significant security and
  operational improvements.

