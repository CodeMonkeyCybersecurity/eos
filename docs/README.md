# Eos Documentation

This directory contains comprehensive documentation for the Eos Ubuntu server administration tool.

## Documentation Structure

### Core Entry Points
- **[INDEX.md](INDEX.md)** - Complete documentation index and navigation
- **[CLAUDE.md](../CLAUDE.md)** - Complete development guide and coding standards
- **[DOCUMENTATION_STANDARDS.md](DOCUMENTATION_STANDARDS.md)** - Documentation standards and guidelines

### Components
- **[components/](./components/)** - Component-specific documentation
  - **[WAZUH.md](./components/WAZUH.md)** - Wazuh monitoring platform
  - **[VAULT.md](./components/VAULT.md)** - HashiCorp Vault integration
  - **[UBUNTU.md](./components/UBUNTU.md)** - Ubuntu system operations
  - **[HECATE.md](./components/HECATE.md)** - Reverse proxy framework
  - **[STORAGE_OPS.md](./components/STORAGE_OPS.md)** - Storage operations
  - **[EOS_INFRASTRUCTURE_COMPILER.md](./components/EOS_INFRASTRUCTURE_COMPILER.md)** - Infrastructure compiler

### Security
- **[security/](./security/)** - Security documentation and compliance
  - **[SECURITY_CHECKLIST.md](./security/SECURITY_CHECKLIST.md)** - Developer security checklist
  - **[SECURITY_COMPLIANCE.md](./security/SECURITY_COMPLIANCE.md)** - Compliance framework
  - **[SECURITY_ANALYSIS.md](./security/SECURITY_ANALYSIS.md)** - Security analysis and findings

### Testing
- **[testing/](./testing/)** - Testing documentation and guides
  - **[TEST_COVERAGE_REPORT.md](./testing/TEST_COVERAGE_REPORT.md)** - Comprehensive test coverage report
  - **[TESTING_GUIDE.md](./testing/TESTING_GUIDE.md)** - Testing best practices
  - **[FUZZING_GUIDE.md](./testing/FUZZING_GUIDE.md)** - Fuzz testing guidelines
  - **[COMPREHENSIVE_TESTING.md](./testing/COMPREHENSIVE_TESTING.md)** - Comprehensive testing implementation

### Development
- **[development/](./development/)** - Development guides and roadmaps
  - **[IMPROVEMENT_ROADMAP.md](./development/IMPROVEMENT_ROADMAP.md)** - Current improvement priorities
  - **[BOOTSTRAP_ARCHITECTURE.md](./development/BOOTSTRAP_ARCHITECTURE.md)** - Bootstrap architecture
  - **[REFACTORING_GUIDE.md](./development/REFACTORING_GUIDE.md)** - Refactoring guidelines
  - **[LOGGER_README.md](./development/LOGGER_README.md)** - Logging system documentation

### Operations & Deployment
- **[operations/](./operations/)** - Operational guides and procedures
  - **[PIPELINE.md](./operations/PIPELINE.md)** - Pipeline architecture and usage
  - **[TELEMETRY.md](./operations/TELEMETRY.md)** - Observability and telemetry setup
  - **[README-terraform-integration.md](./operations/README-terraform-integration.md)** - Terraform integration
  - **[auto-commit-guide.md](./operations/auto-commit-guide.md)** - Automated commit procedures

### User Guides
- **[user-guides/](./user-guides/)** - User and migration guides
  - **[MIGRATION_GUIDE.md](./user-guides/MIGRATION_GUIDE.md)** - Migration documentation
  - **[STACK.md](./user-guides/STACK.md)** - Technology stack overview

### Commands
- **[commands/](./commands/)** - Command-specific documentation
  - **[README.md](./commands/README.md)** - Commands overview
  - **[clusterfuzz.md](./commands/clusterfuzz.md)** - ClusterFuzz operations
  - **[hcl.md](./commands/hcl.md)** - HCL operations
  - **[secure-ubuntu.md](./commands/secure-ubuntu.md)** - Ubuntu hardening

### Guides & Emergency Procedures
- **[guides/](./guides/)** - Specialized guides
  - **[emergency-recovery.md](./guides/emergency-recovery.md)** - Emergency recovery procedures
  - **[mfa-implementation.md](./guides/mfa-implementation.md)** - Multi-factor authentication setup
  - **[mfa-user-guide.md](./guides/mfa-user-guide.md)** - User guide for MFA

### Architecture
- **[architecture/](./architecture/)** - Architectural documentation
  - **[CLEAN_ARCHITECTURE.md](./architecture/CLEAN_ARCHITECTURE.md)** - Clean architecture principles

### Historical & Migration
- **[CONSOLIDATION_COMPLETION_REPORT.md](CONSOLIDATION_COMPLETION_REPORT.md)** - Final consolidation status
- **[REMAINING_MIGRATION_PLAN.md](REMAINING_MIGRATION_PLAN.md)** - Future migration opportunities
- **[archive/](./archive/)** - Historical documentation and completed analyses

## Quick Start

1. **New Users**: Start with [INDEX.md](INDEX.md) for complete navigation, then [CLAUDE.md](../CLAUDE.md)
2. **Developers**: Read [CLAUDE.md](../CLAUDE.md) and explore [development/](./development/) guides
3. **Security Teams**: Review [security/](./security/) documentation and compliance frameworks
4. **Operations**: Check [operations/](./operations/) and [guides/](./guides/) directories
5. **Testing**: See [testing/](./testing/) directory for comprehensive testing documentation

## Getting Help

- **CLI Help**: `eos --help` or `eos [command] --help`
- **Issues**: Report bugs and request features via the project repository
- **Documentation**: Use [INDEX.md](INDEX.md) for complete navigation

---

*This documentation structure has been simplified and consolidated. Historical documents are preserved in the archive/ directory. Last updated: 2025-01-14*