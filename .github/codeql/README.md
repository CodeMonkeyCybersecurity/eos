# CodeQL Security Analysis for Eos

## Overview

This directory contains a comprehensive CodeQL security analysis implementation for the Eos CLI application. The implementation includes custom security queries specifically designed for Go applications with a focus on CLI tools, secret management, and system administration.

## Components

### 1. CodeQL Workflow (`.github/workflows/codeql.yml`)

Enhanced GitHub Actions workflow that provides:
- **Comprehensive Security Analysis**: Daily scheduled runs plus PR/push triggers
- **Performance Optimization**: Caching for Go modules and build artifacts
- **Extended Query Coverage**: Security-and-quality plus experimental security queries
- **Artifact Upload**: Results preservation for review and audit

### 2. CodeQL Configuration (`codeql-config.yml`)

Advanced configuration featuring:
- **Path-based Analysis**: Focused scanning on security-critical components
- **Custom Query Integration**: Includes our custom security queries
- **Security Category Mapping**: Targets specific CWE categories relevant to Go CLI applications
- **Performance Tuning**: Optimized for comprehensive yet efficient analysis

### 3. Custom Security Queries

#### `vault-token-exposure.ql`
- **Purpose**: Detects potential exposure of HashiCorp Vault tokens in logging statements
- **Coverage**: Zap, standard log, fmt, and otelzap logging functions
- **Detection**: Pattern matching for hvs/hvb tokens, variable names, method calls
- **Security Impact**: Prevents credential leakage in logs

#### `command-injection.ql`
- **Purpose**: Identifies command injection vulnerabilities in exec calls
- **Coverage**: os/exec.Command, syscall.Exec, os.StartProcess
- **Detection**: User input to command execution without proper sanitization
- **Security Impact**: Prevents remote code execution through command injection

#### `hardcoded-credentials.ql`
- **Purpose**: Finds hard-coded passwords, tokens, and credentials
- **Coverage**: String literals, variable assignments, struct field initialization
- **Detection**: Vault tokens, JWT tokens, API keys, passwords, database connections
- **Security Impact**: Eliminates hard-coded secrets in source code

#### `insecure-file-permissions.ql`
- **Purpose**: Detects insecure file permissions for sensitive files
- **Coverage**: os.OpenFile, os.WriteFile, os.Chmod, ioutil.WriteFile
- **Detection**: World-readable/writable permissions on sensitive files
- **Security Impact**: Ensures proper file system security

### 4. Query Suite (`eos-security-queries.qls`)

Organized collection of:
- Custom Eos-specific security queries
- Standard Go security queries
- CWE-mapped vulnerability detection

### 5. Query Package (`qlpack.yml`)

Properly structured CodeQL package with:
- Dependencies on codeql/go-all
- Exclusion of test files and utilities
- Security-focused grouping

## Security Coverage

### CWE Categories Addressed

- **CWE-78**: OS Command Injection
- **CWE-200**: Information Exposure
- **CWE-532**: Information Exposure Through Log Files
- **CWE-732**: Incorrect Permission Assignment for Critical Resource
- **CWE-798**: Use of Hard-coded Credentials

### Application-Specific Risks

- **Vault Token Management**: Detection of token exposure in various contexts
- **CLI Argument Processing**: Command injection through user input
- **File System Operations**: Insecure permissions on sensitive files
- **Logging Practices**: Prevention of sensitive data logging

## Usage

### Automated Analysis

CodeQL analysis runs automatically on:
- **Push to main/develop**: Immediate security feedback
- **Pull Requests**: Pre-merge security validation
- **Daily Schedule**: Comprehensive security scanning
- **Manual Trigger**: On-demand full security scan

### Manual Testing

```bash
# Test query syntax
./.github/codeql/test-queries.sh

# Run specific query (requires CodeQL CLI)
codeql database analyze --format=csv --output=results.csv database.db .github/codeql/custom-queries/
```

### Integration with Security Workflow

The CodeQL analysis integrates with the broader security testing pipeline:
- **Security Tests**: Validates security-focused unit tests
- **Static Analysis**: Combines with GoSec, Staticcheck, and Semgrep
- **Dependency Scanning**: Works alongside govulncheck and nancy
- **Secret Scanning**: Complements TruffleHog scanning

## Configuration

### Customization

To modify the analysis:

1. **Add New Queries**: Place `.ql` files in `custom-queries/`
2. **Update Query Suite**: Modify `eos-security-queries.qls`
3. **Adjust Paths**: Update `codeql-config.yml` path filters
4. **Change Schedule**: Modify workflow triggers

### Environment Variables

The workflow supports:
- **Go Version**: Configurable Go version (default: 1.25)
- **Timeout**: Analysis timeout (default: 360 minutes)
- **Cache**: Automatic Go module caching

## Security Best Practices

### Query Development

- **Precision**: High precision to minimize false positives
- **Performance**: Optimized for large codebases
- **Maintainability**: Well-documented and structured
- **Test Coverage**: Exclude test files from security analysis

### Integration

- **Fail-Fast**: Early detection in development workflow
- **Comprehensive**: Multiple analysis tools for complete coverage
- **Actionable**: Clear, specific security findings
- **Auditable**: Preserved results for compliance and review

## Monitoring and Maintenance

### Regular Tasks

- **Query Updates**: Keep queries aligned with new security patterns
- **Library Updates**: Maintain compatibility with CodeQL library updates
- **Performance Review**: Monitor analysis execution time
- **Coverage Assessment**: Ensure queries cover new code patterns

### Metrics

The implementation tracks:
- **Analysis Coverage**: Percentage of code analyzed
- **Query Performance**: Execution time per query
- **Finding Accuracy**: False positive/negative rates
- **Security Trend**: Historical security issue detection

## Support

For issues or improvements:
- **Security Issues**: Report via [SECURITY.md](../SECURITY.md)
- **General Issues**: Use GitHub Issues
- **Contact**: [main@cybermonkey.net.au](mailto:main@cybermonkey.net.au)

## References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Go CodeQL Library](https://codeql.github.com/codeql-standard-libraries/go/)
- [GitHub Security Features](https://docs.github.com/en/code-security)
- [Eos Security Policy](../SECURITY.md)