# Security Policy

## Supported Versions

We actively support security updates for the following versions of Eos:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Security Analysis

### CodeQL Integration

This project uses GitHub CodeQL for automated security analysis with custom queries specifically designed for:

- **Vault Token Exposure**: Detects potential exposure of HashiCorp Vault tokens in logs or error messages
- **File Permission Validation**: Identifies insecure file permissions for sensitive files
- **Command Injection**: Detects potential command injection vulnerabilities
- **Hard-coded Credentials**: Finds hard-coded passwords, tokens, or other credentials

### Security Testing

Our security testing includes:

- **Static Analysis**: GoSec, Staticcheck, and custom security rules
- **Dependency Scanning**: Vulnerability scanning with govulncheck and nancy
- **Fuzz Testing**: Comprehensive fuzz testing for input validation
- **Integration Testing**: Security-focused integration tests

### Security Features

Eos implements several security features:

- **Structured Logging**: All output uses structured logging to prevent information disclosure
- **Secure File Permissions**: Sensitive files are created with restricted permissions (0600/0640)
- **Input Validation**: Comprehensive input validation and sanitization
- **Error Handling**: Secure error handling that doesn't expose sensitive information
- **Secret Management**: Integration with HashiCorp Vault for secret management

## Reporting a Vulnerability

If you discover a security vulnerability in Eos, please report it responsibly:

### Where to Report

- **Email**: [main@cybermonkey.net.au](mailto:main@cybermonkey.net.au)
- **Subject**: `[SECURITY] Vulnerability Report - Eos`

### What to Include

Please include the following information in your report:

1. **Description**: A clear description of the vulnerability
2. **Impact**: Assessment of the potential impact
3. **Reproduction Steps**: Detailed steps to reproduce the issue
4. **Environment**: Version, operating system, and configuration details
5. **Proof of Concept**: If applicable, include a minimal proof of concept

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix Timeline**: Varies by severity (see below)
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| **Critical** | Remote code execution, privilege escalation | 24-48 hours |
| **High** | Data exposure, authentication bypass | 3-7 days |
| **Medium** | Information disclosure, DoS | 2-4 weeks |
| **Low** | Minor security issues | 1-2 months |

## Security Best Practices

### For Users

- **Keep Updated**: Always use the latest version of Eos
- **Secure Configuration**: Follow security configuration guidelines
- **Vault Integration**: Use HashiCorp Vault for secret management
- **File Permissions**: Ensure proper file permissions for sensitive files
- **Network Security**: Use TLS/SSL for all network communications

### For Contributors

- **Security Review**: All code changes undergo security review
- **Testing**: Include security tests with your contributions
- **Dependencies**: Keep dependencies updated and scan for vulnerabilities
- **Secrets**: Never commit secrets or credentials to the repository
- **Logging**: Use structured logging and avoid logging sensitive data

## Security Contacts

- **Security Team**: [main@cybermonkey.net.au](mailto:main@cybermonkey.net.au)
- **Website**: [cybermonkey.net.au](https://cybermonkey.net.au/)

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged in our security advisories (unless they prefer to remain anonymous).

## Security Updates

Security updates are announced through:

- GitHub Security Advisories
- Release notes
- Email notifications to maintainers

Subscribe to repository notifications to stay informed about security updates.