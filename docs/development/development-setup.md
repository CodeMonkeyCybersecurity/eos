# Development Setup

Set up a local environment to build, test, and extend Eos.

## Prerequisites
- Ubuntu 24.04+ (or compatible dev environment)
- Go 1.25+
- Git
- Access to test infrastructure (Vault/Consul/Nomad, Ceph, etc.) when working on integration-heavy features.

## Initial setup
```bash
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
./install.sh   # builds the binary; requires sudo for system paths
```

## Local workflow
- Run formatting and tests before pushing changes:
  ```bash
  gofmt -w ./pkg ./cmd
  go vet ./...
  go test ./...
  ```
- Build the CLI without installing when iterating:
  ```bash
  go build -o /tmp/eos-dev ./cmd/...
  ```
- Use feature flags and dry-run options where available when testing on shared hosts.

## Tooling
- Linting: use `golangci-lint` if installed; keep configs in version control when added.
- Observability: verify structured logs via `otelzap` and ensure debug outputs land in `~/.eos/debug/`.

## Next steps
- Review [coding standards](coding-standards.md) and [release process](release-process.md).
- Add ADRs for significant architecture or UX changes.
