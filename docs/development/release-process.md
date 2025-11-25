# Release Process

Lightweight release checklist; refine as automation evolves.

## Planning
- Confirm scope and status of relevant ADRs.
- Ensure documentation for new commands/services is updated (guides, reference, security if applicable).

## Quality gates
```bash
gofmt -w ./pkg ./cmd
go vet ./...
go test ./...
# Add integration/service-specific tests as needed
```
- Run linting (`golangci-lint run`) if configured.
- Smoke-test key workflows: create/update/backup/debug for core services (Vault, Consul, Nomad, Ceph).

## Versioning & tagging
- Bump version identifiers if present in code/scripts.
- Create a git tag for the release (`vX.Y.Z`).
- Update `CHANGELOG.md` with notable changes and risks.

## Build & publish
- Build artifacts using `./install.sh` (or dedicated release pipeline when added).
- Verify binaries on a clean host or container matching the preferred infrastructure outline.

## Post-release
- Monitor telemetry and debug outputs for regressions.
- File ADRs for follow-up improvements or deviations discovered post-release.
