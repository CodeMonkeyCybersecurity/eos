# Coding Standards

Align code with Eos architecture and the Human Technology principles.

## Core rules
- Keep orchestration in `cmd/`; business logic lives in `pkg/`.
- Follow Assess → Intervene → Evaluate for every operation.
- Use `otelzap.Ctx(rc.Ctx)` for logging; avoid `fmt.Print*` for operational output.
- No hardcoded ports/paths/permissions; centralize constants under `pkg/<service>/constants.go` or shared packages.
- Use SecretManager for credentials; never embed secrets in code or config examples.
- Prefer SDKs over shelling out; handle retries and timeouts explicitly.
- Keep functions small and typed; return rich errors with context (wrap, do not panic).

## Testing and quality
- Format: `gofmt -w ./pkg ./cmd`
- Static analysis: `go vet ./...`
- Tests: `go test ./...` (add focused integration tests when touching services)
- Linting: `golangci-lint run` if configured.

## Documentation
- Update relevant docs and ADRs alongside code changes.
- Document new flags/env vars in [reference](../reference/) and new behaviors in [guides](../guides/).
- Keep examples human-centric: show consent prompts and safe defaults.
