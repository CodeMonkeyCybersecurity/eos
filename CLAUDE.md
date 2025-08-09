# CLAUDE.md

*Last Updated: 2025-01-07*

AI assistant guidance for the Eos project - a Go-based CLI for Ubuntu server administration by Code Monkey Cybersecurity.

## 🚨 CRITICAL RULES (P0 - Breaking)

These violations cause immediate failure:

1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
2. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate in helpers
3. **Architecture**: Infrastructure → SaltStack, Applications → Nomad
4. **Completion**: Must pass `go build`, `golangci-lint run`, `go test -v ./pkg/...`
5. **Context**: Always use `*eos_io.RuntimeContext` for all operations

## Quick Decision Trees

```
New Service?
├─ System/Security/Orchestration → SaltStack (/salt/states/)
└─ Container/Web/Database → Nomad (/nomad/jobs/)

Need User Input?
├─ Flag provided → Use it
└─ Flag missing → Prompt interactively (eos_io.PromptInput)

Error Type?
├─ User fixable → eos_err.NewUserError() → exit(0)
└─ System failure → eos_err.NewSystemError() → exit(1)

Command Structure?
└─ VERB-FIRST only: create, read, list, update, delete (+ self, backup)
```

## Project Constraints

### MUST:
- Use structured logging via `otelzap.Ctx(rc.Ctx)`
- Follow Assess → Intervene → Evaluate pattern
- Keep business logic in `pkg/`, orchestration in `cmd/`
- Verify all operations with explicit checks
- Use version resolver for new deployments (`pkg/platform/version_resolver.go`)
- Add `*Last Updated: YYYY-MM-DD*` to all .md files

### MUST NOT:
- Use `fmt.Print/Printf/Println` for output (but `fmt.Errorf` is OK)
- Put business logic in `cmd/` files
- Skip verification steps
- Create tactical documentation files (.md)
- Hardcode values - use flags or prompts
- Mix SaltStack and Nomad for same service

## Quick Command Reference

| Pattern | Example | Location |
|---------|---------|----------|
| Command file | `cmd/create/consul.go` | Orchestration only |
| Package helper | `pkg/consul/install.go` | Business logic |
| Error wrapping | `fmt.Errorf("failed to X: %w", err)` | All errors |
| User prompt | `logger.Info("terminal prompt: X")` | Before input |
| Testing | See `PATTERNS.md#testing` | All packages |

## Architecture Overview

### Dual-Layer System
- **Layer 1 (SaltStack)**: Infrastructure, security tools, system packages
- **Layer 2 (Nomad)**: Containerized apps, web services, databases
- **User sees**: Unified `eos create X` regardless of layer

### Package Structure
```
cmd/[verb]/          # Orchestration only
pkg/[feature]/       # Business logic
  ├── types.go       # Types, constants
  ├── install.go     # Installation
  ├── configure.go   # Configuration  
  └── verify.go      # Verification
```

### Command Flow
1. User input → 2. Cobra routing → 3. RuntimeContext → 4. Orchestration (`cmd/`) 
→ 5. Business logic (`pkg/`) → 6. Assess/Intervene/Evaluate → 7. Error handling

## Testing Requirements

Before marking complete:
```bash
go build -o /tmp/eos-build ./cmd/    # Must compile
golangci-lint run                    # Must pass linting
go test -v ./pkg/...                 # Must pass tests
```

## AI Assistant Guidelines

### Efficiency Tips
- Batch related file reads in single response
- Use Task tool for open-ended searches
- Use TodoWrite for multi-step operations
- Search before asking for clarification
- Check existing patterns in codebase first

### Code Patterns
For detailed examples see `PATTERNS.md`:
- Logging patterns → `PATTERNS.md#logging`
- Error handling → `PATTERNS.md#errors`
- Assess/Intervene/Evaluate → `PATTERNS.md#aie-pattern`
- Interactive prompting → `PATTERNS.md#prompting`
- Helper structure → `PATTERNS.md#helpers`

## Common Anti-Patterns

| Never Do This | Always Do This |
|--------------|----------------|
| `fmt.Println("text")` | `logger.Info("text")` |
| Business logic in `cmd/` | Delegate to `pkg/` |
| `exec.Command().Run()` | Check with `exec.LookPath()` first |
| Skip verification | Explicit verification checks |
| Create tactical .md files | Use inline `// TODO:` comments |

## Service Classification

### Infrastructure (SaltStack)
consul, vault, nomad, fail2ban, trivy, osquery, saltstack, docker

### Applications (Nomad)
grafana, jenkins, nextcloud, mattermost, gitlab, postgres, redis

## Priority Levels

- **P0 (BREAKING)**: Violations cause immediate failure
- **P1 (CRITICAL)**: Must fix before marking complete
- **P2 (IMPORTANT)**: Should follow unless justified
- **P3 (RECOMMENDED)**: Best practices

## Idempotency Principles

1. Check before acting - Don't assume state
2. Handle "already done" gracefully - Not an error
3. Focus on end result, not the action
4. Use conditional operations

## External References

- Detailed patterns: `PATTERNS.md`
- Architecture: `STACK.md`
- Knowledge base: [Athena](https://wiki.cybermonkey.net.au)
- Company: [cybermonkey.net.au](https://cybermonkey.net.au/)

## Memory Notes

- No emojis in code or documentation
- Prefer editing existing files over creating new ones
- Documentation files only for strategic changes
- Use inline comments for tactical notes