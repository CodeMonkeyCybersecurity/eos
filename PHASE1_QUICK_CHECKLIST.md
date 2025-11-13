# Phase 1 Quick Checklist

**Status**: Ready for Execution (Network Connectivity Required)

---

## Pre-Flight Checks

- [ ] Go 1.25.3+ installed: `go version`
- [ ] Network connectivity: `ping storage.googleapis.com`
- [ ] Git configured: `git config user.name && git config user.email`
- [ ] On correct branch: `claude/eos-adversarial-analysis-011CV4zCrddG5gJjzf9ySyom`

---

## P0-1: Flag Bypass Fix (45 minutes)

- [ ] Dry-run: `./scripts/add-flag-validation.sh --dry-run`
- [ ] Apply: `./scripts/add-flag-validation.sh`
- [ ] Verify: `git diff cmd/ | head -50`
- [ ] Build: `go build -o /tmp/eos-build ./cmd/`
- [ ] Test attack blocked: `eos delete env prod -- --force` (should fail)
- [ ] Test normal usage: `eos delete env test --force` (should work)
- [ ] Commit: `git add cmd/ && git commit -m "fix(security): P0-1 flag bypass vulnerability"`
- [ ] Push: `git push`

---

## P0-7: TLS Audit (6-8 hours)

- [ ] Find: `grep -rn "InsecureSkipVerify.*true" pkg/ cmd/ --include="*.go"`
- [ ] Categorize 19 instances:
  - [ ] Test files (*_test.go): Document justification
  - [ ] Dev mode: Verify isDevelopment checks
  - [ ] Production: FIX or REMOVE
- [ ] Apply fixes (dev/prod split, CA certs)
- [ ] Document: Add `// SECURITY JUSTIFICATION` comments
- [ ] Validate: No unjustified InsecureSkipVerify in production
- [ ] Build: `go build -o /tmp/eos-build ./cmd/`
- [ ] Test: `go test ./pkg/...`
- [ ] Commit: `git add pkg/ cmd/ && git commit -m "fix(security): P0-7 TLS audit"`
- [ ] Push: `git push`

---

## Final Validation

- [ ] Full build: `go build -o /tmp/eos-build ./cmd/`
- [ ] Tests pass: `go test -v ./pkg/verify/ ./pkg/shared/`
- [ ] Lint passes: `golangci-lint run`
- [ ] CVE announcement drafted
- [ ] All changes pushed to remote

---

## Success Metrics

**Target State**:
- Flag bypass: 0/363 vulnerable (100% protected)
- InsecureSkipVerify: 0 unjustified in production
- Build: ✓ PASS
- Tests: ✓ PASS
- Lint: ✓ PASS

---

## Rollback (If Needed)

```bash
# Restore from backups
for f in cmd/**/*.bak; do mv "$f" "${f%.bak}"; done

# Or revert commits
git revert HEAD
git push --force-with-lease
```

---

## Time Budget

- P0-1: ~45 minutes
- P0-7: ~6-8 hours
- CVE: ~1 hour
- **Total: ~8-10 hours**

---

**See**: PHASE1_EXECUTION_GUIDE.md for detailed instructions
