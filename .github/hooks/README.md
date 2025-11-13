# Git Hooks for Eos

*Last Updated: 2025-10-21*

This directory contains Git hooks and related scripts for the Eos project.

## Quick Start

To install all Git hooks:

```bash
./.github/hooks/setup-hooks.sh
```

## Available Hooks

### pre-commit

Automatically removes emojis from staged Go files before commit.

**What it does:**
- Scans all staged `.go` files
- Skips test files (`*_test.go`, `test/`, `tests/`)
- Removes emojis using comprehensive Unicode pattern matching
- Re-stages cleaned files
- Reports which files were cleaned

**Example output:**
```
Running pre-commit checks...
Checking staged Go files for emojis...
Found emojis in 2 file(s)
Removing emojis from: cmd/create/example.go
✓ Cleaned: cmd/create/example.go
Removing emojis from: pkg/service/handler.go
✓ Cleaned: pkg/service/handler.go

Emojis removed from 2 file(s) and re-staged
✓ Pre-commit checks passed
```

**To bypass the hook (not recommended):**
```bash
git commit --no-verify
```

## Available Scripts

### remove-emojis.sh

Comprehensive emoji removal script for the entire codebase.

**Usage:**
```bash
# Dry-run mode (shows what would be changed)
./.github/hooks/remove-emojis.sh --dry-run

# Actually remove emojis
./.github/hooks/remove-emojis.sh
```

**Features:**
- Processes all Git-tracked files
- Supports 30+ file extensions
- Skips test files automatically
- Comprehensive Unicode emoji coverage (1F600-1F64F, 1F300-1F5FF, etc.)
- Colored output with summary statistics

**Example output:**
```
Starting emoji removal process...

⊗ Skipping test file: pkg/example/example_test.go
✓ Removed emojis from: cmd/create/service.go
✓ Removed emojis from: pkg/handler/response.go

═══════════════════════════════════════
Summary:
  Total files checked: 450
  Test files skipped: 75
  Non-test files processed: 375
  Files with emojis found: 12

✓ Emoji removal complete!
═══════════════════════════════════════
```

### setup-hooks.sh

Installation script for Git hooks.

**Usage:**
```bash
./.github/hooks/setup-hooks.sh
```

**What it does:**
1. Copies `pre-commit` hook to `.git/hooks/`
2. Makes scripts executable
3. Prompts before overwriting existing hooks
4. Provides usage instructions

## CI/CD Integration

The emoji check is also enforced in GitHub Actions via `.github/workflows/emoji-check.yml`.

**Workflow triggers:**
- Pull requests with Go/MD file changes
- Pushes to main with Go/MD file changes

**What it does:**
- Runs `remove-emojis.sh --dry-run`
- Comments on PR if emojis found
- Fails build if emojis detected
- Uploads detailed report

**Example PR comment:**
```markdown
##  Emojis Detected

Your PR contains emojis in non-test files. According to Eos project
standards (CLAUDE.md), emojis should not be used in production code.

### How to Fix

Run the emoji removal script locally:
./.github/hooks/remove-emojis.sh

Or set up the pre-commit hook to automatically remove emojis:
./.github/hooks/setup-hooks.sh
```

## Why No Emojis?

According to the Eos project philosophy (CLAUDE.md):

> "Only use emojis if the user explicitly requests it. Avoid using emojis
> in all communication unless asked."

**Rationale:**
- **Professional consistency**: Code should be universally readable
- **Rendering issues**: Emojis may not render correctly in all terminals
- **Accessibility**: Screen readers may struggle with emojis
- **Logging clarity**: Emojis in logs can cause parsing issues
- **International teams**: Emoji meanings vary across cultures

**Exception: Test files are exempt** to allow expressive test descriptions.

## Emoji Pattern Coverage

The hooks detect emojis from these Unicode blocks:

- **Emoticons**: U+1F600–U+1F64F (😀 to 🙏)
- **Misc Symbols & Pictographs**: U+1F300–U+1F5FF (🌀 to 🗿)
- **Transport & Map**: U+1F680–U+1F6FF (🚀 to 🛿)
- **Supplemental Symbols**: U+1F900–U+1F9FF (🤀 to 🧿)
- **Extended Pictographs**: U+1FA70–U+1FAFF (🩰 to 🫿)
- **Flags**: U+1F1E0–U+1F1FF (🇦 to 🇿)
- **Dingbats**: U+2700–U+27BF (✀ to ➿)
- **Misc Symbols**: U+2600–U+26FF (☀ to ⛿)
- **Variation Selectors**: U+FE00–U+FE0F
- **Zero Width Joiner**: U+200D (for composite emojis like 👨‍👩‍👧‍👦)

## Troubleshooting

### Hook not running

```bash
# Check if hook is installed
ls -la .git/hooks/pre-commit

# Reinstall
./.github/hooks/setup-hooks.sh

# Check permissions
chmod +x .git/hooks/pre-commit
chmod +x .github/hooks/remove-emojis.sh
```

### Perl not found

The scripts require Perl for Unicode regex support:

```bash
# macOS (usually pre-installed)
perl --version

# Ubuntu/Debian
sudo apt-get install perl

# RHEL/CentOS
sudo yum install perl
```

### Hook is slow

If you have many staged files, the hook may take a few seconds. This is normal.
Consider committing in smaller batches.

### False positives

If the hook incorrectly identifies non-emoji characters:
1. Check the Unicode range in the EMOJI_PATTERN
2. Report the issue with the specific character
3. Temporarily bypass with `git commit --no-verify` (not recommended)

## Development

### Testing changes to hooks

```bash
# Test emoji detection
echo "Test 🚀" > test.go
git add test.go
git commit -m "Test"  # Should trigger hook

# Test dry-run
./.github/hooks/remove-emojis.sh --dry-run

# Clean up
git reset HEAD test.go
rm test.go
```

### Modifying the emoji pattern

To add/remove Unicode ranges, edit `EMOJI_PATTERN` in:
- `.github/hooks/remove-emojis.sh`
- `.git/hooks/pre-commit`

### Adding new hooks

1. Create hook script in `.github/hooks/`
2. Add installation step to `setup-hooks.sh`
3. Document in this README
4. Consider adding GitHub Action equivalent

## Related Files

- **Hook installation**: `.github/hooks/setup-hooks.sh`
- **Pre-commit hook**: `.git/hooks/pre-commit` (installed)
- **Pre-commit source**: `.github/hooks/pre-commit` (version-controlled)
- **Emoji removal**: `.github/hooks/remove-emojis.sh`
- **GitHub Action**: `.github/workflows/emoji-check.yml`
- **Project standards**: `CLAUDE.md`
- **CI/CD analysis**: `.github/GITHUB_ACTIONS_ANALYSIS.md`

## Support

If you have issues with the hooks:

1. Check this README for troubleshooting
2. Review `.github/GITHUB_ACTIONS_ANALYSIS.md` for CI/CD context
3. Check `CLAUDE.md` for project standards
4. Report issues at: https://github.com/anthropics/claude-code/issues

---

*"No emojis in production code. Clear, professional, accessible."*
