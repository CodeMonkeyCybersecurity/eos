# Eos Documentation Standards

*Last Updated: 2025-01-14*

This document establishes standards for all documentation in the Eos project to ensure consistency, maintainability, and ease of navigation.

## File Organization

### Directory Structure
```
docs/
├── INDEX.md                 # Main navigation index
├── README.md               # Project overview
├── DOCUMENTATION_STANDARDS.md  # This file
├── architecture/           # System design and architecture
├── commands/              # Command reference and usage
├── components/            # Component-specific documentation
├── development/           # Developer guides and processes
├── guides/                # User guides and tutorials
├── migration/             # Migration guides and procedures
├── operations/            # Deployment and operational guides
├── security/              # Security documentation
├── testing/               # Testing guides and reports
├── user-guides/           # End-user documentation
└── archive/               # Historical and deprecated docs
```

### File Naming Conventions

#### Filenames
- Use UPPERCASE for major documents: `README.md`, `SECURITY_GUIDE.md`
- Use lowercase for specific guides: `installation-guide.md`
- Use descriptive names: `vault-database-integration.md` not `vault-db.md`
- Separate words with hyphens: `multi-word-guide.md`
- Include version for versioned docs: `api-guide-v2.md`

#### Categories
- **README**: Project/component overviews
- **GUIDE**: Step-by-step instructions
- **REFERENCE**: API/command references
- **ANALYSIS**: Technical analysis and reports
- **STANDARDS**: Standards and conventions
- **CHECKLIST**: Verification lists

## Content Standards

### Document Structure

#### Required Sections
Every document must include:
1. **Title** (# level 1 heading)
2. **Overview/Summary** (brief description)
3. **Table of Contents** (for docs >100 lines)
4. **Main Content**
5. **Related Documentation** (links to related docs)

#### Optional Sections (as appropriate)
- **Prerequisites**
- **Quick Start**
- **Examples**
- **Troubleshooting**
- **References**
- **Changelog**

### Writing Style

#### General Guidelines
- Write in clear, concise language
- Use active voice when possible
- Address the reader directly ("you should...")
- Use consistent terminology throughout
- Avoid jargon without explanation
- Include examples for complex concepts

#### Technical Content
- Use code blocks with language specification:
  ```bash
  eos create vault --auto-unseal
  ```
- Include expected output when relevant
- Provide context for commands
- Explain the "why" not just the "how"

#### Formatting
- Use **bold** for emphasis and UI elements
- Use `code` for commands, file paths, and technical terms
- Use *italics* for new concepts on first introduction
- Use > blockquotes for important notes and warnings

### Cross-References

#### Internal Links
- Link to related documentation: `[Migration Guide](migration/MIGRATION_GUIDE.md)`
- Use relative paths: `../security/SECURITY_CHECKLIST.md`
- Link to specific sections: `[Installation](#installation)`
- Maintain links when moving files

#### External Links
- Use descriptive link text: `[HashiCorp Vault Documentation](https://www.vaultproject.io/docs)`
- Include version information for external references
- Check links regularly for validity

## Maintenance

### Update Responsibilities

#### Authors
- Keep documents current with code changes
- Update cross-references when moving files
- Tag documents with creation/update dates

#### Reviewers
- Verify technical accuracy
- Check links and references
- Ensure style consistency
- Validate examples work as described

### Version Control

#### Commit Messages
- Use descriptive commit messages for documentation
- Group related documentation changes
- Reference issue numbers when applicable

#### Change Tracking
- Major changes should update the document date
- Breaking changes require update to dependent docs
- Archive outdated documents rather than deleting

## Quality Checklist

### Before Publishing
- [ ] Document follows naming conventions
- [ ] Structure includes required sections
- [ ] Content is technically accurate
- [ ] Examples are tested and working
- [ ] Links are valid and functional
- [ ] Spelling and grammar are correct
- [ ] Style is consistent with other documents
- [ ] INDEX.md is updated if needed

### Regular Maintenance
- [ ] Review annually for accuracy
- [ ] Update links quarterly
- [ ] Archive obsolete documents
- [ ] Consolidate duplicate information
- [ ] Update examples with current syntax

## Templates

### New Document Template
```markdown
# Document Title

Brief overview of what this document covers.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Main Section](#main-section)
- [Related Documentation](#related-documentation)

## Overview
Detailed description of the topic.

## Prerequisites
What the reader needs before following this guide.

## Main Section
The core content with examples.

## Related Documentation
- [Related Guide 1](../category/guide1.md)
- [Related Guide 2](../category/guide2.md)

---
*Created: YYYY-MM-DD | Updated: YYYY-MM-DD*
```

### Command Reference Template
```markdown
# Command Name

## Synopsis
```bash
eos command [options] [arguments]
```

## Description
What the command does and when to use it.

## Options
- `--option`: Description of option
- `--flag`: Description of flag

## Examples
```bash
# Example 1
eos command --option value

# Example 2 with explanation
eos command --flag  # This does something specific
```

## See Also
- Related commands
- Configuration files
```

## Implementation

### Migration Plan
1. **Phase 1**: Apply standards to new documents
2. **Phase 2**: Update existing high-priority documents
3. **Phase 3**: Systematic review of all documentation
4. **Phase 4**: Implement automated validation

### Automation Opportunities
- Link checking scripts
- Template validation
- Style guide enforcement
- INDEX.md generation
- Orphaned file detection

## Enforcement

### Pre-commit Hooks
Consider implementing checks for:
- Filename conventions
- Required sections
- Link validity
- Template compliance

### Review Process
- All documentation changes require review
- Technical accuracy verification required
- Style compliance checking
- Cross-reference validation

This standard ensures Eos documentation remains high-quality, navigable, and maintainable as the project grows.