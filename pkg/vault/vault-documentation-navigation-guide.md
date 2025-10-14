# EOS Vault Documentation Navigation Guide

## Visual Document Relationship

```
                        START HERE
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │  WHAT ARE YOU TRYING TO DO?           │
        └────────────────┬───────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    
  ┌──────────┐    ┌──────────┐    ┌──────────┐
  │  Learn   │    │  Plan    │    │ Implement│
  │  Vault   │    │Deployment│    │  Vault   │
  └────┬─────┘    └────┬─────┘    └────┬─────┘
       │               │                │
       ▼               ▼                ▼
       
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│Architecture   │ │Decision Tree  │ │Implementation │
│Comparison     │ │Document       │ │Checklist      │
│               │ │               │ │               │
│raft-vs-file-  │ │eos-raft-      │ │eos-raft-      │
│architecture.md│ │decision-      │ │implementation-│
│               │ │tree.md        │ │checklist.md   │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        │                 ▼                 │
        │          ┌─────────────┐          │
        └─────────>│ Integration │<─────────┘
                   │ Guide       │
                   │             │
                   │eos-raft-    │
                   │integration- │
                   │guide.md     │
                   └──────┬──────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Main        │
                   │Specification│
                   │             │
                   │vault-       │
                   │complete-    │
                   │spec-v1.0.md │
                   └─────────────┘
                          │
                          ▼
                     REFERENCE
                     ALL THE TIME
```

---

## Decision Flow: Which Document Do I Need?

```
START: What is your role and goal?
│
├─ "I'm NEW to Vault and need to understand the basics"
│  └─> READ: raft-vs-file-architecture.md
│      ├─ Visual diagrams explain the concepts
│      ├─ Shows how Raft consensus works
│      └─ Compares file storage vs Raft
│      
│      THEN: vault-complete-specification.md (Quick Start section)
│
├─ "I'm an ARCHITECT planning a deployment"
│  └─> READ: eos-raft-decision-tree.md
│      ├─ How many nodes? (1/3/5)
│      ├─ Which unseal method? (manual/AWS/Azure/GCP)
│      ├─ Load balancer strategy?
│      ├─ Backup approach?
│      └─ Monitoring solution?
│      
│      THEN: vault-complete-specification.md (relevant sections)
│      THEN: eos-raft-integration-guide.md (technical details)
│
├─ "I'm a DEVOPS ENGINEER implementing Vault"
│  └─> READ: eos-raft-implementation-checklist.md
│      ├─ Phase-by-phase instructions
│      ├─ Exact commands to run
│      ├─ Verification steps
│      └─ Time estimates
│      
│      REFER TO: vault-complete-specification.md (for details)
│      REFER TO: eos-raft-integration-guide.md (if stuck)
│
├─ "I'm a DEVELOPER integrating Raft into EOS codebase"
│  └─> READ: eos-raft-integration-guide.md
│      ├─ Configuration changes needed
│      ├─ Code modifications required
│      ├─ Testing strategies
│      └─ EOS CLI changes
│      
│      REFER TO: vault-complete-specification.md (config examples)
│      REFER TO: eos-raft-decision-tree.md (understand options)
│
├─ "I'm TROUBLESHOOTING a production issue"
│  └─> GO TO: vault-complete-specification.md
│      └─ Troubleshooting section
│          ├─ Find your symptom
│          ├─ Follow diagnostic steps
│          └─ Apply fixes
│          
│          IF NEEDED: eos-raft-integration-guide.md (technical depth)
│
└─ "I'm MIGRATING from file storage to Raft"
   └─> READ: vault-complete-specification.md
       └─ Migration section
           ├─ Export procedure
           ├─ Installation steps
           ├─ Import procedure
           └─ Verification
           
           REFER TO: eos-raft-implementation-checklist.md (detailed steps)
```

---

## Document Usage Matrix

| Document | Learning | Planning | Implementing | Troubleshooting | Reference |
|----------|----------|----------|--------------|-----------------|-----------|
| **vault-complete-specification.md** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **eos-raft-decision-tree.md** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐ |
| **eos-raft-implementation-checklist.md** | ⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐⭐ |
| **eos-raft-integration-guide.md** | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **raft-vs-file-architecture.md** | ⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐ | ⭐⭐ |

⭐⭐⭐ = Essential for this use case  
⭐⭐ = Very helpful  
⭐ = Optional/reference

---

## Workflow Examples

### Workflow 1: First Production Deployment

```
Day 1-2: PLANNING PHASE
┌─────────────────────────────────────┐
│ 1. Read decision tree               │ eos-raft-decision-tree.md
│    - Decide: 5 nodes across 3 AZs   │
│    - Decide: AWS KMS auto-unseal     │
│    - Decide: AWS ALB load balancer   │
│    - Decide: Daily S3 backups        │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 2. Review main specification        │ vault-complete-specification.md
│    - Read production quick start    │ (sections relevant to decisions)
│    - Read auto-unseal section       │
│    - Read load balancer section     │
│    - Read monitoring section         │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 3. Review integration guide         │ eos-raft-integration-guide.md
│    - Understand technical details   │
│    - Note EOS-specific requirements │
└─────────────────────────────────────┘

Week 1-2: IMPLEMENTATION PHASE
┌─────────────────────────────────────┐
│ 4. Follow implementation checklist  │ eos-raft-implementation-checklist.md
│    Phase 1: Planning (2-4h)         │ + vault-complete-specification.md
│    Phase 2: Infrastructure (1-2h)   │ (for detailed commands)
│    Phase 3: TLS Certs (1-2h)        │
│    Phase 4: Installation (30m)      │
│    Phase 5: Initialization (1-2h)   │
│    Phase 6: Load Balancer (1-2h)    │
│    Phase 7: Backup Config (30-60m)  │
│    Phase 8: Monitoring (2-4h)       │
│    Phase 9: Hardening (2-4h)        │
│    Phase 10: Testing (2-4h)         │
│    Phase 11: Documentation (2-3h)   │
│    Phase 12: Go-Live (1-2h)         │
└─────────────────────────────────────┘
                │
                ▼
        PRODUCTION RUNNING
```

**Total Time:** 16-24 hours of work spread over 2-3 weeks

---

### Workflow 2: Quick Development Setup

```
Day 1: RAPID DEPLOYMENT
┌─────────────────────────────────────┐
│ 1. Go directly to quick start       │ vault-complete-specification.md
│    Read: "Quick Start: Development" │ (single-node section)
│                                     │
│    Skip decision tree (dev is clear)│
│    Skip checklist (too detailed)    │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 2. Run commands from quick start    │
│    - Install Vault (5 min)          │
│    - Create config (2 min)          │
│    - Initialize (3 min)             │
│    - Test (5 min)                   │
└─────────────────────────────────────┘
                │
                ▼
        VAULT RUNNING IN DEV
```

**Total Time:** 15-30 minutes

---

### Workflow 3: Understanding Why Raft Matters

```
LEARNING PHASE
┌─────────────────────────────────────┐
│ 1. Read architecture comparison     │ raft-vs-file-architecture.md
│    - Visual diagrams                │
│    - How Raft works                 │
│    - Why file storage is limited    │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 2. Read decision tree introduction  │ eos-raft-decision-tree.md
│    - Understand cluster sizes       │
│    - See failure tolerance math     │
│    - Review use cases               │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 3. Review main spec storage section │ vault-complete-specification.md
│    - Official HashiCorp guidance    │
│    - Production requirements        │
│    - Evidence-based recommendations │
└─────────────────────────────────────┘
                │
                ▼
     NOW READY TO ADVOCATE FOR RAFT
```

**Total Time:** 2-3 hours of reading

---

### Workflow 4: Integrating Raft into EOS Code

```
DEVELOPMENT PHASE
┌─────────────────────────────────────┐
│ 1. Understand architecture          │ raft-vs-file-architecture.md
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 2. Review integration requirements  │ eos-raft-integration-guide.md
│    - Configuration changes needed   │
│    - Port requirements              │
│    - TLS certificate requirements   │
│    - Code changes in EOS            │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 3. Reference config examples        │ vault-complete-specification.md
│    - Single node template           │
│    - Multi-node template            │
│    - Auto-unseal config             │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 4. Test using checklist             │ eos-raft-implementation-checklist.md
│    - Phase 10: Testing procedures   │
│    - Verify all scenarios           │
└─────────────────────────────────────┘
```

**Total Time:** 1-2 weeks development + testing

---

## Quick Reference: Where to Find Things

### Configuration Examples
**Primary:** vault-complete-specification.md (Configuration Templates section)  
**Also in:** eos-raft-integration-guide.md

### Commands to Run
**Primary:** eos-raft-implementation-checklist.md  
**Reference:** vault-complete-specification.md (Quick Reference Commands)

### Decision Guidance
**Primary:** eos-raft-decision-tree.md  
**Supporting:** vault-complete-specification.md (Production Deployment section)

### Troubleshooting
**Primary:** vault-complete-specification.md (Troubleshooting section)  
**Deep Dive:** eos-raft-integration-guide.md (Part 8: Testing Strategy)

### Migration Procedures
**Primary:** vault-complete-specification.md (Migration section)  
**Technical Details:** eos-raft-integration-guide.md (Part 7: Migration)

### Architecture Explanation
**Primary:** raft-vs-file-architecture.md  
**Official Guidance:** vault-complete-specification.md (Storage Backends section)

### Security Hardening
**Primary:** vault-complete-specification.md (Security Hardening Checklist)  
**Implementation:** eos-raft-implementation-checklist.md (Phase 9)

### Monitoring Setup
**Primary:** vault-complete-specification.md (Monitoring section)  
**Implementation:** eos-raft-implementation-checklist.md (Phase 8)

---

## Document Reading Order by Scenario

### Scenario: "I'm completely new to Vault and Raft"

**Order:**
1. raft-vs-file-architecture.md (1 hour)
2. vault-complete-specification.md - Quick Start: Development (30 min)
3. vault-complete-specification.md - Storage Backends section (30 min)
4. eos-raft-decision-tree.md - Deployment size decisions (30 min)

**Total:** 2.5 hours to get up to speed

---

### Scenario: "I need to deploy to production ASAP"

**Order:**
1. eos-raft-decision-tree.md (1 hour - make all decisions)
2. vault-complete-specification.md - Production quick start (30 min - overview)
3. eos-raft-implementation-checklist.md (follow phase by phase) (16-24 hours)
4. vault-complete-specification.md (reference as needed during implementation)

**Total:** 18-26 hours

---

### Scenario: "I need to justify Raft to management"

**Order:**
1. vault-complete-specification.md - CRITICAL section (10 min)
2. raft-vs-file-architecture.md (30 min - visual justification)
3. vault-complete-specification.md - Storage Backends Comparison (20 min)
4. eos-raft-decision-tree.md - Production recommendations (20 min)

**Total:** 1.5 hours + create presentation

---

### Scenario: "I'm migrating from file to Raft"

**Order:**
1. vault-complete-specification.md - Migration section (30 min - read thoroughly)
2. eos-raft-decision-tree.md (30 min - decide on target architecture)
3. eos-raft-implementation-checklist.md - Phase 14 (1 hour - plan migration)
4. vault-complete-specification.md - Migration procedure (4-8 hours - execute)

**Total:** 6-10 hours

---

## Common Questions → Document Answers

| Question | Go To | Section |
|----------|-------|---------|
| "Why not use file storage?" | vault-complete-specification.md | Storage Backends Comparison |
| "How many nodes do I need?" | eos-raft-decision-tree.md | Deployment Size Decision |
| "How do I initialize a cluster?" | eos-raft-implementation-checklist.md | Phase 5 |
| "What ports need to be open?" | vault-complete-specification.md | Port Reference |
| "How do I set up auto-unseal?" | vault-complete-specification.md | Auto-Unseal Setup |
| "What's the difference between Raft and file?" | raft-vs-file-architecture.md | Entire document |
| "How do I backup Vault?" | vault-complete-specification.md | Backup and Restore |
| "What if I lose quorum?" | vault-complete-specification.md | Disaster Recovery Scenarios |
| "How do I monitor Vault?" | vault-complete-specification.md | Monitoring and Health Checks |
| "How do I troubleshoot cluster issues?" | vault-complete-specification.md | Troubleshooting |
| "What changes are needed in EOS?" | eos-raft-integration-guide.md | Part 10: Code Changes |
| "How long will implementation take?" | eos-raft-implementation-checklist.md | Phase time estimates |

---

## Print/Share Recommendations

### For Management/Executives
**Print:** 
- vault-complete-specification.md - CRITICAL section + Storage Backends
- raft-vs-file-architecture.md - Architecture diagrams

**Length:** 5 pages

---

### For Architects
**Print:** 
- eos-raft-decision-tree.md (entire document)
- vault-complete-specification.md - Production Deployment section

**Length:** 15 pages

---

### For Implementation Engineers
**Print:** 
- eos-raft-implementation-checklist.md (entire document)
- vault-complete-specification.md - Quick Reference section

**Length:** 55 pages

---

### For Developers
**Print:** 
- eos-raft-integration-guide.md (entire document)
- vault-complete-specification.md - Configuration Templates section

**Length:** 65 pages

---

## Digital vs Print Usage

### Use Digital For:
- Implementation (need to copy/paste commands)
- Reference (search functionality)
- Updates (documents will be updated)
- Links (cross-references between docs)

### Print For:
- Planning meetings (easier to annotate)
- DR procedures (if systems are down)
- Training (easier to follow along)
- Approval processes (easier to review)

---

## Version Control and Updates

| Document | Update Frequency | Reason |
|----------|------------------|--------|
| vault-complete-specification.md | Quarterly | Vault version updates |
| eos-raft-decision-tree.md | Annually | Stable decision logic |
| eos-raft-implementation-checklist.md | Quarterly | Process improvements |
| eos-raft-integration-guide.md | As needed | EOS code changes |
| raft-vs-file-architecture.md | Stable | Architecture is stable |

**Check for updates:** Before starting new production deployment

---

## Getting Help

### If Documents Don't Answer Your Question:

1. **Check all 5 documents** - answer might be in different doc
2. **Use search** (Ctrl+F) - look for keywords
3. **Check appendices** - often have detailed info
4. **Review examples** - might show what you need
5. **Ask team** - someone may have done it before

### If Still Stuck:

- **HashiCorp Docs:** https://developer.hashicorp.com/vault/docs
- **Community Forum:** https://discuss.hashicorp.com/c/vault
- **Internal Team:** #eos-vault Slack channel

---

## Key Takeaways

 **5 documents work together** - each has specific purpose  
 **Main spec is hub** - central reference for everything  
 **Decision tree before planning** - make informed choices  
 **Checklist during implementation** - step-by-step guidance  
 **Integration guide for developers** - code-level details  
 **Architecture doc for learning** - understand concepts

**Start with your goal, find the right document, follow the workflow.**

---

**Document Version:** 1.0  
**Created:** October 13, 2025  
**Maintained By:** Code Monkey Cybersecurity - EOS Team