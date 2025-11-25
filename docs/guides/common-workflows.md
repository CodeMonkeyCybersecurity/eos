# Common Workflows

Quick recipes for everyday Eos usage. Adapt service names to your environment and host roles.

## Bootstrap the control plane
```bash
eos create vault
eos create consul
eos create nomad
```
- Apply SSH hardening per host role (see `security/` docs) before exposing services.
- Store generated secrets in Vault; prefer short-lived tokens for automation.

## Deploy platform and storage
```bash
eos create ceph      # Distributed storage
# K3s and KVM helpers are service-specific; add commands here as they are wired.
```

## Manage services safely
```bash
# Detect and remediate drift
eos update vault --fix
eos update consul --fix
eos update ceph --fix

# Review current state
eos list services
eos read <service>
```

## Backups and recovery
```bash
eos backup <service>
eos restore <service> --from <artifact>
```
- Capture ADRs for backup destinations, retention, and encryption choices.

## Diagnostics
```bash
eos debug vault
eos debug consul
eos debug ceph
```
- Evidence is stored in `~/.eos/debug/` to aid post-incident analysis.

## Upgrades and maintenance
- Pull latest code and rerun `./install.sh`.
- Reapply `update --fix` flows after OS or package upgrades to reassert hardening.
- Revisit ADRs when changing service roles or introducing new dependencies.
