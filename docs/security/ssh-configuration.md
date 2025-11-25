# SSH Configuration

Baseline SSH settings to support the role-based hardening profiles (see [hardening-profiles.md](hardening-profiles.md)) and ADR-0002.

## Defaults to apply (validate per OS release)
- Protocol: SSHv2 only; disable legacy options.
- Authentication: prefer key-based; disable password auth where automation allows; enable MFA on bastions.
- Host keys: strong key types (ed25519, rsa-sha2-512/256); rotate on schedule.
- KEX/Ciphers/MACs: limit to modern algorithms; document the exact list per release in this file.
- Login controls: set `MaxAuthTries`, `LoginGraceTime`, `ClientAliveInterval`, `ClientAliveCountMax` to reduce lingered sessions.
- Forwarding: disable agent and TCP forwarding by default; enable only where required and audited.
- Banner/consent: display authorized use banners and maintenance windows when needed.

## Role-specific notes
- **Bastion/Gateway**: enforce MFA-capable flows, record sessions, and restrict to admin groups.
- **Control Plane**: allow only automation identities and minimal ops group; prefer short-lived certificates/tokens.
- **Platform/Compute**: limit to deployer group; ensure cgroup/resource isolation is not bypassed via SSH.
- **Storage**: restrict to service accounts; disable port forwarding; enable verbose audit logging.
- **Workload/Service**: permit only deployment automation; align with reverse-proxy and app-level auth.

## Testing and rollout
- Validate config with `sshd -t` before reload; apply via automation not manual edits.
- Stage changes on non-production hosts; monitor Wazuh/telemetry for auth failures.
- Document exceptions and rationale in ADRs and per-host notes.
