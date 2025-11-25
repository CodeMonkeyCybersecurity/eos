# Hardening Profiles

Role-based hardening aligned to ADR-0002 and the preferred infrastructure outline. Tailor each host to one of the roles below and document exceptions.

## Roles
- **Bastion/Gateway**: entry point for admins; MFA-capable, session logging, tight allowlists.
- **Control Plane**: Vault, Consul, Nomad nodes; minimal user access, short-lived machine credentials.
- **Platform/Compute**: K3s workers, KVM hosts; restrict SSH to ops group, enforce key-based auth.
- **Storage**: Ceph/ZFS nodes; service accounts only, strict network ACLs.
- **Workload/Service**: app hosts (e.g., Hecate, Mattermost, Umami); deployer keys only, configuration managed by Eos.
- **Admin Workstations**: development endpoints; adhere to org MFA/policy and avoid storing long-lived secrets.

## Profile template
- Authentication: keys only vs. MFA + keys; allowed users/groups.
- Network: allowed source CIDRs; listen interfaces; port changes if any.
- SSH settings: KEX/ciphers/MACs, MaxAuthTries, LoginGraceTime, AllowTcpForwarding, agent forwarding.
- Logging: session recording or auditd configuration; forwarding to Wazuh/central SIEM.
- Updates: patch cadence, package pinning, kernel/LTS policies.
- Break-glass: documented procedure, time-limited access, and audit trail.

## Actions
- Map every host to a role and note deviations here.
- Reflect final settings in `ssh-configuration.md` and encode them in automation.
- Capture new decisions in an ADR when changing defaults or introducing exceptions.
