# docs/STACK.md

## Caddy 
- as a reverse proxy for http/s traffic 


## Nginx 
- to be used alongside Caddy for non-http/s traffic (eg.UDP, TCP, SMTP, IMAP, etc.)


## Authentik 
- as SSO provider to make Caddy identity aware as a reverse proxy


## Saltstack 
for orchestration commands (including backup and recovery, Terraform, etc)

## Terraform
instruments the hashicorp stack includes: 

### Nomad 
for container orchestration, 

### Vault 
with a file backend for secrets management, 
- only overlay CephFS behind S3 or postgres where positively indicated for to minimise the opportunity for circular dependencies and non-deterministic and/or cascading failures 
- deployed on base metal to fix bootstrapping issues with secrets management
- bare metal deployment isolates vault from frontend access by separating it from containerised appplications

### Consul 
for service discovery, 

### Boundary 
for zero trust control plane access

## Restic 
- for backup and recovery 

## Clusterfuzz 
for fuzzing of the eos tool (this codebase)

## Minio 
for S3 storage
- deployed in containers via nomad so it can be attached to applications


## Wazuh 
for XDR/SEIM (implemented in this stack as Delphi)

## Docker 
for containers

## PostgreSQL 
for databases
- gotchas include: when deployed alongside CephFS and MinIO can lead 
- deployed in containers via nomad so it can be attached to applications

## CephFS 
as a distributed file system
- deployed on base metal to fix bootstrapping issues and ensure performance by removing docker overhead 
- only overlay CephFS behind S3 or postgres where positively indicated for to minimise the opportunity for circular dependencies and non-deterministic and/or cascading failures 
- avoids this issue: CephFS needs to be available before Nomad can schedule persistent workloads, but CephFS itself might need to run as a Nomad job.


### Specific Recommendations: 
Implement a staged bootstrap approach where CephFS runs initially as a Docker container outside Nomad, then transitions to Nomad management once the cluster is stable. Create explicit health checks and waiting mechanisms in SaltStack to ensure each service layer is fully operational before starting dependent services.


## The "State Drift Horror Story"
SaltStack, Terraform, and Nomad all have their own idea of what "current state" means. When they disagree, you get into situations where your infrastructure appears healthy but is actually in an inconsistent state that will fail under load.

## Resource Contention Reality Check
Running this entire stack on a single machine creates resource contention patterns you won't see in distributed deployments. Let me paint the picture of what actually happens:
### Memory pressure cascade: 
Vault loads its entire dataset into memory. MinIO caches frequently accessed objects in memory. Nomad keeps metadata about all jobs in memory. When you hit memory pressure, the Linux OOM killer starts terminating processes, but it doesn't understand the dependency relationships between your services. It might kill Vault first, which causes MinIO to lose authentication, which causes Nomad jobs to fail health checks, which triggers restart loops that consume even more memory.
I/O contention nightmares: All your services are writing to the same disk. Vault's frequent fsync operations (for security) will block MinIO's large file operations. MinIO's data writes will cause Vault's small metadata updates to queue up. Meanwhile, Nomad is trying to write job logs and state updates. The result is that all your services become I/O bound even though none of them individually would be I/O bound on a dedicated machine.