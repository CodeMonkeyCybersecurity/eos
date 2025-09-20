# STACK.md - Infrastructure Architecture Documentation

*Last Updated: 2025-01-14*

## Table of Contents

1. [Architectural Decisions Declaration](#1-architectural-decisions-declaration)
   - 1.1 [Infrastructure Stack Overview](#11-infrastructure-stack-overview)
   - 1.2 [Core Architectural Patterns](#12-core-architectural-patterns)
   - 1.3 [Fundamental Design Principles](#13-fundamental-design-principles)

2. [Implementation Approaches and Foundational Assumptions](#2-implementation-approaches-and-foundational-assumptions)
   - 2.1 [Resource Management Strategy](#21-resource-management-strategy)
   - 2.2 [Bootstrap and Dependency Management](#22-bootstrap-and-dependency-management)
   - 2.3 [Configuration Generation Workflows](#23-configuration-generation-workflows)
   - 2.4 [Integration Patterns](#24-integration-patterns)

3. [Known Challenges and Operational Gotchas](#3-known-challenges-and-operational-gotchas)
   - 3.1 [State Management Challenges](#31-state-management-challenges)
   - 3.2 [Resource and Performance Gotchas](#32-resource-and-performance-gotchas)
   - 3.3 [Operational Complexity Challenges](#33-operational-complexity-challenges)
   - 3.4 [Integration and Boundary Issues](#34-integration-and-boundary-issues)
   - 3.5 [Failure Scenario Analysis](#35-failure-scenario-analysis)

4. [Validation, Monitoring, and Operational Verification](#4-validation-monitoring-and-operational-verification)
   - 4.1 [Testing Strategy Framework](#41-testing-strategy-framework)
   - 4.2 [Monitoring and Observability Requirements](#42-monitoring-and-observability-requirements)
   - 4.3 [Operational Procedures](#43-operational-procedures)
   - 4.4 [Validation Criteria](#44-validation-criteria)

## 1. Architectural Decisions Declaration

This section establishes the foundational architectural commitments that define our infrastructure approach. These decisions represent deliberate choices made after evaluating alternatives and considering the specific requirements of our environment.

### 1.1 Infrastructure Stack Overview

Our infrastructure architecture combines multiple deployment strategies and orchestration tools to create a sophisticated system that matches deployment approaches to service characteristics. We will implement a hybrid infrastructure that leverages both bare metal deployment for infrastructure services and containerization for application workloads.

**Infrastructure Services (Bare Metal Deployment):**
- **CephFS**: Distributed file system providing optional robust storage capabilities. We deploy CephFS on bare metal via apt repository installation to maximize I/O performance and eliminate container runtime overhead for storage operations.
- **Vault**: Secrets management using file backend for bootstrap simplicity. Bare metal deployment ensures minimal attack surface and eliminates dependency on container orchestration for critical security operations.

**Orchestration and Management Services:**
- ****: Primary orchestrator and single source of truth for all configuration management.  serves as the authoritative system for policy enforcement and high-level operational procedures.
- **Terraform**: Infrastructure mediation layer that translates 's declarative intentions into specific resource provisioning. Terraform provides the critical translation between configuration management and infrastructure orchestration.
- **Nomad**: Container orchestration platform operating within Terraform-defined boundaries. Nomad handles dynamic workload scheduling and container lifecycle management.

**Supporting Infrastructure:**
- **Consul**: Service discovery and configuration coordination across the entire stack.
- **Boundary**: Zero trust access control for infrastructure management.

**Network and Proxy Layer:**
- **Caddy**: Reverse proxy handling HTTP/HTTPS traffic with automatic SSL certificate management.
- **Nginx**: Complementary proxy for non-HTTP protocols including UDP, TCP, SMTP, and IMAP traffic.
- **Authentik**: SSO provider enabling identity-aware proxy operations across both Caddy and Nginx.

**Application Services (Containerized Deployment):**
- **MinIO**: S3-compatible object storage deployed per application for isolation and specific optimization.
- **PostgreSQL**: Relational database deployed per application to provide dedicated resources and configuration flexibility.

**Security and Monitoring:**
- **Wazuh**: XDR/SIEM implementation (deployed as "Delphi") for comprehensive security monitoring.
- **ClusterFuzz**: Security testing infrastructure for continuous vulnerability assessment.

**Runtime and Backup:**
- **Docker**: Container runtime providing the foundation for all containerized services.
- **Restic**: Backup and recovery system coordinating across multiple storage backends.

### 1.2 Core Architectural Patterns

#### Orchestration Hierarchy

We will implement a three-tier orchestration hierarchy:  → Terraform → Nomad. This mediation pattern was chosen over direct integration because it solves the fundamental tension between declarative configuration management and dynamic container orchestration.

 excels at expressing "this is what the system should look like" through declarative states, while Nomad excels at making real-time decisions about workload placement and resource optimization. Terraform serves as the critical translation layer that maintains state consistency between these two paradigms. When  determines that an application should have certain characteristics, it generates Terraform configuration that creates appropriate Nomad job specifications. Terraform then applies this configuration and maintains ongoing state reconciliation between declared intentions and operational reality.

This approach provides several key benefits over direct integration alternatives. First, it leverages each tool's core strengths rather than forcing any single tool to handle responsibilities outside its design scope. Second, it provides clear separation of concerns where  owns policy and high-level configuration, Terraform owns infrastructure state management, and Nomad owns workload orchestration. Third, it creates a systematic approach to handling configuration drift across multiple management layers.

#### Deployment Strategy Matrix

We will match deployment strategies to service characteristics based on performance, security, and operational requirements:

**Bare Metal Services:**
- **CephFS**: Requires direct hardware access for optimal I/O performance and cache management. Container overhead would significantly impact storage performance.
- **Vault**: Benefits from bare metal deployment for security isolation and elimination of container runtime attack surface. File backend choice further simplifies bootstrap dependencies.

**Containerized Services:**
- **MinIO**: Application-specific deployment provides isolation and allows optimization for specific workload patterns. Container deployment enables easy scaling and resource management.
- **PostgreSQL**: Per-application deployment prevents cross-application data leakage and allows database-specific tuning. Containerization provides deployment flexibility and resource isolation.

This hybrid approach acknowledges that different services have different operational characteristics that benefit from different deployment strategies, rather than forcing all services into a single deployment model.

#### Network Architecture

We will implement a dual proxy architecture using both Caddy and Nginx to provide comprehensive protocol coverage. This design was chosen as an intentional compromise that maximizes protocol support while maintaining operational manageability.

Caddy handles HTTP/HTTPS traffic and provides automatic SSL certificate management, eliminating the operational overhead of certificate lifecycle management. Nginx handles non-HTTP traffic including UDP, TCP, SMTP, and IMAP protocols that Caddy cannot process. Authentik provides centralized authentication for both proxy layers, ensuring consistent security policies across all traffic types.

This dual proxy approach creates some additional configuration complexity but provides significantly broader protocol coverage than either proxy could provide individually. The trade-off is justified because attempting to force all traffic through a single proxy would require either accepting limited protocol support or implementing complex protocol translation layers.

#### Storage Architecture

We will implement a multi-storage approach using CephFS, MinIO, and PostgreSQL, with each storage system serving distinct purposes and workload characteristics.

**CephFS** provides distributed file system capabilities for applications requiring shared file storage with high availability. CephFS deployment is optional rather than mandatory, allowing applications to choose local storage when distributed storage benefits don't justify the additional complexity.

**MinIO** provides S3-compatible object storage for applications requiring blob storage capabilities. Per-application deployment ensures isolation and enables workload-specific optimization.

**PostgreSQL** provides relational database capabilities for applications requiring structured data storage with ACID properties. Application-specific deployment prevents data leakage and allows database tuning for specific workload patterns.

This multi-storage approach acknowledges that different applications have fundamentally different storage requirements that cannot be efficiently served by a single storage solution.

### 1.3 Fundamental Design Principles

#### Separation of Concerns

Our architecture maintains clear boundaries between configuration management, infrastructure provisioning, and workload orchestration.  owns high-level policy and configuration decisions. Terraform owns infrastructure state management and resource provisioning. Nomad owns container scheduling and lifecycle management. This separation prevents any single tool from becoming overly complex while ensuring that each tool operates within its core competency area.

#### State Management Philosophy

We will maintain state consistency across multiple management layers through systematic reconciliation and validation procedures.  provides the authoritative source for desired configuration state. Terraform maintains infrastructure state and handles drift detection between desired and actual resource configurations. Nomad maintains runtime state for active workloads. Regular validation procedures ensure that all three state representations remain consistent with each other and with operational reality.

#### Security-by-Design

Security considerations influence architectural choices at every level. Vault's bare metal deployment eliminates container runtime attack surface for critical secrets management. Authentik provides centralized authentication that creates a single point of control for access policies. Boundary implements zero trust principles for infrastructure access. Wazuh provides comprehensive monitoring for security events across all infrastructure layers.

#### Operational Simplicity

We manage complexity through tool composition rather than tool replacement. Instead of attempting to force any single tool to handle all operational requirements, we combine well-designed tools that each excel in specific areas. This approach creates architectural complexity in the integration points between tools, but it avoids the operational complexity that emerges when tools are pushed beyond their design limitations.

## 2. Implementation Approaches and Foundational Assumptions

This section documents the practical implementation strategies that make our sophisticated architecture workable in real environments. These approaches acknowledge the constraints and opportunities of our specific deployment context.

### 2.1 Resource Management Strategy

#### Hardware Assumptions

Our resource management strategy is designed around abundant hardware availability, with backend machines providing 96GB+ DDR4 or 200GB+ DDR3 RAM and several TB of SSD storage per machine. This abundance creates unique opportunities and challenges that differ significantly from resource-constrained deployments.

The abundant memory enables aggressive caching strategies for both CephFS and application services, but it also requires careful management to prevent services from competing for cache space or creating memory exhaustion scenarios. With substantial memory available, services like PostgreSQL and CephFS will attempt to cache large portions of their working sets, which provides excellent performance until aggregate memory usage approaches system limits.

The substantial SSD storage enables high-performance I/O for multiple concurrent workloads, but it requires careful partitioning to prevent I/O interference between different storage systems. We will partition storage I/O workloads by dedicating specific storage devices or partitions to different usage patterns to minimize contention.

#### Resource Allocation Patterns

We will implement explicit resource reservations that account for both bare metal services and containerized workloads running on the same infrastructure. Bare metal services like CephFS and Vault will have reserved memory and CPU allocations that are excluded from container resource pools. Container resource limits will account for bare metal service resource usage to prevent overcommitment scenarios.

Memory allocation follows a hierarchical approach where system operations receive first priority, bare metal infrastructure services receive second priority, and containerized application workloads receive remaining resources. This hierarchy ensures that infrastructure services maintain stable performance even when application workloads experience usage spikes.

#### Contention Prevention

We will implement monitoring and alerting that detects resource contention before it causes performance degradation. Memory usage monitoring includes both system-level metrics and per-service metrics that can identify when cache competition is affecting performance. I/O monitoring tracks both throughput and latency across different storage systems to detect interference patterns.

CPU scheduling uses processor affinity where possible to reduce cache pollution between bare metal and containerized workloads. Network bandwidth monitoring ensures that distributed storage operations don't interfere with application network traffic.

### 2.2 Bootstrap and Dependency Management

#### Startup Sequence

Our bootstrap sequence follows a carefully orchestrated order that respects service dependencies while minimizing startup time:

1. **System Infrastructure**: Host OS, networking, and base security configurations
2. **Bare Metal Services**: CephFS and Vault deployment and initialization
3. **Orchestration Platform**: Consul, Nomad agent startup and cluster formation
4. **Infrastructure Validation**: Health checks confirming all infrastructure services are operational
5. **Application Services**: MinIO and PostgreSQL deployment through Nomad
6. **Application Workloads**: Business application deployment
7. **Proxy and Authentication**: Caddy, Nginx, and Authentik configuration and activation

Each phase includes explicit wait conditions and health checks that prevent the next phase from starting until the current phase is fully operational. This prevents cascade failures that can occur when services start before their dependencies are ready.

#### Dependency Resolution

We avoid circular dependencies through careful service design and staged initialization. Vault uses a file backend specifically to avoid dependency on distributed storage during bootstrap. CephFS provides optional rather than required storage capabilities, allowing the system to operate without distributed storage during initial deployment.

The  → Terraform → Nomad orchestration chain creates a unidirectional dependency flow that prevents circular dependencies in the management layer.  generates Terraform configurations based on static  data. Terraform provisions resources based on these configurations. Nomad schedules workloads based on Terraform-created job specifications.

#### Recovery Procedures

Individual component restart procedures are designed to minimize impact on running services. Vault restart requires manual unseal operations but doesn't affect running applications that have already retrieved their secrets. CephFS restart may cause temporary storage unavailability but doesn't affect applications using local or MinIO storage. Nomad restart triggers workload rescheduling but maintains application availability through rolling restart procedures.

Complete system recovery follows the same startup sequence but includes additional validation steps to ensure that persistent data remains consistent across the restart. Database integrity checks validate PostgreSQL data consistency. Storage system checks validate CephFS and MinIO data integrity. Configuration validation ensures that , Terraform, and Nomad state representations remain consistent.

### 2.3 Configuration Generation Workflows

####  to Terraform Translation

 generates Terraform configurations using Jinja2 templating that transforms high-level application requirements into specific infrastructure resource specifications.   data contains application-level configuration including resource requirements, networking specifications, and storage needs. Template files convert this data into appropriate Terraform HCL configurations that create corresponding Nomad jobs and supporting infrastructure.

The templating process includes validation steps that ensure generated Terraform configurations are syntactically correct and operationally consistent. Variable files provide parameterization that allows the same Terraform templates to be used across different environments and application types.

#### State Coordination Mechanisms

State consistency across , Terraform, and Nomad requires systematic synchronization and validation procedures.  maintains authoritative configuration state in  data and state execution results. Terraform maintains infrastructure state in state files that track provisioned resources and their configurations. Nomad maintains runtime state about job allocations and workload health.

Regular reconciliation procedures compare state across all three systems and alert when inconsistencies are detected.  states include validation steps that query Terraform state and Nomad status to ensure that intended configurations match operational reality. Terraform refresh cycles detect when Nomad resources have changed outside of Terraform control. Nomad health checks provide feedback about workload operational status that informs higher-level configuration decisions.

#### Change Propagation

Configuration changes flow through the orchestration hierarchy in a controlled manner that prevents partial applications and ensures consistency.   data changes trigger Terraform configuration regeneration and validation. Terraform plan operations show exactly what infrastructure changes will result from configuration updates. Terraform apply operations implement changes in a way that respects resource dependencies and minimizes service disruption.

Emergency change procedures allow bypassing parts of the normal workflow when rapid response is required, but these procedures include reconciliation steps that ensure temporary changes are properly integrated into the normal configuration management workflow.

### 2.4 Integration Patterns

#### Network Boundary Management

Communication between bare metal and containerized services requires careful network configuration that bridges different network namespaces while maintaining security boundaries. Bare metal services bind to host network interfaces that are accessible to containerized services through Nomad's host networking capabilities. Service discovery through Consul provides consistent naming and endpoint discovery across deployment boundaries.

Network security policies ensure that cross-boundary communication uses authenticated and encrypted channels where appropriate. Firewall rules restrict access to bare metal service endpoints to authorized container networks. Network monitoring tracks communication patterns between deployment types to detect security issues or performance problems.

#### Storage Coordination

Applications choose between CephFS, local storage, and MinIO based on their specific requirements and performance characteristics. CephFS provides shared storage for applications requiring distributed file access. Local storage provides high-performance storage for applications that don't require sharing. MinIO provides object storage for applications requiring blob storage capabilities.

Storage provisioning procedures ensure that chosen storage backends are available before applications attempt to use them. Volume management coordinates between different storage systems to prevent conflicts and ensure appropriate resource allocation. Backup procedures coordinate across all storage backends to provide consistent data protection.

#### Authentication Flow Implementation

User authentication flows through a multi-step process that ensures consistent security policies across all services:

1. **Initial Authentication**: Users authenticate through Authentik using configured identity providers
2. **Token Generation**: Authentik generates authentication tokens that contain user identity and authorization information
3. **Proxy Validation**: Both Caddy and Nginx validate authentication tokens using Authentik's token validation endpoints
4. **Backend Authorization**: Backend services receive authenticated requests with user identity information for application-level authorization decisions

This flow ensures that authentication state remains consistent across both proxy layers and that backend services receive reliable identity information for authorization decisions.

#### Secret Distribution

Secrets flow from bare metal Vault to containerized applications through Nomad's Vault integration capabilities. Vault policies define which secrets are accessible to which services. Nomad job specifications include Vault policy references that enable automatic secret retrieval during container startup. Application containers receive secrets through environment variables or mounted files that are automatically populated by Nomad's Vault integration.

Secret rotation procedures ensure that updated secrets are automatically distributed to running applications without requiring manual intervention. Secret access logging provides audit trails for security compliance and incident investigation.

## 3. Known Challenges and Operational Gotchas

This section prepares operators for anticipated problems and provides strategies for handling them. Understanding these challenges before they occur enables proactive preparation and faster resolution when issues arise.

### 3.1 State Management Challenges

#### Multi-Layer Drift

Configuration drift manifests differently across our three management layers, creating complex scenarios where each layer may have a different understanding of the correct system state.  drift occurs when  data changes or state execution fails to complete successfully. Terraform drift occurs when infrastructure resources are modified outside of Terraform control. Nomad drift occurs when job specifications are manually modified or when autonomous rescheduling changes workload placement.

Detection strategies must account for the different types of drift that can occur at each layer.  state runs include validation steps that compare intended configuration with actual system state. Terraform refresh operations detect when managed resources differ from state file expectations. Nomad status monitoring identifies when job specifications or allocation patterns differ from management system expectations.

The most challenging drift scenarios occur when multiple layers drift simultaneously or when drift in one layer causes apparent drift in other layers. For example, manual changes to Nomad job specifications can make Terraform state appear inconsistent even though Terraform hasn't actually lost control of its resources.

#### Consistency Validation

Verifying that actual system state matches intended configuration across all three layers requires comprehensive validation procedures that can correlate information from different management systems. End-to-end validation procedures check that high-level application requirements specified in   data result in appropriate infrastructure resources in Terraform state and operational workloads in Nomad.

Cross-layer validation becomes particularly complex when dealing with dynamic systems like Nomad that make autonomous decisions about resource allocation. Validation procedures must distinguish between legitimate operational changes and actual configuration problems that require intervention.

#### Conflict Resolution

When different management layers disagree about desired system state, resolution procedures must determine which layer has authoritative information and how to restore consistency.  serves as the ultimate authority for high-level configuration decisions, but Terraform and Nomad may have more current information about infrastructure and runtime state.

Conflict resolution procedures include escalation paths that determine when manual intervention is required versus when automated reconciliation can resolve inconsistencies. Emergency procedures allow bypassing normal validation when rapid response is required, but these procedures include follow-up steps that ensure emergency changes are properly integrated into normal configuration management workflows.

### 3.2 Resource and Performance Gotchas

#### Memory Overcommitment Scenarios

Abundant memory creates a false sense of unlimited resources that can lead to sudden exhaustion when multiple services simultaneously expand their memory usage. CephFS cache expansion, PostgreSQL buffer pool growth, and application memory usage can combine to consume available memory faster than monitoring systems can detect and respond.

The most dangerous scenarios occur when memory exhaustion triggers the Linux OOM killer, which may terminate critical services based on memory usage patterns rather than service importance. OOM killer behavior can cascade through the system when terminated services restart and consume memory, potentially creating restart loops that prevent system recovery.

Prevention strategies include explicit memory reservations for critical services, monitoring that alerts before memory exhaustion occurs, and OOM killer configuration that protects essential services from termination.

#### I/O Contention Patterns

Multiple storage systems operating on shared infrastructure create I/O interference patterns that can significantly impact performance. Vault's frequent small synchronous writes can block large sequential operations from MinIO or CephFS. PostgreSQL write-ahead logging creates regular I/O spikes that interfere with other storage operations. CephFS replication traffic can saturate I/O bandwidth and affect other storage systems.

The most problematic contention occurs when multiple storage systems compete for the same underlying storage devices. SSD wear leveling algorithms can create unpredictable performance variations when multiple write-heavy workloads operate simultaneously.

Mitigation strategies include I/O partitioning across different storage devices, I/O priority configuration that ensures critical operations receive appropriate bandwidth, and monitoring that can detect I/O contention before it causes service degradation.

#### CPU Scheduling Conflicts

Bare metal services and containerized workloads compete for CPU resources through different scheduling mechanisms that may not coordinate effectively. Bare metal services can consume CPU resources that containerized workloads expect to be available. High-CPU containerized workloads can interfere with bare metal service performance through cache pollution and scheduling delays.

CephFS rebalancing operations can create sustained high-CPU usage that affects other services. PostgreSQL query processing can consume multiple CPU cores during complex operations. Background maintenance tasks can create unexpected CPU usage spikes that interfere with foreground operations.

Prevention strategies include CPU affinity configuration that reduces cache pollution between workload types, CPU resource reservations that ensure critical services receive necessary resources, and monitoring that can detect CPU contention and trigger workload rescheduling when appropriate.

### 3.3 Operational Complexity Challenges

#### Service Multiplication Problem

Application-specific deployment of MinIO and PostgreSQL creates operational overhead that grows exponentially with the number of applications. Each application deployment includes its own database instance, object storage, monitoring configuration, backup procedures, and maintenance schedules. Ten applications result in ten different PostgreSQL configurations, ten different backup schedules, and ten different upgrade procedures.

The complexity becomes particularly problematic when applications need to share data or when debugging issues that span multiple application deployments. Cross-application troubleshooting requires understanding multiple different configurations and deployment patterns.

Management strategies include standardized deployment templates that reduce configuration variation, shared operational procedures that work across multiple application deployments, and monitoring systems that can correlate issues across different application instances.

#### Cross-Boundary Debugging

Troubleshooting issues that span bare metal and containerized services requires different diagnostic tools and procedures for each deployment type. Network connectivity issues may manifest differently in bare metal versus containerized environments. Storage performance problems may require different diagnostic approaches depending on whether storage is provided by bare metal CephFS or containerized MinIO.

The most challenging debugging scenarios occur when symptoms appear in one deployment type but the root cause exists in another. Container networking issues may be caused by bare metal network configuration. Application performance problems may be caused by resource contention from bare metal services.

Debugging strategies include unified logging systems that correlate events across deployment boundaries, monitoring systems that provide visibility into interactions between deployment types, and diagnostic procedures that systematically examine both bare metal and containerized components.

#### Authentication Cascade Failures

Authentication failures can propagate through multiple proxy layers and create complex failure scenarios where the symptom location differs significantly from the problem location. Authentik failures affect both Caddy and Nginx, but the failure symptoms may manifest differently in each proxy. Backend service authentication failures may appear as proxy configuration problems.

Network connectivity issues between authentication components can create intermittent failures that are difficult to reproduce and diagnose. Load balancing and failover between authentication components can create inconsistent behavior where some requests succeed while others fail.

Prevention strategies include comprehensive authentication monitoring that tracks success and failure rates at each layer, health checks that can distinguish between different types of authentication failures, and fallback procedures that maintain service availability when authentication components experience problems.

### 3.4 Integration and Boundary Issues

#### Package Dependency Conflicts

Apt-installed services may require library versions that conflict with container runtime requirements. System package updates can change library versions in ways that affect containerized applications. Container base image updates can introduce dependencies that conflict with host system packages.

The most problematic conflicts occur when security updates require changes that affect both bare metal and containerized services simultaneously. Coordinating updates across deployment boundaries requires careful testing and potentially complex rollback procedures if incompatibilities are discovered.

Resolution strategies include isolated dependency management for different service types, comprehensive testing procedures that validate compatibility across deployment boundaries, and rollback procedures that can restore service operation when update conflicts occur.

#### Network Interface Conflicts

Bare metal services and container networking can compete for network interface resources or create routing conflicts. Service discovery may provide incorrect endpoint information when services are accessible through multiple network interfaces. Load balancing configuration may direct traffic to the wrong endpoints when network interface configuration changes.

Port conflicts can occur when bare metal services attempt to bind to ports that are also used by containerized services. Network configuration changes can affect service connectivity in ways that aren't immediately apparent but cause problems under specific traffic patterns.

Prevention strategies include systematic network configuration management that coordinates between bare metal and containerized services, monitoring that detects network configuration conflicts before they cause service failures, and testing procedures that validate network connectivity across all service types.

#### File Permission Coordination

Different deployment types may require different file ownership and permission patterns when accessing shared storage. Container user IDs may not match host system user IDs, creating permission conflicts when containers write to shared storage. File system permission changes can affect both bare metal and containerized services in different ways.

Backup and restore operations can modify file permissions in ways that affect service operation across deployment boundaries. Storage system maintenance may change ownership or permissions in ways that aren't immediately apparent but cause problems when services restart.

Management strategies include standardized file permission schemes that work across deployment types, permission monitoring that detects changes that could affect service operation, and restore procedures that correctly restore permissions for all service types.

### 3.5 Failure Scenario Analysis

#### Vault Failure Impact

When Vault becomes unavailable, running applications continue to operate with their current secrets, but new applications cannot retrieve secrets for initial startup. Secret rotation operations fail, potentially causing authentication failures when cached secrets expire. Service-to-service authentication may fail if services attempt to refresh authentication tokens.

**Detection Methods**: Vault health check failures, authentication failures in application logs, secret retrieval failures during container startup

**Recovery Procedures**: 
1. Identify Vault failure root cause (process failure, storage issues, network connectivity)
2. Restart Vault service and perform manual unseal if necessary
3. Validate that secret retrieval is working correctly
4. Restart any applications that failed to start due to secret retrieval failures
5. Monitor for authentication failures that may indicate expired secrets

**Prevention Strategies**: Vault clustering for high availability, regular backup of Vault data and unseal keys, monitoring of Vault performance and storage usage

#### Nomad Failure Impact

Nomad server failure prevents new job scheduling and job status updates, but running containers continue to operate normally. Container health monitoring and automatic restart capabilities are lost. Scaling operations and rolling updates cannot be performed. Service discovery registration may become stale if services restart without Nomad coordination.

**Detection Methods**: Nomad API unavailability, job status update failures, inability to schedule new workloads

**Recovery Procedures**:
1. Identify Nomad server failure cause and restart Nomad servers
2. Allow Nomad cluster to re-elect leader and synchronize state
3. Validate that job scheduling and status updates are working correctly
4. Check for any containers that may have failed during Nomad unavailability
5. Resume any paused deployment or scaling operations

**Prevention Strategies**: Nomad server clustering, regular backup of Nomad state, monitoring of Nomad cluster health and performance

#### CephFS Failure Impact

CephFS failure affects only applications specifically configured to use distributed storage, allowing other applications to continue operating with local or MinIO storage. Shared file access between applications is lost. Backup operations for CephFS-stored data fail.

**Detection Methods**: CephFS mount failures, file system I/O errors, CephFS cluster health alerts

**Recovery Procedures**:
1. Diagnose CephFS cluster health and identify failed components
2. Repair or replace failed CephFS components
3. Validate file system integrity and consistency
4. Remount CephFS on affected nodes
5. Verify that applications can access shared storage correctly

**Prevention Strategies**: CephFS redundancy configuration, regular file system consistency checks, monitoring of CephFS cluster health and performance

#### Authentication Layer Failure Impact

Authentik failure prevents new user authentication but doesn't affect users with valid authentication tokens. API access and service-to-service communication may continue if not dependent on user authentication. Administrative access to infrastructure may be lost if it depends on Authentik authentication.

**Detection Methods**: Authentication failures in proxy logs, Authentik health check failures, user reports of login failures

**Recovery Procedures**:
1. Identify Authentik failure cause and restart Authentik services
2. Validate that authentication provider connections are working
3. Test authentication flow through both Caddy and Nginx
4. Monitor for any cached authentication state that may need to be refreshed
5. Verify that emergency access procedures work if needed

**Prevention Strategies**: Authentik high availability configuration, emergency administrative access procedures, monitoring of authentication success rates and performance

## 4. Validation, Monitoring, and Operational Verification

This section defines comprehensive strategies for ensuring our architecture operates according to design intentions. These procedures provide confidence that the complexity we've introduced actually delivers the benefits we expect.

### 4.1 Testing Strategy Framework

#### Boundary Condition Testing

Chaos engineering approaches specifically target the interfaces between deployment types to validate that our hybrid architecture handles failure scenarios gracefully. Network partition testing validates that bare metal and containerized services can recover when connectivity is restored. Resource exhaustion testing ensures that resource contention between deployment types doesn't cause cascade failures.

Interface testing validates that authentication flows work correctly across proxy boundaries and that service discovery operates consistently between bare metal and containerized services. Load testing specifically exercises cross-boundary communication to ensure that performance characteristics remain acceptable under realistic usage patterns.

Storage boundary testing validates that applications can switch between storage backends when necessary and that backup procedures work correctly across all storage types. Configuration boundary testing ensures that changes in one management layer propagate correctly through the orchestration hierarchy.

#### Integration Testing

 → Terraform → Nomad workflow validation requires end-to-end testing that exercises the complete configuration generation and deployment pipeline. Test scenarios include configuration changes that affect multiple layers simultaneously, failure recovery scenarios that test state reconciliation across all three layers, and performance testing that validates the latency characteristics of the complete workflow.

Integration testing includes validation that emergency procedures work correctly when normal workflows need to be bypassed. Rollback testing ensures that configuration changes can be reversed without causing service disruption. Cross-environment testing validates that the same configuration management workflow works correctly across development, staging, and production environments.

Automated integration testing runs regularly to detect configuration drift or workflow problems before they affect production operations. Manual integration testing exercises complex scenarios that are difficult to automate but represent realistic operational challenges.

#### Load Testing

Simultaneous testing of all storage systems validates that I/O partitioning and resource management strategies prevent performance degradation when multiple storage systems operate under high load. Load testing scenarios include realistic application workloads that exercise CephFS, MinIO, and PostgreSQL simultaneously to identify resource contention issues.

Network load testing validates that proxy layer performance remains acceptable when handling realistic traffic volumes across both HTTP and non-HTTP protocols. Authentication load testing ensures that Authentik and proxy integration can handle expected user authentication rates without creating bottlenecks.

Memory and CPU load testing validates that resource allocation strategies prevent bare metal services from interfering with containerized workloads under high utilization. Storage load testing identifies the actual I/O performance characteristics of our multi-storage architecture under realistic workload patterns.

#### Disaster Recovery Testing

Multi-storage backup and recovery testing validates that Restic coordination works correctly across CephFS, MinIO, and PostgreSQL storage systems. Recovery testing includes scenarios where different storage systems fail at different times and validation that data consistency is maintained during recovery operations.

Complete system recovery testing validates that our bootstrap sequence works correctly when recovering from total system failure. Partial recovery testing ensures that individual component recovery doesn't disrupt other system components. Cross-boundary recovery testing validates that recovery procedures work correctly when failures span bare metal and containerized services.

Backup validation includes regular testing of restore procedures to ensure that backup data remains usable and that recovery procedures are correctly documented and practiced. Recovery time measurement provides baseline data for setting realistic recovery time objectives.

### 4.2 Monitoring and Observability Requirements

#### Cross-Boundary Monitoring

Monitoring systems provide visibility into interactions between bare metal and containerized services through unified logging and metrics collection. Network monitoring tracks communication patterns and performance characteristics between deployment types. Resource usage monitoring correlates consumption patterns across bare metal services and containerized workloads.

Service dependency monitoring provides visibility into which services depend on which other services across deployment boundaries. Performance monitoring tracks end-to-end request flows that span multiple deployment types. Health monitoring provides unified status information for services regardless of their deployment type.

Alert correlation provides intelligent alerting that can distinguish between problems in different deployment types and identify when problems in one area are causing symptoms in another area. Monitoring dashboards provide operators with unified visibility into the entire system rather than requiring separate views for different deployment types.

#### State Consistency Monitoring

Automated state consistency checks compare intended configuration across , Terraform, and Nomad to detect drift before it causes operational problems. Configuration monitoring tracks changes in any layer and validates that appropriate changes occur in dependent layers. Reconciliation monitoring ensures that periodic state synchronization operations complete successfully.

State validation monitoring includes checks that verify end-to-end consistency between high-level application requirements and actual running services. Resource allocation monitoring ensures that intended resource allocations match actual resource usage across all management layers. Service discovery monitoring validates that registered services match deployed services across all orchestration layers.

Drift detection provides early warning when configuration inconsistencies are developing, allowing proactive correction before they cause service disruption. State backup monitoring ensures that all management layers maintain consistent backup procedures that enable recovery to consistent state.

#### Resource Utilization Monitoring

Resource monitoring distinguishes between service failures and resource contention by tracking resource usage patterns and correlating them with service performance metrics. Memory usage monitoring tracks both overall system memory usage and per-service memory consumption to detect overcommitment scenarios before they cause failures.

I/O performance monitoring tracks throughput and latency across different storage systems to detect interference patterns. CPU utilization monitoring includes both overall system CPU usage and per-service CPU consumption to identify when services are competing for CPU resources. Network bandwidth monitoring ensures that network capacity is sufficient for all communication requirements.

Storage capacity monitoring tracks usage across all storage systems and provides alerting before capacity limits are reached. Resource trend analysis provides data for capacity planning decisions and identifies when resource allocation strategies need to be adjusted.

#### Authentication Flow Monitoring

End-to-end authentication monitoring tracks user authentication flows from initial login through proxy layers to backend service access. Authentication performance monitoring measures authentication latency and success rates across all authentication components. Token lifecycle monitoring ensures that authentication tokens are renewed correctly and that expired tokens don't cause service disruption.

Proxy integration monitoring validates that both Caddy and Nginx correctly integrate with Authentik and handle authentication consistently. Backend service authentication monitoring ensures that services receive correct authentication information and handle authentication failures gracefully.

Security monitoring tracks authentication patterns to detect potential security issues or attack patterns. Authentication audit logging provides comprehensive records for compliance and incident investigation requirements.

### 4.3 Operational Procedures

#### Health Check Implementation

Component health checks provide reliable detection of service failures across all deployment types. Bare metal service health checks monitor process status, resource usage, and service-specific functionality like Vault seal status and CephFS mount availability. Containerized service health checks monitor container status, resource usage, and application-specific functionality.

Integration point health checks validate that cross-boundary communication is working correctly and that service discovery is providing accurate information. End-to-end health checks validate that complete user workflows operate correctly across all system components.

Health check aggregation provides operators with unified system health status rather than requiring monitoring of individual component health checks. Health check automation enables automatic recovery procedures when health checks detect specific types of failures.

#### Alerting Strategy

Root cause alerting reduces alert noise by correlating symptoms across multiple system components and identifying likely root causes rather than just alerting on every symptom. Alert severity classification ensures that critical alerts receive immediate attention while less urgent alerts are handled through normal operational procedures.

Alert escalation procedures ensure that unresolved alerts receive appropriate attention and that critical issues don't go unnoticed. Alert context provides operators with relevant diagnostic information and suggested troubleshooting procedures rather than just notification that problems exist.

Alert suppression prevents cascading alerts when single failures cause multiple symptoms across the system. Alert integration with documentation systems provides operators with immediate access to troubleshooting procedures and escalation paths.

#### Capacity Planning

Optional infrastructure capacity planning accounts for the unpredictable usage patterns of optional components like CephFS. Capacity monitoring provides data about actual usage patterns that inform capacity planning decisions. Capacity trend analysis identifies when resource allocation decisions need to be revisited.

Multi-storage capacity planning coordinates capacity decisions across CephFS, MinIO, and PostgreSQL storage systems. Application-specific service capacity planning accounts for the resource multiplication effects of per-application service deployment. Resource reservation planning ensures that capacity plans account for both bare metal and containerized service resource requirements.

Capacity testing validates that planned capacity actually supports expected workloads and identifies when capacity planning assumptions need to be revised. Capacity alerting provides early warning when actual usage approaches planned capacity limits.

#### Emergency Response

Emergency response procedures define when normal orchestration workflows should be bypassed to enable faster problem resolution. Emergency access procedures ensure that operators can access critical systems even when normal authentication systems are unavailable. Emergency change procedures allow rapid system changes while ensuring that emergency changes are properly documented and integrated into normal configuration management workflows.

Escalation procedures define when emergency response is required and who should be involved in emergency response decisions. Communication procedures ensure that emergency response activities are properly coordinated and that stakeholders receive appropriate status updates.

Emergency recovery procedures provide step-by-step guidance for recovering from different types of system failures. Emergency preparedness includes regular training and testing of emergency procedures to ensure that operators can execute them effectively under pressure.

### 4.4 Validation Criteria

#### Success Metrics

Architecture success measurement includes quantitative metrics that validate whether our complex architecture actually delivers the benefits that justify its complexity. Performance metrics compare actual system performance against baseline expectations established during architecture design. Reliability metrics track system availability and failure recovery times across all components.

Operational efficiency metrics measure whether the architecture reduces operational burden through automation and clear separation of concerns. Developer productivity metrics track whether the architecture enables faster application development and deployment compared to alternative approaches.

Cost efficiency metrics account for both hardware utilization and operational effort to ensure that the architecture provides appropriate value for its complexity. Scalability metrics track how system performance and operational characteristics change as workload and infrastructure scale.

#### Performance Baselines

System performance baselines establish expected performance characteristics for all major system components and integration points. Storage performance baselines define expected throughput and latency characteristics for CephFS, MinIO, and PostgreSQL under different workload patterns. Network performance baselines establish expected latency and throughput for communication between different system components.

Authentication performance baselines define expected authentication latency and throughput across the complete authentication workflow. Orchestration performance baselines establish expected latency for configuration changes to propagate through the  → Terraform → Nomad workflow.

Application deployment performance baselines define expected deployment times for different types of applications and infrastructure changes. Backup and recovery performance baselines establish expected backup completion times and recovery time objectives for different types of failures.

#### Failure Tolerances

Acceptable failure rates define the reliability expectations for different system components and establish criteria for evaluating whether system reliability meets operational requirements. Recovery time objectives define maximum acceptable recovery times for different types of failures and guide investment in high availability and disaster recovery capabilities.

Service level objectives define performance and availability commitments for applications running on the infrastructure. Error budget management provides frameworks for balancing reliability investments against feature development and operational changes.

Cascading failure tolerance defines how many simultaneous failures the system should tolerate without complete service disruption. Degraded operation modes define how the system should behave when operating with reduced capabilities due to component failures.

#### Scalability Indicators

Scaling trigger metrics identify when current architectural choices approach their operational limits and need to be reconsidered. Performance degradation indicators provide early warning when system performance begins to decline due to scaling limitations. Resource utilization trends identify when hardware capacity or resource allocation strategies need to be revised.

Operational complexity indicators track when management overhead grows faster than system capabilities, suggesting that architectural simplification may be beneficial. Cost scaling indicators identify when infrastructure costs grow disproportionately to delivered capabilities.

Architectural decision review triggers define when specific architectural choices should be reconsidered based on changed requirements or operational experience. Technology evolution indicators track when underlying technology changes might enable better architectural approaches.

## Glossary

**CephFS**: Distributed file system providing shared storage capabilities across multiple nodes
**Nomad**: HashiCorp's container orchestration platform for scheduling and managing workloads
****: Configuration management and orchestration platform that ensures consistent system state
**Terraform**: Infrastructure as code tool that provisions and manages infrastructure resources
**Vault**: HashiCorp's secrets management platform for securing and controlling access to tokens, passwords, and other secrets
**Authentik**: Open-source identity provider that provides SSO and authentication capabilities
**MinIO**: S3-compatible object storage server designed for cloud-native workloads
**Consul**: HashiCorp's service discovery and configuration management platform
**Boundary**: HashiCorp's zero trust network access platform for securing infrastructure access
**Wazuh**: Open-source XDR/SIEM platform for security monitoring and threat detection
**ClusterFuzz**: Scalable fuzzing infrastructure for finding security vulnerabilities
**Restic**: Fast, secure backup program for multiple storage backends

---

*This document serves as the authoritative architectural decision record for our infrastructure. It should be reviewed and updated as operational experience validates or challenges the decisions documented here.*