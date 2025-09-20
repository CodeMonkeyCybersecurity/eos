# Terraform-Nomad Integration Enhancement

*Last Updated: 2025-01-20*

## Current Architecture (Correct Approach)

Eos uses a **mature, opinionated architecture** that treats infrastructure and workloads as a unified system:

```
 (Source of Truth) → Terraform (State Management) → Nomad (Container Runtime)
```

## Why Terraform Manages Nomad Jobs

### **1. Unified State Management**
- Infrastructure and workloads tracked in single Terraform state
- Atomic operations: provision infrastructure AND deploy workloads
- Rollback capabilities across entire stack

### **2. Dependency Management**
```hcl
resource "hcloud_server" "nomad_cluster" {
  # Cloud infrastructure
}

resource "nomad_job" "grafana" {
  depends_on = [hcloud_server.nomad_cluster]
  jobspec = templatefile("jobs/grafana.nomad", var.grafana_config)
}
```

### **3. Cross-Component Integration**
-  states call Terraform via `eos_terraform.py`
- Configuration flows:  → TF vars → Nomad jobs
- Consul KV integration for service discovery

## Enhanced Implementation Pattern

### **1. Improve Terraform Job Templates**

Instead of direct Nomad job files, enhance Terraform templates:

```hcl
# /opt/eos/terraform/modules/grafana/main.tf
resource "nomad_job" "grafana" {
  jobspec = templatefile("${path.module}/grafana.nomad.tpl", {
    admin_password = var.admin_password
    port          = var.port
    datacenter    = var.datacenter
    data_path     = var.data_path
    cpu           = var.cpu
    memory        = var.memory
  })
  
  purge_on_destroy = true
  detach          = false
}

# Terraform manages the job lifecycle
output "grafana_url" {
  value = "http://localhost:${var.port}"
}

output "consul_service" {
  value = "grafana.service.consul"
}
```

### **2. Enhanced  Integration**

Update  states to call Terraform modules:

```yaml
# /srv//grafana/deploy.sls
grafana_terraform_deployment:
  eos_terraform.apply:
    - component: grafana
    - workspace: {{ .get('environment', 'production') }}
    - variables:
        admin_password: {{ .get('grafana:admin_password', 'admin') }}
        port: {{ .get('grafana:port', 3000) }}
        datacenter: {{ .get('nomad:datacenter', 'dc1') }}
        data_path: {{ .get('grafana:data_path', '/opt/grafana/data') }}
```

### **3. Command Implementation**

Update commands to use the Terraform → Nomad flow:

```go
// cmd/create/grafana.go
func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Build  configuration
    Config := map[string]interface{}{
        "grafana": map[string]interface{}{
            "admin_password": adminPassword,
            "port":          port,
            "datacenter":    datacenter,
        },
    }
    
    // Apply  state (which calls Terraform)
    if err := applyState(rc, "grafana.deploy", Config); err != nil {
        return fmt.Errorf("failed to deploy Grafana: %w", err)
    }
    
    return nil
}
```

## Benefits of This Approach

### **1. Maintains Architectural Consistency**
- Preserves established  → Terraform → Nomad flow
- No breaking changes to existing integration
- Respects engineering investment in current architecture

### **2. Enhanced Capabilities** 
- State management and rollback via Terraform
- Dependency tracking between infrastructure and workloads
- Unified configuration source ( s)

### **3. Operational Excellence**
- Consul locks for distributed state management
- Atomic deployments across infrastructure and applications
- Integration with existing monitoring and logging

## Migration Strategy

### **Phase 1: Enhance Terraform Templates**
- Create modular Terraform configurations for each service
- Improve job templates with better parameterization
- Add proper resource dependencies

### **Phase 2: Improve  Integration**
- Enhance `eos_terraform.py` with better error handling
- Add validation for Terraform variables
- Improve state coordination with Consul

### **Phase 3: User Experience**
- Maintain simple `eos create X` interface
- Hide Terraform complexity from users
- Provide better status reporting and debugging

## Example: Complete Grafana Flow

### **1. User Command**
```bash
eos create grafana --admin-password secret123 --port 3000
```

### **2.  State Application**
```yaml
# Applied automatically
grafana_deployment:
  eos_terraform.apply:
    - component: grafana
    - variables:
        admin_password: secret123
        port: 3000
```

### **3. Terraform Execution**
```hcl
# Terraform creates Nomad job resource
resource "nomad_job" "grafana" {
  jobspec = templatefile("grafana.nomad.tpl", {
    admin_password = "secret123"
    port = 3000
  })
}
```

### **4. Nomad Deployment**
- Terraform applies job to Nomad
- Nomad schedules container
- Service registers with Consul
- Health checks validate deployment

## Conclusion

The existing Eos architecture is **highly sophisticated** and treats infrastructure and workloads as a unified system. Rather than bypassing this with direct Nomad jobs, we should enhance the existing Terraform integration to provide better user experience while maintaining architectural integrity.