# salt/states/minio/terraform_generator.sls
# Generate Terraform configurations for MinIO deployment per STACK.md architecture

{% set minio = pillar.get('minio', {}) %}
{% set terraform_base = minio.get('terraform_base', '/srv/terraform/minio') %}
{% set app_name = minio.get('app_name', 'minio-default') %}

# Create Terraform directory structure
minio_terraform_directories:
  file.directory:
    - names:
      - {{ terraform_base }}
      - {{ terraform_base }}/{{ app_name }}
      - {{ terraform_base }}/{{ app_name }}/templates
    - makedirs: True
    - mode: 755

# Generate main.tf from pillar data
minio_terraform_main:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/main.tf
    - source: salt://minio/files/terraform/main.tf.jinja
    - template: jinja
    - context:
        minio: {{ minio | tojson }}
        app_name: {{ app_name }}
    - require:
      - file: minio_terraform_directories

# Generate variables.tf
minio_terraform_variables:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/variables.tf
    - source: salt://minio/files/terraform/variables.tf.jinja
    - template: jinja
    - context:
        minio: {{ minio | tojson }}
    - require:
      - file: minio_terraform_directories

# Generate terraform.tfvars from pillar
minio_terraform_tfvars:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/terraform.tfvars
    - contents: |
        # Generated by SaltStack from pillar data
        datacenter   = "{{ minio.get('datacenter', 'dc1') }}"
        storage_path = "{{ minio.get('storage_path', '/mnt/minio-data') }}"
        api_port     = {{ minio.get('api_port', 9123) }}
        console_port = {{ minio.get('console_port', 8123) }}
        vault_addr   = "{{ minio.get('vault_addr', salt['pillar.get']('vault:api_addr', 'http://localhost:8200')) }}"
        nomad_addr   = "{{ minio.get('nomad_addr', salt['pillar.get']('nomad:api_addr', 'http://localhost:4646')) }}"
        consul_addr  = "{{ minio.get('consul_addr', salt['pillar.get']('consul:api_addr', 'http://localhost:8161')) }}"
        
        # Application-specific settings
        app_name     = "{{ app_name }}"
        memory_limit = {{ minio.get('memory_limit', 1024) }}
        cpu_limit    = {{ minio.get('cpu_limit', 500) }}
        
        # Volume configuration
        {% if minio.get('use_cephfs', false) %}
        volume_type  = "cephfs"
        volume_source = "{{ minio.get('cephfs_volume', 'minio-cephfs') }}"
        {% else %}
        volume_type  = "host"
        volume_source = "minio-data-{{ app_name }}"
        {% endif %}
    - require:
      - file: minio_terraform_directories

# Generate Nomad job template
minio_nomad_job_template:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/minio.nomad.hcl
    - source: salt://minio/files/terraform/minio.nomad.hcl.jinja
    - template: jinja
    - context:
        minio: {{ minio | tojson }}
        app_name: {{ app_name }}
    - require:
      - file: minio_terraform_directories

# State backend configuration
minio_terraform_backend:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/backend.tf
    - contents: |
        terraform {
          backend "consul" {
            address = "{{ salt['pillar.get']('consul:api_addr', 'localhost:8161') }}"
            scheme  = "http"
            path    = "terraform/minio/{{ app_name }}"
            lock    = true
          }
        }
    - require:
      - file: minio_terraform_directories

# Validation script
minio_terraform_validate:
  file.managed:
    - name: {{ terraform_base }}/{{ app_name }}/validate.sh
    - mode: 755
    - contents: |
        #!/bin/bash
        set -e
        
        echo "Validating Terraform configuration for {{ app_name }}..."
        
        # Initialize Terraform
        terraform init -backend=true
        
        # Validate configuration
        terraform validate
        
        # Plan to check for issues
        terraform plan -out=tfplan
        
        echo "Validation successful. Run 'terraform apply tfplan' to deploy."
    - require:
      - file: minio_terraform_main
      - file: minio_terraform_variables
      - file: minio_terraform_tfvars