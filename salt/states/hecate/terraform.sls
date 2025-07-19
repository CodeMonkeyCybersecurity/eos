# Terraform state management for Hecate
{% set hetzner_token = salt['vault'].read_secret('secret/hetzner/api_token', 'token') %}
{% set dns_zone = salt['pillar.get']('hecate:dns_zone', 'example.com') %}
{% set ingress_ip = salt['pillar.get']('hecate:ingress_ip', '1.2.3.4') %}

# Ensure terraform workspace exists
terraform_workspace:
  file.directory:
    - name: /var/lib/hecate/terraform
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

# Main Terraform configuration
/var/lib/hecate/terraform/main.tf:
  file.managed:
    - source: salt://hecate/files/terraform/main.tf.j2
    - template: jinja
    - user: root
    - group: root
    - mode: 644
    - context:
        hetzner_token: {{ hetzner_token }}
        dns_zone: {{ dns_zone }}
        ingress_ip: {{ ingress_ip }}
    - require:
      - file: terraform_workspace

# Variables file
/var/lib/hecate/terraform/variables.tf:
  file.managed:
    - source: salt://hecate/files/terraform/variables.tf
    - user: root
    - group: root
    - mode: 644
    - require:
      - file: terraform_workspace

# Terraform init
terraform_init:
  cmd.run:
    - name: terraform init
    - cwd: /var/lib/hecate/terraform
    - unless: test -d /var/lib/hecate/terraform/.terraform
    - require:
      - file: /var/lib/hecate/terraform/main.tf