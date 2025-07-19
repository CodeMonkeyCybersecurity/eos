# DNS record management via Terraform
{% set dns_config = pillar.get('hecate', {}).get('dns_record', {}) %}

hecate_dns_record_{{ dns_config.get('domain', 'default') }}:
  cmd.run:
    - name: |
        cd /var/lib/hecate/terraform/dns
        cat > {{ dns_config.get('domain', 'default') }}.tf << 'EOF'
        resource "hetznerdns_record" "{{ dns_config.get('domain', 'default') | replace('.', '_') | replace('-', '_') }}" {
          zone_id = data.hetznerdns_zone.main.id
          name    = "{{ dns_config.get('domain', 'default') }}"
          type    = "{{ dns_config.get('type', 'A') }}"
          value   = "{{ dns_config.get('target', '1.2.3.4') }}"
          ttl     = {{ dns_config.get('ttl', 300) }}
        }
        EOF
        terraform init -upgrade
        terraform plan -out=dns.plan
        terraform apply dns.plan
    - cwd: /var/lib/hecate/terraform/dns
    - require:
      - file: hecate_terraform_dns_directory

hecate_terraform_dns_directory:
  file.directory:
    - name: /var/lib/hecate/terraform/dns
    - makedirs: True
    - user: root
    - group: root
    - mode: 755

hecate_terraform_dns_main:
  file.managed:
    - name: /var/lib/hecate/terraform/dns/main.tf
    - source: salt://hecate/files/terraform/dns_main.tf.j2
    - template: jinja
    - context:
        dns_zone: {{ pillar.get('hecate', {}).get('dns_zone', 'example.com') }}
        hetzner_token: {{ pillar.get('hecate', {}).get('hetzner_token', '') }}
    - require:
      - file: hecate_terraform_dns_directory

hecate_terraform_dns_variables:
  file.managed:
    - name: /var/lib/hecate/terraform/dns/variables.tf
    - contents: |
        variable "hetzner_token" {
          description = "Hetzner Cloud API token"
          type        = string
          sensitive   = true
        }

        variable "dns_zone" {
          description = "DNS zone name"
          type        = string
        }
    - require:
      - file: hecate_terraform_dns_directory