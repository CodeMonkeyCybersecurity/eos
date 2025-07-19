# DNS record removal via Terraform
{% set dns_config = pillar.get('hecate', {}).get('dns_record_remove', {}) %}

hecate_dns_record_remove_{{ dns_config.get('domain', 'default') }}:
  cmd.run:
    - name: |
        cd /var/lib/hecate/terraform/dns
        # Remove the Terraform file for this domain
        rm -f {{ dns_config.get('domain', 'default') }}.tf
        # Apply changes to remove the DNS record
        terraform plan -out=dns_remove.plan
        terraform apply dns_remove.plan
    - cwd: /var/lib/hecate/terraform/dns
    - onlyif: test -f /var/lib/hecate/terraform/dns/{{ dns_config.get('domain', 'default') }}.tf

# Clean up any orphaned state if the file doesn't exist but state does
hecate_dns_record_cleanup_{{ dns_config.get('domain', 'default') }}:
  cmd.run:
    - name: |
        cd /var/lib/hecate/terraform/dns
        # Try to remove from state if resource exists but file is gone
        terraform state rm 'hetznerdns_record.{{ dns_config.get('domain', 'default') | replace('.', '_') | replace('-', '_') }}' || true
    - cwd: /var/lib/hecate/terraform/dns
    - unless: test -f /var/lib/hecate/terraform/dns/{{ dns_config.get('domain', 'default') }}.tf