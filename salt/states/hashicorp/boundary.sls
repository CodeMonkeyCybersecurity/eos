# Boundary Installation via Salt
# Manages HashiCorp Boundary installation following Eos architectural principles

# Include shared HashiCorp repository setup
include:
  - hashicorp

boundary_package:
  pkg.installed:
    - name: boundary
    - require:
      - pkgrepo: hashicorp_repo

boundary_user:
  user.present:
    - name: boundary
    - system: true
    - shell: /bin/false
    - home: /var/lib/boundary
    - require:
      - pkg: boundary_package

boundary_directories:
  file.directory:
    - names:
      - /etc/boundary.d
      - /var/lib/boundary
      - /var/log/boundary
    - user: boundary
    - group: boundary
    - mode: 750
    - makedirs: true
    - require:
      - user: boundary_user

boundary_binary_verify:
  cmd.run:
    - name: boundary version
    - require:
      - pkg: boundary_package

# Ensure boundary is in PATH
boundary_binary_link:
  file.symlink:
    - name: /usr/local/bin/boundary
    - target: /usr/bin/boundary
    - makedirs: true
    - require:
      - pkg: boundary_package
    - onlyif: test -f /usr/bin/boundary && ! test -L /usr/local/bin/boundary

# Basic boundary configuration
boundary_config:
  file.managed:
    - name: /etc/boundary.d/boundary.hcl
    - contents: |
        # Boundary configuration managed by Salt
        disable_mlock = {{ pillar.get('boundary:disable_mlock', 'true') }}
        
        {% if pillar.get('boundary:controller_mode', false) %}
        controller {
          name = "{{ pillar.get('boundary:controller_name', 'eos-controller') }}"
          description = "EOS Boundary Controller"
          
          database {
            url = "{{ pillar.get('boundary:database_url', 'postgresql://boundary:boundary@localhost/boundary') }}"
          }
        }
        {% endif %}
        
        {% if pillar.get('boundary:worker_mode', false) %}
        worker {
          name = "{{ pillar.get('boundary:worker_name', 'eos-worker') }}"
          description = "EOS Boundary Worker"
          controllers = {{ pillar.get('boundary:controllers', '["127.0.0.1:9201"]') | tojson }}
        }
        {% endif %}
        
        listener "tcp" {
          address = "{{ pillar.get('boundary:listen_address', '127.0.0.1:9200') }}"
          purpose = "{{ pillar.get('boundary:listener_purpose', 'api') }}"
        }
        
        kms "aead" {
          purpose = "root"
          aead_type = "aes-gcm"
          key = "{{ pillar.get('boundary:root_key', 'sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung=') }}"
          key_id = "global_root"
        }
        
        kms "aead" {
          purpose = "worker-auth"
          aead_type = "aes-gcm" 
          key = "{{ pillar.get('boundary:worker_key', '8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ=') }}"
          key_id = "global_worker-auth"
        }
        
        kms "aead" {
          purpose = "recovery"
          aead_type = "aes-gcm"
          key = "{{ pillar.get('boundary:recovery_key', '8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ=') }}"
          key_id = "global_recovery"
        }
    - user: boundary
    - group: boundary
    - mode: 640
    - require:
      - file: boundary_directories
      - pkg: boundary_package