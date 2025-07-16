# Packer Installation via Salt
# Manages HashiCorp Packer installation following Eos architectural principles

# Include shared HashiCorp repository setup
include:
  - hashicorp

packer_package:
  pkg.installed:
    - name: packer
    - require:
      - pkgrepo: hashicorp_repo

packer_binary_verify:
  cmd.run:
    - name: packer version
    - require:
      - pkg: packer_package

# Ensure packer is in PATH
packer_binary_link:
  file.symlink:
    - name: /usr/local/bin/packer
    - target: /usr/bin/packer
    - makedirs: true
    - require:
      - pkg: packer_package
    - onlyif: test -f /usr/bin/packer && ! test -L /usr/local/bin/packer

# Create packer working directory
packer_work_dir:
  file.directory:
    - name: /opt/packer
    - user: root
    - group: root
    - mode: 755
    - makedirs: true
    - require:
      - pkg: packer_package

# Install common packer plugins if specified in pillar
{% if pillar.get('packer:plugins') %}
{% for plugin in pillar.get('packer:plugins', []) %}
packer_plugin_{{ plugin }}:
  cmd.run:
    - name: packer plugins install {{ plugin }}
    - require:
      - pkg: packer_package
    - unless: packer plugins installed | grep -q "{{ plugin }}"
{% endfor %}
{% endif %}