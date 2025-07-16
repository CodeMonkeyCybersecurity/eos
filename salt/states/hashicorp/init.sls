# HashiCorp Tools Salt States
# This state provides shared repository setup for all HashiCorp tools
# Following the architectural principle: Salt = Physical infrastructure
# Individual tools are installed by calling their specific states:
# - hashicorp.terraform
# - hashicorp.vault  
# - hashicorp.consul
# - hashicorp.nomad
# - hashicorp.packer
# - hashicorp.boundary

# Include common dependencies
include:
  - dependencies

# HashiCorp repository setup (shared by all tools)
hashicorp_gpg_key:
  cmd.run:
    - name: |
        wget -qO- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
        gpg --no-default-keyring --keyring /usr/share/keyrings/hashicorp-archive-keyring.gpg --fingerprint
    - unless: test -f /usr/share/keyrings/hashicorp-archive-keyring.gpg
    - require:
      - pkg: eos_dependencies
    - require_in:
      - pkgrepo: hashicorp_repo

hashicorp_repo:
  pkgrepo.managed:
    - humanname: HashiCorp Repository
    - name: "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com {{ grains['oscodename'] }} main"
    - file: /etc/apt/sources.list.d/hashicorp.list
    - require:
      - cmd: hashicorp_gpg_key
    # Repository will be available for individual tool installations