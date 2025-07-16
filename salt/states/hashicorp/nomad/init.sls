# salt/states/hashicorp/nomad/init.sls
# HashiCorp Nomad state initialization

include:
  - hashicorp.nomad.install
  - hashicorp.nomad.config
  - hashicorp.nomad.service