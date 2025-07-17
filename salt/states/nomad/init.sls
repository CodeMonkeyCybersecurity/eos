# Nomad Installation and Configuration
# Main state file for HashiCorp Nomad deployment

include:
  - .install
  - .configure
  - .service

# Ensure proper ordering
nomad_deployment_order:
  test.succeed_with_changes:
    - require:
      - sls: nomad.install
      - sls: nomad.configure
      - sls: nomad.service