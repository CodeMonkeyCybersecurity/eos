# Hecate Reverse Proxy Framework Orchestration
# Main state file that orchestrates the deployment of all Hecate components

include:
  - .prereqs
  - .hybrid_secrets
  - .nomad.jobs
  - .authentik.database
  - .authentik.redis
  - .authentik.install
  - .authentik.configure
  - .caddy.install
  - .caddy.configure
  - .caddy.service

# Ensure proper ordering of component deployment
hecate_deployment_order:
  test.succeed_with_changes:
    - require:
      - sls: hecate.prereqs
      - sls: hecate.hybrid_secrets
      - sls: hecate.nomad.jobs
      - sls: hecate.authentik.database
      - sls: hecate.authentik.redis
      - sls: hecate.authentik.install
      - sls: hecate.authentik.configure
      - sls: hecate.caddy.install
      - sls: hecate.caddy.configure
      - sls: hecate.caddy.service