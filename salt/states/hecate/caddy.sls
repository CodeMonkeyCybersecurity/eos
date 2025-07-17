# Hecate Caddy reverse proxy deployment
# Combines install, configure, and service states

include:
  - .caddy.install
  - .caddy.configure
  - .caddy.service

# Ensure proper ordering
caddy_deployment_order:
  test.succeed_with_changes:
    - require:
      - sls: hecate.caddy.install
      - sls: hecate.caddy.configure
      - sls: hecate.caddy.service