# Deploy Nomad job specifications for Hecate components

# Copy all Nomad job files
{% for job in ['postgres', 'redis', 'authentik-server', 'authentik-worker', 'caddy'] %}
copy_nomad_job_{{ job }}:
  file.managed:
    - name: /opt/hecate/nomad/jobs/{{ job }}.nomad
    - source: salt://hecate/files/nomad/{{ job }}.nomad
    - template: jinja
    - mode: 644
    - makedirs: True
{% endfor %}

# Submit jobs in correct order with dependencies
submit_postgres_job:
  cmd.run:
    - name: nomad job run /opt/hecate/nomad/jobs/postgres.nomad
    - unless: nomad job status hecate-postgres
    - require:
      - file: copy_nomad_job_postgres

wait_for_postgres:
  cmd.run:
    - name: |
        for i in {1..30}; do
          if nomad job status hecate-postgres | grep -q "running"; then
            echo "PostgreSQL is running"
            exit 0
          fi
          echo "Waiting for PostgreSQL to start..."
          sleep 5
        done
        exit 1
    - require:
      - cmd: submit_postgres_job

submit_redis_job:
  cmd.run:
    - name: nomad job run /opt/hecate/nomad/jobs/redis.nomad
    - unless: nomad job status hecate-redis
    - require:
      - file: copy_nomad_job_redis

wait_for_redis:
  cmd.run:
    - name: |
        for i in {1..30}; do
          if nomad job status hecate-redis | grep -q "running"; then
            echo "Redis is running"
            exit 0
          fi
          echo "Waiting for Redis to start..."
          sleep 5
        done
        exit 1
    - require:
      - cmd: submit_redis_job

submit_authentik_server_job:
  cmd.run:
    - name: nomad job run /opt/hecate/nomad/jobs/authentik-server.nomad
    - unless: nomad job status hecate-authentik-server
    - require:
      - file: copy_nomad_job_authentik-server
      - cmd: wait_for_postgres
      - cmd: wait_for_redis

submit_authentik_worker_job:
  cmd.run:
    - name: nomad job run /opt/hecate/nomad/jobs/authentik-worker.nomad
    - unless: nomad job status hecate-authentik-worker
    - require:
      - file: copy_nomad_job_authentik-worker
      - cmd: wait_for_postgres
      - cmd: wait_for_redis

wait_for_authentik:
  cmd.run:
    - name: |
        for i in {1..60}; do
          if curl -sf http://localhost:9000/-/health/ready/; then
            echo "Authentik is ready"
            exit 0
          fi
          echo "Waiting for Authentik to be ready..."
          sleep 5
        done
        exit 1
    - require:
      - cmd: submit_authentik_server_job
      - cmd: submit_authentik_worker_job

submit_caddy_job:
  cmd.run:
    - name: nomad job run /opt/hecate/nomad/jobs/caddy.nomad
    - unless: nomad job status hecate-caddy
    - require:
      - file: copy_nomad_job_caddy
      - cmd: wait_for_authentik