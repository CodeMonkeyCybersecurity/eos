FROM hashicorp/vault:1.19.1

USER root

RUN mkdir -p /etc/vault-agent /run/vault && \
    chown -R 100:100 /etc/vault-agent /run/vault && \
    chmod 700 /run/vault

COPY agent.hcl /etc/vault-agent/agent.hcl
COPY role_id /etc/vault-agent/role_id
COPY secret_id /etc/vault-agent/secret_id

RUN chmod 600 /etc/vault-agent/role_id /etc/vault-agent/secret_id

USER 100
CMD ["vault", "agent", "-config=/etc/vault-agent/agent.hcl"]
