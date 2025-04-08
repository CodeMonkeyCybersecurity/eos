FROM hashicorp/vault:1.19.1

USER root

RUN mkdir -p /vault/data && \
    chown -R 100:100 /vault && \
    chmod 700 /vault/data

COPY config.hcl /vault/config/config.hcl

USER 100
CMD ["vault", "server", "-config=/vault/config/config.hcl"]
