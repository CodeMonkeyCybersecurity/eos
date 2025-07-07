# salt/states/minio/init.sls
# MinIO state initialization

include:
  - minio.install
  - minio.config
  - minio.service