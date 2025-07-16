# Common dependencies for eos Salt states
# This ensures all required system packages are installed

# Essential system packages required by various Salt states
eos_dependencies:
  pkg.installed:
    - pkgs:
      - jq              # JSON processor (used by Vault initialization)
      - openssl         # TLS certificate generation
      - curl            # HTTP client for health checks and downloads
      - wget            # Alternative HTTP client for downloads
      - gnupg           # GPG for package verification
      - software-properties-common  # Repository management
      - apt-transport-https          # HTTPS transport for apt
      - ca-certificates             # Certificate authorities
      - lsb-release                 # System information
      - unzip                       # Archive extraction

# Ensure system is up to date
eos_system_update:
  pkg.upgrade:
    - require:
      - pkg: eos_dependencies