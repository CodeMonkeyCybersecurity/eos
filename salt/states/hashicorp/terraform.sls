# Terraform Installation via Salt
# Manages HashiCorp Terraform installation following Eos architectural principles

# Include shared HashiCorp repository setup
include:
  - hashicorp

terraform_package:
  pkg.installed:
    - name: terraform
    - require:
      - pkgrepo: hashicorp_repo

terraform_binary_verify:
  cmd.run:
    - name: terraform version
    - require:
      - pkg: terraform_package

# Ensure terraform is in PATH
terraform_binary_link:
  file.symlink:
    - name: /usr/local/bin/terraform
    - target: /usr/bin/terraform
    - makedirs: true
    - require:
      - pkg: terraform_package
    - onlyif: test -f /usr/bin/terraform && ! test -L /usr/local/bin/terraform

terraform_completion:
  cmd.run:
    - name: terraform -install-autocomplete
    - runas: root
    - require:
      - pkg: terraform_package
    - unless: test -f ~/.bashrc && grep -q "complete -C.*terraform" ~/.bashrc