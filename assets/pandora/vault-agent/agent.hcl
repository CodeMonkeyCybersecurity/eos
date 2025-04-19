auto_auth {
  method {
    type = "approle"
    config = {
      role_id_file_path = "/etc/vault-agent/role_id"
      secret_id_file_path = "/etc/vault-agent/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink {
    type = "file"
    config = {
      path = "/run/vault/token"
    }
  }
}

vault {
  address = $VaultDefaultAddr
}
