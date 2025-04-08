pid_file = "/run/vault/agent.pid"

auto_auth {
  method "userpass" {
    mount_path = "auth/userpass"
    config = {
      username = "eos"
      password_file = "/etc/vault-agent/password.txt"
    }
  }

  sink "file" {
    config = {
      path = "/run/vault/.vault-token"
    }
  }
}

vault {
  address = "http://vault:8200"
}

cache {
  use_auto_auth_token = true
}
