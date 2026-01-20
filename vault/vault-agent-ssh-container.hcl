pid_file = "/tmp/vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/vault/creds/role_id"
      secret_id_file_path = "/vault/creds/secret_id"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

template {
  source      = "/vault/templates/trusted-user-ca-keys.pem.tpl"
  destination = "/etc/ssh/trusted-user-ca-keys.pem"
  perms       = "0644"
}
