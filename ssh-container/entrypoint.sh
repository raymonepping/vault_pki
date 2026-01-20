#!/usr/bin/env bash
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR not set}"

# Start Vault Agent in background
vault agent -config=/etc/vault-agent.d/vault-agent.hcl &
AGENT_PID="$!"

# Wait until CA key is rendered
echo "[entrypoint] waiting for /etc/ssh/trusted-user-ca-keys.pem ..."
until [ -s /etc/ssh/trusted-user-ca-keys.pem ]; do
  sleep 1
done

# Ensure principals file exists for ubuntu
install -d -m 0755 /etc/ssh/authorized_principals
echo "ubuntu" > /etc/ssh/authorized_principals/ubuntu
chmod 0644 /etc/ssh/authorized_principals/ubuntu

# Idempotent sshd_config patch
SSHD_CONFIG="/etc/ssh/sshd_config"

ensure_line () {
  local line="$1"
  grep -qF -- "$line" "$SSHD_CONFIG" || echo "$line" >> "$SSHD_CONFIG"
}

ensure_line "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem"
ensure_line "AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u"
ensure_line "PubkeyAuthentication yes"
ensure_line "PermitTTY yes"
ensure_line "PasswordAuthentication no"

# Make sure runtime dir exists (some images still complain at runtime)
mkdir -p /run/sshd
chmod 0755 /run/sshd

echo "[entrypoint] starting sshd ..."
exec /usr/sbin/sshd -D -e
