#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${CERT_DIR:-./shared/certs}"
BACKUPS_DIR="${BACKUPS_DIR:-${CERT_DIR}/backups}"

# Where nginx serves static content from (mapped to /usr/share/nginx/html)
WWW_DIR="${WWW_DIR:-./shared/www}"
CRL_OUT_DIR="${CRL_OUT_DIR:-${WWW_DIR}/crl}"
CRL_OUT_FILE="${CRL_OUT_FILE:-${CRL_OUT_DIR}/pki-int.crl.pem}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }

need vault
need openssl
need curl

JQ_OK=true
if ! command -v jq >/dev/null 2>&1; then
  JQ_OK=false
  need python3
fi

latest="$(ls -1 "${BACKUPS_DIR}" 2>/dev/null | sort | tail -n 1 || true)"
if [[ -z "${latest}" ]]; then
  echo "No backups found in ${BACKUPS_DIR}" >&2
  exit 1
fi

backup_path="${BACKUPS_DIR}/${latest}"
old_json="${backup_path}/nginx-leaf.json"
old_crt="${backup_path}/nginx.crt"

if [[ ! -f "${old_crt}" ]]; then
  echo "Could not find ${old_crt} in latest backup: ${backup_path}" >&2
  ls -la "${backup_path}" >&2 || true
  exit 1
fi

serial=""

# 1) Prefer Vault serial format from the saved JSON
if [[ -f "${old_json}" ]]; then
  if [[ "${JQ_OK}" == "true" ]]; then
    serial="$(jq -r '.data.serial_number // empty' "${old_json}")"
  else
    serial="$(python3 - <<PY
import json
p="${old_json}"
with open(p,"r",encoding="utf-8") as f:
  j=json.load(f)
print(j.get("data",{}).get("serial_number",""))
PY
)"
  fi
fi

# 2) Fallback: derive from cert and convert to Vault format (aa:bb:cc...)
if [[ -z "${serial}" || "${serial}" == "null" ]]; then
  serial_hex="$(openssl x509 -in "${old_crt}" -noout -serial | cut -d= -f2)"
  serial_hex="$(echo "${serial_hex}" | tr '[:upper:]' '[:lower:]')"

  # pad odd length
  if (( ${#serial_hex} % 2 == 1 )); then
    serial_hex="0${serial_hex}"
  fi

  serial="$(echo "${serial_hex}" | sed 's/../&:/g; s/:$//')"
fi

echo "Revoking previous leaf cert from: ${old_crt}"
echo "Serial (Vault format): ${serial}"

vault write pki-int/revoke serial_number="${serial}" >/dev/null

echo
echo "Fetching CRL (PEM)..."
curl -sS "http://127.0.0.1:8200/v1/pki-int/crl/pem" -o "${backup_path}/pki-int.crl.pem"
echo "CRL saved to: ${backup_path}/pki-int.crl.pem"

# Publish latest CRL to nginx-served location
mkdir -p "${CRL_OUT_DIR}"
cp -f "${backup_path}/pki-int.crl.pem" "${CRL_OUT_FILE}"
echo "CRL published to: ${CRL_OUT_FILE}"
echo "Dashboard URL: https://nginx.lab.local:8443/crl/pki-int.crl.pem"

echo
echo "Best-effort check: is serial present in CRL text?"
openssl crl -in "${backup_path}/pki-int.crl.pem" -inform PEM -noout -text > "${backup_path}/pki-int.crl.txt"

# Normalize by stripping colons for grep
if grep -qi "$(echo "${serial}" | tr -d ':')" "${backup_path}/pki-int.crl.txt"; then
  echo "✅ Found serial (normalized) in CRL output."
else
  echo "ℹ️  Not found via quick grep. Open this file to confirm:"
  echo "   ${backup_path}/pki-int.crl.txt"
fi

echo
echo "Done."