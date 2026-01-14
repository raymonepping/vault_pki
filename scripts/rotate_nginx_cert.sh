#!/usr/bin/env bash
set -euo pipefail

ROLE="${ROLE:-nginx}"
CN="${CN:-nginx.lab.local}"
ALT_NAMES="${ALT_NAMES:-localhost}"
IP_SANS="${IP_SANS:-127.0.0.1}"
TTL="${TTL:-24h}"

CERT_DIR="${CERT_DIR:-./shared/certs}"
LEAF_JSON="${CERT_DIR}/nginx-leaf.json"

LEAF_CRT="${CERT_DIR}/nginx.crt"
LEAF_KEY="${CERT_DIR}/nginx.key"
ISSUING_CA="${CERT_DIR}/lab-int-issuing-ca.pem"
CHAIN_CRT="${CERT_DIR}/nginx.chain.crt"
FULLCHAIN_CRT="${CERT_DIR}/nginx.fullchain.crt"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }

need vault
need podman
need openssl
need curl

# jq is optional, we fall back to python3 if missing
JQ_OK=true
if ! command -v jq >/dev/null 2>&1; then
  JQ_OK=false
  need python3
fi

if [[ ! -d "$CERT_DIR" ]]; then
  echo "Cert dir not found: $CERT_DIR" >&2
  exit 1
fi

ts="$(date +%Y%m%d-%H%M%S)"
backup_dir="${CERT_DIR}/backups/${ts}"
mkdir -p "$backup_dir"

# Backup current files if they exist
for f in "$LEAF_JSON" "$LEAF_CRT" "$LEAF_KEY" "$ISSUING_CA" "$CHAIN_CRT" "$FULLCHAIN_CRT"; do
  if [[ -f "$f" ]]; then
    cp -a "$f" "$backup_dir/"
  fi
done

echo "Issuing new leaf cert from Vault (role=${ROLE}, cn=${CN}, ttl=${TTL})..."

vault write -format=json "pki-int/issue/${ROLE}" \
  common_name="${CN}" \
  alt_names="${ALT_NAMES}" \
  ip_sans="${IP_SANS}" \
  ttl="${TTL}" > "${LEAF_JSON}.tmp"

# Extract fields
if [[ "$JQ_OK" == "true" ]]; then
  jq -r .data.certificate "${LEAF_JSON}.tmp" > "${LEAF_CRT}.tmp"
  jq -r .data.private_key "${LEAF_JSON}.tmp" > "${LEAF_KEY}.tmp"
  jq -r .data.issuing_ca "${LEAF_JSON}.tmp" > "${ISSUING_CA}.tmp"

  # If ca_chain exists, build fullchain (leaf + chain array). Otherwise leaf+issuing_ca.
  if jq -e '.data.ca_chain != null' "${LEAF_JSON}.tmp" >/dev/null 2>&1; then
    : > "${FULLCHAIN_CRT}.tmp"
    cat "${LEAF_CRT}.tmp" >> "${FULLCHAIN_CRT}.tmp"
    jq -r '.data.ca_chain[]' "${LEAF_JSON}.tmp" >> "${FULLCHAIN_CRT}.tmp"
  else
    cat "${LEAF_CRT}.tmp" "${ISSUING_CA}.tmp" > "${FULLCHAIN_CRT}.tmp"
  fi

  serial="$(jq -r .data.serial_number "${LEAF_JSON}.tmp" || true)"
else
  python3 - <<PY
import json
p = "${LEAF_JSON}.tmp"
with open(p, "r", encoding="utf-8") as f:
  j = json.load(f)
d = j["data"]
open("${LEAF_CRT}.tmp","w",encoding="utf-8").write(d["certificate"])
open("${LEAF_KEY}.tmp","w",encoding="utf-8").write(d["private_key"])
open("${ISSUING_CA}.tmp","w",encoding="utf-8").write(d["issuing_ca"])
# fullchain best-effort
fc = d["certificate"] + "\n" + d["issuing_ca"] + "\n"
if d.get("ca_chain"):
  fc = d["certificate"] + "\n" + "\n".join(d["ca_chain"]) + "\n"
open("${FULLCHAIN_CRT}.tmp","w",encoding="utf-8").write(fc)
open("${LEAF_JSON}.tmp.serial","w",encoding="utf-8").write(d.get("serial_number",""))
PY
  serial="$(cat "${LEAF_JSON}.tmp.serial" 2>/dev/null || true)"
fi

# nginx uses chain for ssl_certificate, key for ssl_certificate_key
cat "${LEAF_CRT}.tmp" "${ISSUING_CA}.tmp" > "${CHAIN_CRT}.tmp"

# Atomic-ish replace
mv -f "${LEAF_JSON}.tmp" "${LEAF_JSON}"
mv -f "${LEAF_CRT}.tmp" "${LEAF_CRT}"
mv -f "${LEAF_KEY}.tmp" "${LEAF_KEY}"
mv -f "${ISSUING_CA}.tmp" "${ISSUING_CA}"
mv -f "${CHAIN_CRT}.tmp" "${CHAIN_CRT}"
mv -f "${FULLCHAIN_CRT}.tmp" "${FULLCHAIN_CRT}"

chmod 0644 "${LEAF_CRT}" "${ISSUING_CA}" "${CHAIN_CRT}" "${FULLCHAIN_CRT}" || true
chmod 0600 "${LEAF_KEY}" || true

# --- Rotation receipt (served by nginx as static JSON) ---
ROT_DIR="./shared/www/rotation"
ROT_FILE="${ROT_DIR}/last.json"
mkdir -p "${ROT_DIR}"

prev_backup_dir="${backup_dir}"
prev_serial=""
prev_fp=""

# If we backed up a previous leaf, extract its serial + fingerprint for receipts
if [[ -f "${backup_dir}/nginx.crt" ]]; then
  prev_serial="$(openssl x509 -in "${backup_dir}/nginx.crt" -noout -serial | cut -d= -f2 || true)"
  prev_fp="$(openssl x509 -in "${backup_dir}/nginx.crt" -noout -fingerprint -sha256 | cut -d= -f2 || true)"
fi

curr_serial="$(openssl x509 -in "${LEAF_CRT}" -noout -serial | cut -d= -f2 || true)"
curr_fp="$(openssl x509 -in "${LEAF_CRT}" -noout -fingerprint -sha256 | cut -d= -f2 || true)"
curr_notafter="$(openssl x509 -in "${LEAF_CRT}" -noout -enddate | cut -d= -f2 || true)"

cat > "${ROT_FILE}" <<JSON
{
  "rotatedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "commonName": "${CN}",
  "ttl": "${TTL}",
  "backupDir": "${prev_backup_dir}",
  "previous": {
    "serial": "${prev_serial}",
    "fingerprint256": "${prev_fp}"
  },
  "current": {
    "serial": "${curr_serial}",
    "fingerprint256": "${curr_fp}",
    "notAfter": "${curr_notafter}"
  }
}
JSON
# --- End rotation receipt ---

echo
echo "New cert details:"
openssl x509 -in "${LEAF_CRT}" -noout -subject -issuer -enddate -serial -fingerprint -sha256

if [[ -n "${serial}" && "${serial}" != "null" ]]; then
  echo "Vault serial_number: ${serial}"
fi

echo
echo "Testing nginx config inside container..."
podman exec nginx nginx -t

echo "Reloading nginx..."
podman exec nginx nginx -s reload

echo
echo "Verifying via dashboard endpoint:"
curl -sS "https://${CN}:8443/cert" | (command -v jq >/dev/null 2>&1 && jq . || cat)

echo
echo "Done. Backup of previous cert material is in: ${backup_dir}"