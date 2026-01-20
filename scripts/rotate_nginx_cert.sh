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

# macOS trust store install (optional)
TRUST_ROOT_CA="${TRUST_ROOT_CA:-false}"    # true|false
TRUST_FORCE="${TRUST_FORCE:-false}"        # true|false
ROOT_CA_PEM="${ROOT_CA_PEM:-./shared/certs/lab-root-ca.pem}"
ROOT_CA_CN="${ROOT_CA_CN:-lab.local Root CA}"

usage() {
  cat <<'EOF'
Usage:
  rotate_nginx_cert.sh [options]

Options:
  --trust-root-ca        Install/ensure lab Root CA is trusted in macOS System keychain (requires sudo)
  --trust-force          Re-add Root CA even if it is already present
  --root-ca=PATH         Root CA PEM path (default: ./shared/certs/lab-root-ca.pem)
  --root-ca-cn=CN        CN to search in System keychain (default: lab.local Root CA)
  --nginx-container=NAME Explicit nginx container name/id (overrides auto-detection)
  -h, --help             Show this help

Environment:
  ROLE, CN, ALT_NAMES, IP_SANS, TTL
  CERT_DIR
  TRUST_ROOT_CA, TRUST_FORCE, ROOT_CA_PEM, ROOT_CA_CN
  NGINX_CONTAINER
EOF
}

for arg in "$@"; do
  case "$arg" in
    --trust-root-ca) TRUST_ROOT_CA="true" ;;
    --trust-force)   TRUST_FORCE="true" ;;
    --root-ca=*)     ROOT_CA_PEM="${arg#*=}" ;;
    --root-ca-cn=*)  ROOT_CA_CN="${arg#*=}" ;;
    --nginx-container=*) NGINX_CONTAINER="${arg#*=}" ;;
    -h|--help) usage; exit 0 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }

install_root_ca_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Skipping root CA trust install (not macOS)."
    return 0
  fi

  if [[ ! -f "$ROOT_CA_PEM" ]]; then
    echo "Root CA PEM not found: $ROOT_CA_PEM" >&2
    return 1
  fi

  echo
  echo "Root CA to trust: $ROOT_CA_PEM"
  openssl x509 -in "$ROOT_CA_PEM" -noout -subject -issuer || true

  if security find-certificate -c "$ROOT_CA_CN" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    if [[ "$TRUST_FORCE" != "true" ]]; then
      echo "Root CA already present in System.keychain (CN=$ROOT_CA_CN). Skipping."
      return 0
    fi
    echo "Root CA already present, but TRUST_FORCE=true. Re-adding anyway."
  fi

  echo "Installing Root CA into macOS System.keychain (requires sudo)..."
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$ROOT_CA_PEM"

  echo "Verifying trust store entry:"
  security find-certificate -c "$ROOT_CA_CN" /Library/Keychains/System.keychain | sed -n '1,40p' || true
}

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

# --- Find nginx container (do not assume it's literally named "nginx") ---
NGINX_CONTAINER="${NGINX_CONTAINER:-}"

if [[ -z "${NGINX_CONTAINER}" ]]; then
  # Prefer an exact container_name: nginx if present, else fall back to compose-style *_nginx
  if podman ps --format '{{.Names}}' | grep -qx 'nginx'; then
    NGINX_CONTAINER='nginx'
  else
    NGINX_CONTAINER="$(podman ps --format '{{.Names}}' | grep -E '(^|_)nginx$' | head -n1 || true)"
  fi
fi

if [[ -z "${NGINX_CONTAINER}" ]]; then
  echo "ERROR: Could not find a running nginx container." >&2
  echo "Running containers:" >&2
  podman ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}" >&2
  exit 1
fi

echo "Using nginx container: ${NGINX_CONTAINER}"
# --- End nginx container lookup ---

echo
echo "Testing nginx config inside container..."
podman exec "${NGINX_CONTAINER}" nginx -t

echo "Reloading nginx..."
podman exec "${NGINX_CONTAINER}" nginx -s reload

if [[ "$TRUST_ROOT_CA" == "true" ]]; then
  install_root_ca_macos
fi

echo
echo "Verifying via dashboard endpoint:"
curl -sS "https://${CN}:8443/cert" | (command -v jq >/dev/null 2>&1 && jq . || cat)

echo
echo "Done. Backup of previous cert material is in: ${backup_dir}"
