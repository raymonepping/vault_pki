#!/usr/bin/env bash
set -euo pipefail

# Certificate as a Service (CaaS) issuer for Vault PKI
# - Issues 1..N new leaf certs from a Vault PKI role (pki-int/issue/<role>)
# - Writes material to ./shared/issued/<timestamp>/cert-###/
# - Emits a summary.json receipt for “proof”
# - Best-effort validates certs using openssl verify when a root CA is available

DEFAULT_MOUNT="pki-int"
DEFAULT_ROLE="nginx"
DEFAULT_TTL="24h"
DEFAULT_COUNT="1"
DEFAULT_OUT_BASE="./shared/www/issued"
DEFAULT_CN_TEMPLATE="service-%03d.lab.local"
DEFAULT_ALT_NAMES="localhost"
DEFAULT_IP_SANS="127.0.0.1"
DEFAULT_ROOT_CA="./shared/certs/lab-root-ca.pem"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }
}
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/caas_issue.sh [options]

Options:
  --mount <name>         PKI mount name (default: pki-int)
  --role <name>          Vault PKI role (default: nginx)
  --count <n>            Number of certs to issue (default: 1)
  --ttl <ttl>            Cert TTL passed to Vault (default: 24h)

  --cn-template <tpl>    Common Name template with printf integer, like "svc-%03d.lab.local"
                         (default: service-%03d.lab.local)
  --alt-names <names>    Comma-separated alt_names (default: localhost)
  --ip-sans <ips>        Comma-separated ip_sans (default: 127.0.0.1)

  --out <dir>            Base output dir (default: ./shared/issued)
  --root-ca <path>       Root CA PEM for openssl verify (default: ./shared/certs/lab-root-ca.pem)

  --dry-run              Print what would happen, do not call Vault
  --help                 Show help

Notes:
- Requires: vault, openssl
- Uses jq if available; otherwise python3
- Assumes you already have VAULT_ADDR set and a Vault token (vault login done)
USAGE
}

MOUNT="$DEFAULT_MOUNT"
ROLE="$DEFAULT_ROLE"
COUNT="$DEFAULT_COUNT"
TTL="$DEFAULT_TTL"
CN_TEMPLATE="$DEFAULT_CN_TEMPLATE"
ALT_NAMES="$DEFAULT_ALT_NAMES"
IP_SANS="$DEFAULT_IP_SANS"
OUT_BASE="$DEFAULT_OUT_BASE"
ROOT_CA="$DEFAULT_ROOT_CA"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mount) MOUNT="${2:-}"; shift 2 ;;
    --role) ROLE="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    --ttl) TTL="${2:-}"; shift 2 ;;
    --cn-template) CN_TEMPLATE="${2:-}"; shift 2 ;;
    --alt-names) ALT_NAMES="${2:-}"; shift 2 ;;
    --ip-sans) IP_SANS="${2:-}"; shift 2 ;;
    --out) OUT_BASE="${2:-}"; shift 2 ;;
    --root-ca) ROOT_CA="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

need vault
need openssl

JQ_OK="true"
if ! have jq; then
  JQ_OK="false"
  need python3
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
  echo "--count must be an integer >= 1 (got: $COUNT)" >&2
  exit 1
fi

# JSON extraction helpers (no heredocs)
json_field() {
  # json_field <file> <key>
  local file="$1"
  local key="$2"
  if [[ "$JQ_OK" == "true" ]]; then
    jq -r --arg k "$key" '.data[$k] // ""' "$file"
  else
    python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); d=j.get("data",{}); print(d.get(sys.argv[2],"") or "")' \
      "$file" "$key"
  fi
}

json_ca_chain_to_file() {
  # json_ca_chain_to_file <file> <outfile>
  local file="$1"
  local out="$2"
  if [[ "$JQ_OK" == "true" ]]; then
    if jq -e '.data.ca_chain != null and (.data.ca_chain | length) > 0' "$file" >/dev/null 2>&1; then
      jq -r '.data.ca_chain[]' "$file" > "$out"
      return 0
    fi
    return 1
  else
    python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); chain=(j.get("data",{}) or {}).get("ca_chain") or []; 
if not chain: sys.exit(1)
open(sys.argv[2],"w",encoding="utf-8").write("\n".join(chain) + "\n")' \
      "$file" "$out"
  fi
}

ts="$(date -u +%Y%m%d-%H%M%S)"
run_dir="${OUT_BASE}/${ts}"
summary_json="${run_dir}/summary.json"
mkdir -p "${run_dir}"

echo "CaaS issuing run:"
echo "  mount       : ${MOUNT}"
echo "  role        : ${ROLE}"
echo "  count       : ${COUNT}"
echo "  ttl         : ${TTL}"
echo "  cn_template : ${CN_TEMPLATE}"
echo "  alt_names   : ${ALT_NAMES}"
echo "  ip_sans     : ${IP_SANS}"
echo "  out         : ${run_dir}"
echo

cat > "${summary_json}.tmp" <<JSON
{
  "issuedAtUtc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "mount": "${MOUNT}",
  "role": "${ROLE}",
  "ttl": "${TTL}",
  "count": ${COUNT},
  "outDir": "${run_dir}",
  "certs": [
JSON

comma=""

for i in $(seq 1 "$COUNT"); do
  cn="$(printf "$CN_TEMPLATE" "$i")"
  cert_dir="${run_dir}/cert-$(printf "%03d" "$i")"
  mkdir -p "$cert_dir"

  resp_json="${cert_dir}/vault.json"
  leaf_crt="${cert_dir}/leaf.crt"
  leaf_key="${cert_dir}/leaf.key"
  issuing_ca="${cert_dir}/issuing_ca.pem"
  chain_pem="${cert_dir}/chain.pem"
  fullchain_pem="${cert_dir}/fullchain.pem"
  meta_json="${cert_dir}/meta.json"
  verify_txt="${cert_dir}/verify.txt"

  echo "Issuing [$i/$COUNT] CN=${cn}"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  DRY RUN: vault write -format=json ${MOUNT}/issue/${ROLE} common_name=${cn} alt_names=${ALT_NAMES} ip_sans=${IP_SANS} ttl=${TTL}"
    continue
  fi

  vault write -format=json "${MOUNT}/issue/${ROLE}" \
    common_name="${cn}" \
    alt_names="${ALT_NAMES}" \
    ip_sans="${IP_SANS}" \
    ttl="${TTL}" > "${resp_json}.tmp"
  mv -f "${resp_json}.tmp" "${resp_json}"

  # Materialize files
  json_field "${resp_json}" "certificate" > "${leaf_crt}.tmp"
  json_field "${resp_json}" "private_key" > "${leaf_key}.tmp"
  json_field "${resp_json}" "issuing_ca" > "${issuing_ca}.tmp"

  mv -f "${leaf_crt}.tmp" "${leaf_crt}"
  mv -f "${leaf_key}.tmp" "${leaf_key}"
  mv -f "${issuing_ca}.tmp" "${issuing_ca}"

  chmod 0644 "${leaf_crt}" "${issuing_ca}" || true
  chmod 0600 "${leaf_key}" || true

  # Chain and fullchain
  if json_ca_chain_to_file "${resp_json}" "${chain_pem}.tmp"; then
    :
  else
    cat "${issuing_ca}" > "${chain_pem}.tmp"
  fi
  cat "${leaf_crt}" "${chain_pem}.tmp" > "${fullchain_pem}.tmp"

  mv -f "${chain_pem}.tmp" "${chain_pem}"
  mv -f "${fullchain_pem}.tmp" "${fullchain_pem}"

  # Metadata
  serial_vault="$(json_field "${resp_json}" "serial_number" | tr -d '\n' || true)"
  not_after="$(openssl x509 -in "${leaf_crt}" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
  fp_sha256="$(openssl x509 -in "${leaf_crt}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"

  cat > "${meta_json}.tmp" <<JSON
{
  "commonName": "${cn}",
  "ttl": "${TTL}",
  "serialVault": "${serial_vault}",
  "notAfter": "${not_after}",
  "fingerprintSha256": "${fp_sha256}",
  "paths": {
    "leafCrt": "leaf.crt",
    "leafKey": "leaf.key",
    "issuingCa": "issuing_ca.pem",
    "chainPem": "chain.pem",
    "fullchainPem": "fullchain.pem"
  }
}
JSON
  mv -f "${meta_json}.tmp" "${meta_json}"

  # Best-effort validation
  {
    echo "CN=${cn}"
    echo "notAfter=${not_after}"
    echo "fingerprintSha256=${fp_sha256}"
    echo
    echo "Parse check:"
    if openssl x509 -in "${leaf_crt}" -noout -subject -issuer -serial -enddate >/dev/null 2>&1; then
      echo "  ok: openssl can parse leaf.crt"
    else
      echo "  fail: openssl could not parse leaf.crt"
    fi

    echo
    if [[ -f "${ROOT_CA}" ]]; then
      echo "Verify check (using root CA: ${ROOT_CA}):"
      if openssl verify -CAfile "${ROOT_CA}" -untrusted "${chain_pem}" "${leaf_crt}" >/dev/null 2>&1; then
        echo "  ok: openssl verify succeeded"
      else
        echo "  warn: openssl verify failed"
        openssl verify -CAfile "${ROOT_CA}" -untrusted "${chain_pem}" "${leaf_crt}" 2>&1 | sed 's/^/  /'
      fi
    else
      echo "Verify check skipped (root CA not found at ${ROOT_CA})"
    fi
  } > "${verify_txt}.tmp"
  mv -f "${verify_txt}.tmp" "${verify_txt}"

  # Append to summary
  cat >> "${summary_json}.tmp" <<JSON
${comma}
    {
      "index": ${i},
      "commonName": "${cn}",
      "serialVault": "${serial_vault}",
      "notAfter": "${not_after}",
      "fingerprintSha256": "${fp_sha256}",
      "dir": "cert-$(printf "%03d" "$i")"
    }
JSON
  comma=","
done

cat >> "${summary_json}.tmp" <<JSON

  ]
}
JSON

mv -f "${summary_json}.tmp" "${summary_json}"

echo
echo "Done."
echo "Output : ${run_dir}"
echo "Receipt: ${summary_json}"

if [[ "$DRY_RUN" != "true" ]]; then
  echo
  echo "Quick peek:"
  if have jq; then
    jq -r '.certs[] | "\(.index)\t\(.commonName)\t\(.notAfter)\t\(.serialVault)"' "${summary_json}"
  else
    head -n 50 "${summary_json}"
  fi
fi
