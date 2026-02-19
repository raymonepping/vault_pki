#!/usr/bin/env bash
set -euo pipefail

# intelligent.sh
# Correlate Vault "clients" without audit logs using token accessors, token metadata,
# optional entity correlation, and optional leases.
#
# Works in Vault OSS:
# - /auth/token/accessors (list)
# - token lookup by accessor
# - /identity/entity/id (list=true) when identity is in use
# - /sys/leases/lookup traversal and lookup
#
# Notes:
# - Root token is used (as you stated).
# - Requires jq. Script checks and explains how to install it.

OUT_DIR="${OUT_DIR:-out}"
PARALLELISM="${PARALLELISM:-6}"
FETCH_LEASES="false"

log() { printf "ℹ️  %s\n" "$*" >&2; }
warn() { printf "⚠️  %s\n" "$*" >&2; }
die() {
  printf "❌ %s\n" "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --leases)
    FETCH_LEASES="${2:-false}"
    shift 2
    ;;
  --parallelism)
    PARALLELISM="${2:-6}"
    shift 2
    ;;
  --out)
    OUT_DIR="${2:-out}"
    shift 2
    ;;
  -h | --help)
    cat <<EOF
Usage: $0 [--leases true|false] [--parallelism N] [--out DIR]

Examples:
  $0
  $0 --leases true
  $0 --leases true --parallelism 10
  $0 --out out_lab --leases true
EOF
    exit 0
    ;;
  *)
    die "Unknown argument: $1"
    ;;
  esac
done

mkdir -p "$OUT_DIR"

# Recompute absolute output dir after parsing args
OUT_DIR_ABS="$(cd "$OUT_DIR" 2>/dev/null && pwd || true)"
if [[ -z "${OUT_DIR_ABS:-}" ]]; then
  mkdir -p "$OUT_DIR"
  OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

check_prereqs() {
  need_cmd vault || die "vault CLI not found. Install Vault CLI and ensure it is in PATH."
  if ! need_cmd jq; then
    cat >&2 <<'EOF'
❌ jq not found.

This script requires jq to parse JSON.
Install options:
- macOS: brew install jq
- Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y jq
- RHEL/Fedora: sudo dnf install -y jq
EOF
    exit 1
  fi
}

check_vault_session() {
  if ! vault status >/dev/null 2>&1; then
    die "vault status failed. Verify VAULT_ADDR and VAULT_TOKEN (root token) are set and reachable."
  fi
}

# Parallel xargs helper
pxargs() {
  local fn="$1"
  xargs -r -n 1 -P "$PARALLELISM" -I {} bash -lc "$fn \"{}\""
}

check_prereqs
check_vault_session

ACCESSORS_FILE="$OUT_DIR/accessors.txt"
TOKENS_JSONL="$OUT_DIR_ABS/tokens.jsonl"
: >"$TOKENS_JSONL"

log "Listing token accessors from: auth/token/accessors"

vault list -format=json auth/token/accessors |
  jq -r '
    if type == "array" then
      .[]?
    elif type == "object" then
      .data.keys[]?
    else
      empty
    end
  ' |
  tee "$ACCESSORS_FILE" >/dev/null

ACCESSOR_COUNT="$(wc -l <"$ACCESSORS_FILE" | tr -d ' ')"
log "Found $ACCESSOR_COUNT token accessors"

token_lookup_one() {
  local accessor="$1"
  local j

  mkdir -p "$(dirname "$TOKENS_JSONL")"

  j="$(vault token lookup -format=json -accessor "$accessor" 2>/dev/null || true)"
  [[ -z "$j" ]] && return 0

  echo "$j" | jq -c --arg a "$accessor" '(.data // {}) + {accessor:$a}' >>"$TOKENS_JSONL"
}
export -f token_lookup_one
export TOKENS_JSONL

log "Looking up each accessor (parallel=$PARALLELISM). This can take a while with thousands of tokens."
cat "$ACCESSORS_FILE" | pxargs token_lookup_one

log "Wrote: $TOKENS_JSONL"

# ---- Reports ----
log "Building reports..."

# 1) Count tokens with and without identity linkage
IDENTITY_STATS_TXT="$OUT_DIR/identity_stats.txt"
jq -s '
  {
    total: length,
    with_entity_id: ([.[] | select(.entity_id? and (.entity_id|tostring|test("^[0-9a-f-]{36}$")))] | length),
    missing_entity_id: ([.[] | select((.entity_id|tostring) == "n/a" or (.entity_id|tostring) == "" or (.entity_id|tostring) == "null" or (.entity_id|tostring|test("^[0-9a-f-]{36}$")|not))] | length)
  }
' "$TOKENS_JSONL" | jq -r '
  "total_tokens=\(.total)\nwith_entity_id=\(.with_entity_id)\nmissing_entity_id=\(.missing_entity_id)\n"
' >"$IDENTITY_STATS_TXT"
log "Wrote: $IDENTITY_STATS_TXT"

# 1b) Entity correlation report (if identity list is readable)
log "Attempting entity correlation report (identity/entity/id list=true)..."
ENTITIES_LIST_JSON="$OUT_DIR/entities_list.json"
TOKENS_WITH_ENTITY_CSV="$OUT_DIR/tokens_with_entity_aliases.csv"

if vault read -format=json identity/entity/id list=true >"$ENTITIES_LIST_JSON" 2>/dev/null; then
  jq -r --slurpfile ents "$ENTITIES_LIST_JSON" '
    ($ents[0].data.key_info // {}) as $key_info
    |
    select(.entity_id? and (.entity_id|tostring|test("^[0-9a-f-]{36}$")))
    | . as $t
    | ($t.entity_id|tostring) as $eid
    | ($key_info | has($eid)) as $present
    | ($key_info[$eid] // {}) as $e
    | ($e.aliases // []) as $aliases
    | ($e.name // "") as $entity_name
    | ($aliases|length) as $alias_count
    | if $alias_count == 0 then
        [
          ($t.accessor // ""),
          ($t.display_name // ""),
          ($t.path // ""),
          $eid,
          ($present|tostring),
          $entity_name,
          ($alias_count|tostring),
          "",
          "",
          "",
          ""
        ] | @csv
      else
        $aliases[]
        | [
            ($t.accessor // ""),
            ($t.display_name // ""),
            ($t.path // ""),
            $eid,
            ($present|tostring),
            $entity_name,
            ($alias_count|tostring),
            (.name // ""),
            (.mount_type // ""),
            (.mount_path // ""),
            (.mount_accessor // "")
          ] | @csv
      end
  ' "$TOKENS_JSONL" |
    awk 'BEGIN{print "\"accessor\",\"display_name\",\"token_path\",\"entity_id\",\"entity_present\",\"entity_name\",\"alias_count\",\"alias_name\",\"mount_type\",\"mount_path\",\"mount_accessor\""} {print}' \
      >"$TOKENS_WITH_ENTITY_CSV"

  log "Wrote: $TOKENS_WITH_ENTITY_CSV"
else
  warn "Could not read identity/entity/id (list=true). Skipping entity correlation report."
  : >"$ENTITIES_LIST_JSON" # keep file present but empty, downstream checks use -s
fi

# Entities inventory
ENTITIES_INVENTORY_CSV="$OUT_DIR/entities_inventory.csv"
if [[ -s "$ENTITIES_LIST_JSON" ]]; then
  jq -r '
    .data.key_info // {}
    | to_entries[]
    | .key as $entity_id
    | .value as $v
    | ($v.aliases // []) as $aliases
    | if ($aliases|length) == 0 then
        [ $entity_id, ($v.name // ""), "0", "", "", "", "" ] | @csv
      else
        $aliases[]
        | [ $entity_id, ($v.name // ""), ($aliases|length|tostring),
            (.name // ""), (.mount_type // ""), (.mount_path // ""), (.mount_accessor // "")
          ] | @csv
      end
  ' "$ENTITIES_LIST_JSON" |
    awk 'BEGIN{print "\"entity_id\",\"entity_name\",\"alias_count\",\"alias_name\",\"mount_type\",\"mount_path\",\"mount_accessor\""} {print}' \
      >"$ENTITIES_INVENTORY_CSV"
  log "Wrote: $ENTITIES_INVENTORY_CSV"
else
  : >"$ENTITIES_INVENTORY_CSV"
  warn "entities_list.json is empty. Skipping entities inventory."
fi

WITH_ENTITY_ID="$(grep '^with_entity_id=' "$IDENTITY_STATS_TXT" | cut -d= -f2 || echo "0")"
if [[ "${WITH_ENTITY_ID:-0}" == "0" ]]; then
  warn "No tokens have a usable entity_id today. Entity correlation will be heuristic (path/display_name/meta)."
  warn "This often happens when tokens are created via token auth, or identity entities/aliases are not being created by the auth methods in use."
fi

# 2) Top principals (heuristic)
TOP_PRINCIPALS_CSV="$OUT_DIR/summary_top_principals.csv"
jq -r '
  def pick_meta:
    (.meta // {}) as $m
    | {
        username: ($m.username // ""),
        user: ($m.user // ""),
        name: ($m.name // ""),
        role: ($m.role // ""),
        service_account_name: ($m.service_account_name // ""),
        service_account_namespace: ($m.service_account_namespace // ""),
        approle_name: ($m.role_name // ""),
        client_id: ($m.client_id // "")
      };

  def principal_key:
    pick_meta as $pm
    | [
        (.path // ""),
        (.display_name // ""),
        ($pm.username // $pm.user // $pm.name // ""),
        ($pm.role // $pm.approle_name // ""),
        (
          if ($pm.service_account_name != "" or $pm.service_account_namespace != "") then
            ($pm.service_account_namespace + ":" + $pm.service_account_name)
          else
            ""
          end
        ),
        ($pm.client_id // "")
      ] | @tsv;

  principal_key
' "$TOKENS_JSONL" |
  awk -F'\t' '{ key=$0; c[key]++ } END { for (k in c) print c[k] "\t" k }' |
  sort -nr |
  head -n 200 |
  awk -F'\t' '
    BEGIN { print "token_count,token_path,display_name,meta_user,meta_role,meta_k8s_sa,meta_client_id" }
    { printf "%s,%s,%s,%s,%s,%s,%s\n", $1,$2,$3,$4,$5,$6,$7 }
  ' >"$TOP_PRINCIPALS_CSV"
log "Wrote: $TOP_PRINCIPALS_CSV"

# 3) Summary by auth/token path prefix
BY_AUTH_PATH_CSV="$OUT_DIR/summary_by_auth_path.csv"
tmp_counts="$(mktemp)"
jq -r '(.path // "unknown")' "$TOKENS_JSONL" |
  awk '
    {
      p=$0
      n=split(p,a,"/")
      if (n>=2) k=a[1]"/"a[2]
      else k=p
      c[k]++
    }
    END { for (k in c) print c[k] "," k }
  ' | sort -t, -nr -k1,1 >"$tmp_counts"

{
  echo "token_count,auth_path_group"
  cat "$tmp_counts"
} >"$BY_AUTH_PATH_CSV"
rm -f "$tmp_counts"
log "Wrote: $BY_AUTH_PATH_CSV"

# 4) Export tokens missing identity
MISSING_IDENTITY_CSV="$OUT_DIR/tokens_missing_identity.csv"
jq -r '
  def is_uuid: test("^[0-9a-f-]{36}$");
  select(
    (.entity_id|tostring) == "n/a"
    or (.entity_id|tostring) == ""
    or (.entity_id|tostring) == "null"
    or ((.entity_id|tostring)|is_uuid|not)
  )
  | [
      (.accessor // ""),
      (.display_name // ""),
      (.path // ""),
      ((.policies // []) | join("|")),
      (.ttl // ""),
      (.expire_time // ""),
      (.issue_time // ""),
      ((.meta // {}) | tostring)
    ] | @csv
' "$TOKENS_JSONL" |
  awk 'BEGIN{print "\"accessor\",\"display_name\",\"path\",\"policies\",\"ttl\",\"expire_time\",\"issue_time\",\"meta\""} {print}' \
    >"$MISSING_IDENTITY_CSV"
log "Wrote: $MISSING_IDENTITY_CSV"

# ---- Leases (optional) ----
if [[ "$FETCH_LEASES" == "true" ]]; then
  log "Leases enabled. Lease probe: checking if sys/leases/lookup has any keys..."
  LEASE_PROBE="$(vault list -format=json sys/leases/lookup 2>/dev/null || true)"

  if [[ -z "$LEASE_PROBE" ]]; then
    warn "Lease probe: no response from sys/leases/lookup. With a root token this is unusual."
  else
    LEASE_KEY_COUNT="$(echo "$LEASE_PROBE" | jq -r '
      if type=="array" then length
      elif type=="object" then (.data.keys|length)
      else 0 end
    ' 2>/dev/null || echo "0")"

    if [[ "$LEASE_KEY_COUNT" == "0" ]]; then
      warn "Lease probe: sys/leases/lookup returned 0 keys. This usually means there are no active leases in this Vault."
      warn "If you expect leases, ensure an auth method is issuing renewable tokens or a secrets engine is issuing dynamic creds."
    else
      log "Lease probe: sys/leases/lookup returned $LEASE_KEY_COUNT top-level keys."
    fi
  fi

  log "Walking sys/leases/lookup tree..."
  LEASE_IDS_FILE="$OUT_DIR/lease_ids.txt"
  LEASES_JSONL="$OUT_DIR_ABS/leases.jsonl"
  : >"$LEASE_IDS_FILE"
  : >"$LEASES_JSONL"

  vault_list_keys() {
    local path="$1"
    local j
    j="$(vault list -format=json "$path" 2>/dev/null || true)"
    [[ -z "$j" ]] && return 0

    echo "$j" | jq -r '
      if type == "array" then .[]?
      elif type == "object" then .data.keys[]?
      else empty
      end
    ' | sed 's:/*$::'
  }

  walk_leases() {
    local prefix="$1"
    local keys
    keys="$(vault_list_keys "$prefix" || true)"
    [[ -z "$keys" ]] && return 0

    while IFS= read -r k; do
      [[ -z "$k" ]] && continue

      local child="${prefix%/}/${k}"
      local subkeys
      subkeys="$(vault_list_keys "$child" || true)"
      if [[ -z "$subkeys" ]]; then
        local lease_path="${child#sys/leases/lookup/}"
        while [[ "$lease_path" == *"//"* ]]; do
          lease_path="${lease_path//\/\//\/}"
        done
        echo "$lease_path" >>"$LEASE_IDS_FILE"
      else
        walk_leases "$child"
      fi
    done <<<"$keys"
  }

  lease_lookup_one() {
    local lease_id="$1"
    local j

    mkdir -p "$(dirname "$LEASES_JSONL")"

    while [[ "$lease_id" == *"//"* ]]; do
      lease_id="${lease_id//\/\//\/}"
    done

    j="$(vault write -format=json sys/leases/lookup "lease_id=$lease_id" 2>/dev/null || true)"
    [[ -z "$j" ]] && return 0

    echo "$j" | jq -c --arg id "$lease_id" '(.data // {}) + {lease_id:$id}' >>"$LEASES_JSONL"
  }

  export -f lease_lookup_one
  export LEASES_JSONL

  walk_leases "sys/leases/lookup"

  sort -u "$LEASE_IDS_FILE" -o "$LEASE_IDS_FILE"
  LEASE_COUNT="$(wc -l <"$LEASE_IDS_FILE" | tr -d ' ')"

  if [[ "$LEASE_COUNT" == "0" ]]; then
    warn "No lease IDs discovered under sys/leases/lookup. leases.jsonl will remain empty."
  else
    log "Found $LEASE_COUNT lease IDs. Looking them up (parallel=$PARALLELISM)..."
    cat "$LEASE_IDS_FILE" | pxargs lease_lookup_one
    log "Wrote: $LEASES_JSONL"

    LEASES_BY_PREFIX_CSV="$OUT_DIR/summary_leases_by_prefix.csv"
    tmp_lease_counts="$(mktemp)"

    if [[ -s "$LEASE_IDS_FILE" ]]; then
      awk '
        NF {
          p=$0
          gsub(/\/+/, "/", p)
          n=split(p,a,"/")
          if (n>=2) k=a[1]"/"a[2]
          else k=p
          c[k]++
        }
        END { for (k in c) print c[k] "," k }
      ' "$LEASE_IDS_FILE" | sort -t, -nr -k1,1 >"$tmp_lease_counts"
    fi

    {
      echo "lease_count,lease_prefix_group"
      cat "$tmp_lease_counts" 2>/dev/null || true
    } >"$LEASES_BY_PREFIX_CSV"
    rm -f "$tmp_lease_counts"
    log "Wrote: $LEASES_BY_PREFIX_CSV"

    LEASES_SUSPICIOUS_CSV="$OUT_DIR/leases_suspicious_ttl.csv"
    # Be null-safe: ttl can be null in some lease payloads
    jq -r '
      select((.ttl // 0) | tonumber < 0)
      | [(.lease_id // ""), ((.ttl // "")|tostring), (.issue_time // ""), (.expire_time // ""), (.renewable|tostring)] | @csv
    ' "$LEASES_JSONL" |
      awk 'BEGIN{print "\"lease_id\",\"ttl\",\"issue_time\",\"expire_time\",\"renewable\""} {print}' \
        >"$LEASES_SUSPICIOUS_CSV"
    log "Wrote: $LEASES_SUSPICIOUS_CSV"
  fi
else
  log "Leases disabled. Run with: --leases true"
fi

# ---- KPIs (compute BEFORE principal summaries so we can pass totals safely) ----
KPIS_CSV="$OUT_DIR/summary_kpis.csv"

TOTAL_TOKENS="$(wc -l <"$TOKENS_JSONL" | tr -d ' ')"
UNIQUE_ENTITY_IDS="$(jq -r 'select(.entity_id? and (.entity_id|tostring|test("^[0-9a-f-]{36}$"))) | .entity_id' "$TOKENS_JSONL" | sort -u | wc -l | tr -d ' ')"
TOTAL_LEASES="0"
[[ -f "$OUT_DIR/lease_ids.txt" ]] && TOTAL_LEASES="$(wc -l <"$OUT_DIR/lease_ids.txt" | tr -d ' ')"

UNIQUE_ALIASES="0"
if [[ -f "$ENTITIES_INVENTORY_CSV" && -s "$ENTITIES_INVENTORY_CSV" ]]; then
  UNIQUE_ALIASES="$(awk -F, 'NR>1 {gsub(/"/,"",$4); if ($4!="") print $4}' "$ENTITIES_INVENTORY_CSV" | sort -u | wc -l | tr -d ' ')"
fi

ALIAS_INFLATION_FACTOR="n/a"
if [[ "${UNIQUE_ALIASES:-0}" != "0" ]]; then
  ALIAS_INFLATION_FACTOR="$(awk -v t="$TOTAL_TOKENS" -v a="$UNIQUE_ALIASES" 'BEGIN{ printf "%.2f", (t/a) }')"
fi

ENTITY_INFLATION_FACTOR="n/a"
if [[ "${UNIQUE_ENTITY_IDS:-0}" != "0" ]]; then
  ENTITY_INFLATION_FACTOR="$(awk -v t="$TOTAL_TOKENS" -v e="$UNIQUE_ENTITY_IDS" 'BEGIN{ printf "%.2f", (t/e) }')"
fi

TOP_AUTH_GROUP="$(tail -n +2 "$OUT_DIR/summary_by_auth_path.csv" 2>/dev/null | head -n 1 || true)"

# ---- Principal summaries ----
PRINCIPALS_CSV="$OUT_DIR/summary_principals.csv"
PRINCIPALS_TOP_CSV="$OUT_DIR/summary_principals_top.csv"

# ---- Combined principal summary (identity if available, otherwise heuristic) ----
PRINCIPALS_COMBINED_CSV="$OUT_DIR/summary_principals_combined.csv"
PRINCIPALS_COMBINED_TOP_CSV="$OUT_DIR/summary_principals_combined_top.csv"

TOTAL_TOKENS="$(wc -l <"$TOKENS_JSONL" | tr -d ' ')"

# Build an entity_id -> aliases map (may be empty if identity not available)
KEY_INFO_JSON="{}"
if [[ -f "$ENTITIES_LIST_JSON" && -s "$ENTITIES_LIST_JSON" ]]; then
  KEY_INFO_JSON="$(jq -c '.data.key_info // {}' "$ENTITIES_LIST_JSON" 2>/dev/null || echo "{}")"
fi

# Export TOTAL_TOKENS for jq (so we don't parse null)
export TOTAL_TOKENS

jq -c --argjson key_info "$KEY_INFO_JSON" '
  def is_uuid: test("^[0-9a-f-]{36}$");

  def auth_group(p):
    if (p|startswith("auth/")) then
      (p | split("/") | .[0] + "/" + .[1])
    else "unknown"
    end;

  def sorted_policies:
    ((.policies // []) | map(tostring) | sort | unique | join("|"));

  def meta_kv_string:
    if (.meta // null) == null then
      "no-meta"
    else
      (.meta
        | to_entries
        | map("\(.key)=\(.value|tostring)")
        | sort
        | join(";")
      )
    end;

    def ttl_bucket:
    # remaining ttl changes constantly, so bucket it
    # uses seconds (Vault typically returns ttl as seconds)
    ((.ttl // null) as $t
        | if $t == null then "ttl=na"
        else
            ($t | tonumber) as $s
            | if $s <= 0 then "ttl=expired"
            elif $s < 300 then "ttl=<5m"
            elif $s < 900 then "ttl=<15m"
            elif $s < 1800 then "ttl=<30m"
            elif $s < 3600 then "ttl=<1h"
            elif $s < 21600 then "ttl=<6h"
            elif $s < 86400 then "ttl=<24h"
            else "ttl>=24h"
            end
        end);

    def has_period:
    if (.period // null) == null then "period=false" else "period=true" end;

    def lifecycle_sig:
    [
        "type=" + ((.type // .token_type // "") | tostring),
        "orphan=" + ((.orphan // false) | tostring),
        "renewable=" + ((.renewable // false) | tostring),
        has_period,
        ttl_bucket
    ] | join(";");

  . as $t
  | ($t.entity_id // "" | tostring) as $eid
  | ($eid | is_uuid) as $has_entity
  | ($key_info[$eid] // {}) as $e
  | ($e.aliases // []) as $aliases
  | ($aliases | length) as $alias_count
  | ($t | meta_kv_string) as $mk
  | ($t | sorted_policies) as $pk
  | (auth_group($t.path // "unknown")) as $ag
  | ($t | lifecycle_sig) as $ls

  | if ($has_entity and $alias_count > 0) then
      $aliases[]
      | {
          principal_method: "identity",
          principal_key: ((.mount_type // "unknown") + "|" + (.mount_path // "unknown") + "|" + (.name // "no-alias")),
          mount_type: (.mount_type // "unknown"),
          mount_path: (.mount_path // "unknown"),
          alias_name: (.name // "no-alias"),
          token_path: ($t.path // ""),
          display_name: ($t.display_name // ""),
          policies: $pk,
          entity_id: $eid
        }
    else
      {
        principal_method: "heuristic",
        principal_key: ($ag + "|" + ($t.display_name // "unknown") + "|" + $mk + "|" + $pk + "|" + $ls),
        mount_type: "n/a",
        mount_path: "n/a",
        alias_name: "n/a",
        token_path: ($t.path // ""),
        display_name: ($t.display_name // ""),
        policies: $pk,
        entity_id: (if $has_entity then $eid else "" end)
      }
    end
' "$TOKENS_JSONL" |
  jq -s '
    group_by(.principal_key)
    | map({
        token_count: length,
        token_share_pct: (
          if ((env.TOTAL_TOKENS|tonumber) > 0) then
            (length / (env.TOTAL_TOKENS|tonumber) * 100)
          else 0 end
        ),
        distinct_entity_ids: (map(.entity_id) | map(select(. != "")) | unique | length),
        principal_method: (map(.principal_method) | unique | join("|")),
        principal_key: .[0].principal_key,
        mount_type: .[0].mount_type,
        mount_path: .[0].mount_path,
        alias_name: .[0].alias_name,
        token_path: .[0].token_path,
        display_name: .[0].display_name,
        policies: .[0].policies
    })
    | sort_by(-.token_count)
' |
  jq -r '
    (["token_count","token_share_pct","distinct_entity_ids","principal_method","principal_key","mount_type","mount_path","alias_name","token_path","display_name","policies"] | @csv),
    (.[] | [(.token_count|tostring), (.token_share_pct|tostring), (.distinct_entity_ids|tostring), .principal_method, .principal_key, .mount_type, .mount_path, .alias_name, .token_path, .display_name, .policies] | @csv)
' >"$PRINCIPALS_COMBINED_CSV"

{
  head -n 1 "$PRINCIPALS_COMBINED_CSV"
  tail -n +2 "$PRINCIPALS_COMBINED_CSV" | head -n 50
} >"$PRINCIPALS_COMBINED_TOP_CSV"

log "Wrote: $PRINCIPALS_COMBINED_CSV"
log "Wrote: $PRINCIPALS_COMBINED_TOP_CSV"

# ---- Identity-based principals (only when identity list is available) ----
if [[ -s "$ENTITIES_LIST_JSON" ]]; then
  jq -r --slurpfile ents "$ENTITIES_LIST_JSON" '
    ($ents[0].data.key_info // {}) as $key_info
    |
    select(.entity_id? and (.entity_id|tostring|test("^[0-9a-f-]{36}$")))
    | (.entity_id|tostring) as $eid
    | ($key_info[$eid] // {}) as $e
    | ($e.aliases // []) as $aliases
    | if ($aliases|length) == 0 then
        {
          principal_key: "unknown|unknown|no-alias",
          mount_type: "unknown",
          mount_path: "unknown",
          alias_name: "no-alias",
          entity_id: $eid
        }
      else
        $aliases[]
        | {
            principal_key: ((.mount_type // "unknown") + "|" + (.mount_path // "unknown") + "|" + (.name // "no-alias")),
            mount_type: (.mount_type // "unknown"),
            mount_path: (.mount_path // "unknown"),
            alias_name: (.name // "no-alias"),
            entity_id: $eid
          }
      end
  ' "$TOKENS_JSONL" |
    jq -s '
      group_by(.principal_key)
      | map({
          token_count: length,
          distinct_entity_ids: (map(.entity_id) | unique | length),
          principal_key: .[0].principal_key,
          mount_type: .[0].mount_type,
          mount_path: .[0].mount_path,
          alias_name: .[0].alias_name
        })
      | sort_by(-.token_count)
    ' |
    jq -r '
      (["token_count","distinct_entity_ids","principal_key","mount_type","mount_path","alias_name"] | @csv),
      (.[] | [(.token_count|tostring), (.distinct_entity_ids|tostring), .principal_key, .mount_type, .mount_path, .alias_name] | @csv)
    ' >"$PRINCIPALS_CSV"

  {
    echo "\"token_count\",\"token_share_pct\",\"distinct_entity_ids\",\"principal_class\",\"principal_key\",\"mount_type\",\"mount_path\",\"alias_name\""
    tail -n +2 "$PRINCIPALS_CSV" |
      awk -F, -v total="$TOTAL_TOKENS" '
        BEGIN { OFS="," }
        {
          for (i=1; i<=NF; i++) { gsub(/^"/,"",$i); gsub(/"$/,"",$i) }

          token_count=$1
          distinct_entities=$2
          principal_key=$3
          mount_type=$4
          mount_path=$5
          alias_name=$6

          share = (total>0) ? (token_count/total*100.0) : 0

          pclass="unknown"
          if (mount_type=="userpass" || mount_type=="ldap" || mount_type=="oidc" || mount_type=="github") pclass="human"
          else if (mount_type=="approle" || mount_type=="kubernetes" || mount_type=="jwt") pclass="machine"

          printf "\"%s\",\"%.2f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", token_count, share, distinct_entities, pclass, principal_key, mount_type, mount_path, alias_name
        }
      ' |
      head -n 50
  } >"$PRINCIPALS_TOP_CSV"

  log "Wrote: $PRINCIPALS_CSV"
  log "Wrote: $PRINCIPALS_TOP_CSV"
else
  warn "entities_list.json not found or empty. Skipping identity-based principal summary."
  : >"$PRINCIPALS_CSV"
  : >"$PRINCIPALS_TOP_CSV"
fi

# Unique principals based on identity correlation (mount+alias)
UNIQUE_PRINCIPALS_IDENTITY="0"
if [[ -s "$PRINCIPALS_CSV" ]]; then
  UNIQUE_PRINCIPALS_IDENTITY="$(tail -n +2 "$PRINCIPALS_CSV" | wc -l | tr -d ' ')"
fi

# Now that we have unique principals, write KPIs (final)
{
  echo "metric,value"
  echo "total_tokens,$TOTAL_TOKENS"
  echo "unique_entity_ids,$UNIQUE_ENTITY_IDS"
  echo "unique_alias_names,$UNIQUE_ALIASES"
  echo "unique_principals_identity,$UNIQUE_PRINCIPALS_IDENTITY"
  echo "entity_inflation_factor,$ENTITY_INFLATION_FACTOR"
  echo "alias_inflation_factor,$ALIAS_INFLATION_FACTOR"
  echo "total_leases,$TOTAL_LEASES"
  echo "top_auth_group,\"$TOP_AUTH_GROUP\""
} >"$KPIS_CSV"
log "Wrote: $KPIS_CSV"

# ---- brief.md (always) ----
BRIEF_MD="$OUT_DIR/brief.md"
{
  set +e

  echo "# Vault client correlation brief"
  echo
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo
  echo "## KPI snapshot"
  if [[ -f "$OUT_DIR/summary_kpis.csv" ]]; then
    echo
    echo '```csv'
    cat "$OUT_DIR/summary_kpis.csv"
    echo '```'
  else
    echo "- summary_kpis.csv not found"
  fi

  echo
  echo "## Interpretation"
  if [[ -f "$OUT_DIR/summary_kpis.csv" ]]; then
    ktokens="$(awk -F, '$1=="total_tokens"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    kent="$(awk -F, '$1=="unique_entity_ids"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    kalias="$(awk -F, '$1=="unique_alias_names"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    kprin="$(awk -F, '$1=="unique_principals_identity"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    einf="$(awk -F, '$1=="entity_inflation_factor"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    ainf="$(awk -F, '$1=="alias_inflation_factor"{print $2}' "$OUT_DIR/summary_kpis.csv")"
    kauth="$(awk -F, '$1=="top_auth_group"{print $2}' "$OUT_DIR/summary_kpis.csv")"

    echo "- Tokens observed: $ktokens"
    echo "- Identity entities observed: $kent (entity inflation: $einf tokens per entity)"
    echo "- Identity aliases observed: $kalias (alias inflation: $ainf tokens per alias)"
    echo "- Identity-based principals (mount+alias): $kprin"
    echo "- Dominant auth source: $kauth"
    echo
    echo "Note: In small lab runs it is normal to see more aliases than active tokens (alias inflation < 1.0). In customer environments, long-running automation often drives the opposite."
  else
    echo "- KPI snapshot missing, cannot interpret."
  fi

  echo
  echo "## Top token creation paths"
  if [[ -f "$OUT_DIR/summary_by_auth_path.csv" ]]; then
    echo
    echo '```csv'
    head -n 20 "$OUT_DIR/summary_by_auth_path.csv"
    echo '```'
  else
    echo "- summary_by_auth_path.csv not found"
  fi

  echo
  echo "## Top principals (heuristic)"
  if [[ -f "$OUT_DIR/summary_top_principals.csv" ]]; then
    echo
    echo '```csv'
    head -n 20 "$OUT_DIR/summary_top_principals.csv"
    echo '```'
  else
    echo "- summary_top_principals.csv not found"
  fi

  echo
  echo "## Principal summary (combined)"
  if [[ -f "$OUT_DIR/summary_principals_combined_top.csv" ]]; then
    echo
    echo '```csv'
    head -n 30 "$OUT_DIR/summary_principals_combined_top.csv"
    echo '```'
  else
    echo "- summary_principals_combined_top.csv not found"
  fi

  echo
  echo "## Principal summary (identity-based)"
  if [[ -f "$OUT_DIR/summary_principals_top.csv" ]]; then
    echo
    echo '```csv'
    head -n 30 "$OUT_DIR/summary_principals_top.csv"
    echo '```'
  else
    echo "- summary_principals_top.csv not found"
  fi

  echo
  echo "## Entity correlation"
  if [[ -f "$OUT_DIR/tokens_with_entity_aliases.csv" ]]; then
    echo
    echo '```csv'
    head -n 20 "$OUT_DIR/tokens_with_entity_aliases.csv"
    echo '```'
  else
    echo "- tokens_with_entity_aliases.csv not found"
  fi

  echo
  echo "## Leases"
  if [[ "$FETCH_LEASES" == "true" && -f "$OUT_DIR/summary_leases_by_prefix.csv" ]]; then
    echo
    echo '```csv'
    head -n 30 "$OUT_DIR/summary_leases_by_prefix.csv"
    echo '```'
  else
    echo "- Leases not collected or no leases present"
  fi
} >"$BRIEF_MD"

log "Wrote: $BRIEF_MD"
log "Done. Review outputs in: $OUT_DIR"
log "Suggested starting point: summary_by_auth_path.csv then summary_top_principals.csv"
