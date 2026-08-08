#!/usr/bin/env bash
#
# ASN UFW blocklist manager
#
# Usage:
#
#   sudo ./block_asn.sh block AS215117
#   sudo ./block_asn.sh unblock AS215117
#   sudo ./block_asn.sh sync AS215117
#   sudo ./block_asn.sh sync-all
#   sudo ./block_asn.sh sync-blocklist
#   sudo ./block_asn.sh list
#   sudo ./block_asn.sh status
#
# blocklist.txt format:
#
#   # ASN | Name
#   AS215117 | HOSTERDADDY
#
# Requires:
#   ufw
#   curl
#   flock
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKLIST="${SCRIPT_DIR}/blocklist.txt"
LOCKFILE="/var/run/block_asn.lock"

BASE_URL="https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as"

# Master blocklist URLs — override via environment if needed.
MASTER_ASN_URL="${MASTER_ASN_URL:-https://github.com/AS219412/firewall-blocklist/raw/refs/heads/main/asns.txt}"
MASTER_IPV4_URL="${MASTER_IPV4_URL:-https://github.com/AS219412/firewall-blocklist/raw/refs/heads/main/ipv4.txt}"
MASTER_IPV6_URL="${MASTER_IPV6_URL:-https://github.com/AS219412/firewall-blocklist/raw/refs/heads/main/ipv6.txt}"

# UFW comment tag used to identify master-blocklist IP rules.
MASTER_IP_TAG="MASTER_BLOCKLIST"

#
# ------------------------------------------------------------
# General helpers
# ------------------------------------------------------------
#

die() {
    echo "ERROR: $*" >&2
    exit 1
}

normalize_asn() {
    local input="$1"
    input="${input^^}"
    input="${input#AS}"
    [[ "$input" =~ ^[0-9]+$ ]] || die "Invalid ASN: $1"
    echo "AS${input}"
}

asn_number() {
    local asn="$1"
    echo "${asn#AS}"
}

ensure_blocklist() {
    if [[ ! -f "$BLOCKLIST" ]]; then
        printf '# ASN | Name\n' > "$BLOCKLIST"
        chmod 600 "$BLOCKLIST"
    fi
}

fetch_url() {
    local url="$1"
    local dest="$2"
    local label="${3:-$url}"

    echo "Fetching ${label}..."
    if ! curl -fsSL --retry 3 --connect-timeout 10 "$url" -o "$dest"; then
        echo "ERROR: Failed to fetch ${label}."
        return 1
    fi
}

#
# ------------------------------------------------------------
# Read ASN name from ipverse file
# ------------------------------------------------------------
#

get_asn_name() {
    local file="$1"
    local asn="$2"
    sed -nE "s/^# ${asn} \(([^)]*)\).*/\1/p" "$file" | head -n 1
}

#
# ------------------------------------------------------------
# blocklist.txt management
# ------------------------------------------------------------
#

is_blocked() {
    local asn="$1"
    grep -qE "^${asn}[[:space:]]*\|" "$BLOCKLIST"
}

add_to_blocklist() {
    local asn="$1"
    local name="$2"

    ensure_blocklist

    local tmp
    tmp=$(mktemp)

    grep -vE "^${asn}[[:space:]]*\|" "$BLOCKLIST" > "$tmp" || true
    echo "${asn} | ${name}" >> "$tmp"

    {
        grep '^#' "$tmp" || true
        grep -E '^AS[0-9]+[[:space:]]*\|' "$tmp" | sort -V || true
    } > "${tmp}.sorted"

    mv "${tmp}.sorted" "$BLOCKLIST"
    rm -f "$tmp"
    chmod 600 "$BLOCKLIST"
}

remove_from_blocklist() {
    local asn="$1"

    ensure_blocklist

    local tmp
    tmp=$(mktemp)

    grep -vE "^${asn}[[:space:]]*\|" "$BLOCKLIST" > "$tmp" || true
    mv "$tmp" "$BLOCKLIST"
    chmod 600 "$BLOCKLIST"
}

#
# ------------------------------------------------------------
# UFW rule management
# ------------------------------------------------------------
#

# Remove all UFW rules whose comment matches the given sed pattern.
remove_ufw_rules_by_comment() {
    local comment_pattern="$1"
    local label="${2:-$comment_pattern}"

    echo "Removing existing UFW rules for: ${label}..."

    local rule_numbers
    rule_numbers=$(
        ufw status numbered |
        sed -nE "s/^\[ *([0-9]+)\].*# ${comment_pattern}.*/\1/p" |
        sort -rn
    )

    if [[ -z "$rule_numbers" ]]; then
        echo "  No existing UFW rules found."
        return 0
    fi

    while IFS= read -r rule_number; do
        [[ -z "$rule_number" ]] && continue
        echo "  Deleting UFW rule #${rule_number}"
        ufw --force delete "$rule_number" >/dev/null
    done <<< "$rule_numbers"
}

remove_ufw_rules() {
    local asn="$1"
    remove_ufw_rules_by_comment "${asn} \|" "$asn"
}

#
# ------------------------------------------------------------
# Sync one ASN from ipverse
# ------------------------------------------------------------
#

sync_asn() {
    local asn="$1"
    local number

    number=$(asn_number "$asn")

    local ipv4_url="${BASE_URL}/${number}/ipv4-aggregated.txt"
    local ipv6_url="${BASE_URL}/${number}/ipv6-aggregated.txt"

    local tmp4 tmp6
    tmp4=$(mktemp)
    tmp6=$(mktemp)

    echo
    echo "========================================"
    echo "Syncing ${asn}"
    echo "========================================"

    if ! fetch_url "$ipv4_url" "$tmp4" "IPv4 list"; then
        rm -f "$tmp4" "$tmp6"
        echo "Existing UFW rules were NOT changed."
        return 1
    fi

    if ! fetch_url "$ipv6_url" "$tmp6" "IPv6 list"; then
        rm -f "$tmp4" "$tmp6"
        echo "Existing UFW rules were NOT changed."
        return 1
    fi

    local name=""
    name=$(get_asn_name "$tmp4" "$asn")
    [[ -z "$name" ]] && name=$(get_asn_name "$tmp6" "$asn")

    if [[ -z "$name" ]]; then
        rm -f "$tmp4" "$tmp6"
        echo "ERROR: Could not determine ASN name."
        echo "Existing UFW rules were NOT changed."
        return 1
    fi

    local comment="${asn} | ${name}"

    local ipv4_count ipv6_count total_count
    ipv4_count=$(grep -Ec '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$tmp4" || true)
    ipv6_count=$(grep -Ec '^[0-9a-fA-F:]+/[0-9]+$' "$tmp6" || true)
    total_count=$(( ipv4_count + ipv6_count ))

    if [[ "$total_count" -eq 0 ]]; then
        rm -f "$tmp4" "$tmp6"
        echo "ERROR: No IP ranges found."
        echo "Existing UFW rules were NOT changed."
        return 1
    fi

    echo "ASN name:    ${name}"
    echo "Comment:     ${comment}"
    echo "IPv4 ranges: ${ipv4_count}"
    echo "IPv6 ranges: ${ipv6_count}"
    echo "Total:       ${total_count}"

    remove_ufw_rules "$asn"

    if [[ "$ipv4_count" -gt 0 ]]; then
        echo
        echo "Adding IPv4 ranges..."
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
            echo "  DENY ${line}"
            ufw prepend deny from "$line" comment "$comment" >/dev/null
        done < "$tmp4"
    fi

    if [[ "$ipv6_count" -gt 0 ]]; then
        echo
        echo "Adding IPv6 ranges..."
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            [[ "$line" =~ ^[0-9a-fA-F:]+/[0-9]+$ ]] || continue
            echo "  DENY ${line}"
            ufw prepend deny from "$line" comment "$comment" >/dev/null
        done < "$tmp6"
    fi

    rm -f "$tmp4" "$tmp6"

    add_to_blocklist "$asn" "$name"

    echo
    echo "Sync complete: ${asn} (${total_count} ranges)"
    return 0
}

#
# ------------------------------------------------------------
# sync-blocklist: pull master ASN + IP lists and apply to UFW
#
# ASN entries are expanded via ipverse (same as sync_asn).
# IP entries are applied directly as individual UFW rules,
# tagged with MASTER_BLOCKLIST so they can be cleanly replaced
# on the next sync without touching manually-added rules.
# ------------------------------------------------------------
#

_apply_ip_list() {
    local file="$1"
    local proto="$2"    # "IPv4" or "IPv6"
    local -n _ip_count="$3"
    local -n _ip_failed="$4"

    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Subnet is the first whitespace-delimited token.
        local subnet
        subnet=$(echo "$line" | awk '{print $1}')
        [[ -z "$subnet" ]] && continue

        # Validate.
        local valid=0
        if [[ "$proto" == "IPv4" ]] && \
           [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            valid=1
        elif [[ "$proto" == "IPv6" ]] && \
             [[ "$subnet" =~ ^[0-9a-fA-F:]+(/[0-9]+)?$ ]]; then
            valid=1
        fi

        if [[ "$valid" -eq 0 ]]; then
            echo "  WARNING: Skipping invalid ${proto} entry: ${subnet}"
            (( _ip_failed++ )) || true
            continue
        fi

        # Pull the inline comment (everything after the first #).
        local note
        note=$(echo "$line" | sed -E 's/^[^#]*//' | sed -E 's/^#[[:space:]]*//' | xargs)
        local comment="${MASTER_IP_TAG} | ${note:-no reason given}"

        echo "  DENY ${subnet}"
        ufw prepend deny from "$subnet" comment "$comment" >/dev/null
        (( _ip_count++ )) || true
    done < "$file"
}

sync_blocklist() {
    local tmp_asns tmp_ipv4 tmp_ipv6
    tmp_asns=$(mktemp)
    tmp_ipv4=$(mktemp)
    tmp_ipv6=$(mktemp)

    echo
    echo "========================================"
    echo "Syncing master blocklist"
    echo "========================================"

    local fetch_ok=1
    fetch_url "$MASTER_ASN_URL"  "$tmp_asns" "master ASN list"  || fetch_ok=0
    fetch_url "$MASTER_IPV4_URL" "$tmp_ipv4" "master IPv4 list" || fetch_ok=0
    fetch_url "$MASTER_IPV6_URL" "$tmp_ipv6" "master IPv6 list" || fetch_ok=0

    if [[ "$fetch_ok" -eq 0 ]]; then
        rm -f "$tmp_asns" "$tmp_ipv4" "$tmp_ipv6"
        echo "ERROR: One or more master lists failed to download."
        echo "Existing UFW rules were NOT changed."
        return 1
    fi

    #
    # --- ASNs ---
    # Lines look like: AS215117 # HOSTERDADDY | Ignored abuse complaint
    #

    local -a master_asns=()

    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        local asn
        asn=$(echo "$line" | grep -oE '^AS[0-9]+') || continue
        asn=$(normalize_asn "$asn")
        master_asns+=( "$asn" )
    done < "$tmp_asns"

    echo
    echo "Master ASN list: ${#master_asns[@]} entries"

    local asn_failed=0

    for asn in "${master_asns[@]}"; do
        if ! sync_asn "$asn"; then
            echo "WARNING: Failed to sync ${asn}"
            (( asn_failed++ )) || true
        fi
    done

    #
    # --- Direct IP rules ---
    # Remove all existing master IP rules first, then re-add from
    # the fresh lists so removed entries don't linger.
    #

    echo
    echo "========================================"
    echo "Applying master IP blocklist"
    echo "========================================"

    remove_ufw_rules_by_comment "$MASTER_IP_TAG" "master IP rules"

    local ip_count=0
    local ip_failed=0

    echo
    echo "Adding IPv4 rules..."
    _apply_ip_list "$tmp_ipv4" "IPv4" ip_count ip_failed

    echo
    echo "Adding IPv6 rules..."
    _apply_ip_list "$tmp_ipv6" "IPv6" ip_count ip_failed

    rm -f "$tmp_asns" "$tmp_ipv4" "$tmp_ipv6"

    echo
    echo "========================================"
    echo "Master blocklist sync complete"
    echo "ASNs synced:      ${#master_asns[@]} (${asn_failed} failed)"
    echo "IP rules applied: ${ip_count} (${ip_failed} skipped)"
    echo "========================================"

    [[ "$asn_failed" -eq 0 && "$ip_failed" -eq 0 ]]
}

#
# ------------------------------------------------------------
# BLOCK
# ------------------------------------------------------------
#

block_asn() {
    local asn
    asn=$(normalize_asn "$1")

    ensure_blocklist
    echo "Blocking ${asn}..."

    sync_asn "$asn"
}

#
# ------------------------------------------------------------
# UNBLOCK
# ------------------------------------------------------------
#

unblock_asn() {
    local asn
    asn=$(normalize_asn "$1")

    ensure_blocklist
    echo "Unblocking ${asn}..."

    remove_ufw_rules "$asn"
    remove_from_blocklist "$asn"

    echo
    echo "${asn} removed from blocklist."
}

#
# ------------------------------------------------------------
# SYNC ALL — syncs manual ASNs + master blocklist
# ------------------------------------------------------------
#

sync_all() {
    ensure_blocklist

    # Snapshot ASN list before any writes to $BLOCKLIST.
    local -a asns=()

    while IFS='|' read -r asn _name; do
        asn="$(echo "$asn" | xargs)"

        [[ -z "$asn" ]] && continue
        [[ "$asn" =~ ^# ]] && continue

        if [[ ! "$asn" =~ ^AS[0-9]+$ ]]; then
            echo "WARNING: Invalid entry in blocklist: ${asn}"
            continue
        fi

        asns+=( "$asn" )
    done < "$BLOCKLIST"

    local failed=0
    local total="${#asns[@]}"

    echo
    echo "========================================"
    echo "Synchronising manual ASN blocklist"
    echo "========================================"

    for asn in "${asns[@]}"; do
        if ! sync_asn "$asn"; then
            echo "WARNING: Failed to sync ${asn}"
            (( failed++ )) || true
        fi
    done

    echo
    echo "========================================"
    echo "Manual ASN sync finished"
    echo "ASNs:   ${total}"
    echo "Failed: ${failed}"
    echo "========================================"

    # Also sync the master remote blocklist.
    sync_blocklist

    [[ "$failed" -eq 0 ]]
}

#
# ------------------------------------------------------------
# LIST
# ------------------------------------------------------------
#

list_blocked() {
    ensure_blocklist

    echo
    echo "========================================"
    echo "ASN Blocklist"
    echo "========================================"

    local count=0

    while IFS='|' read -r asn name; do
        asn="$(echo "$asn" | xargs)"
        name="$(echo "$name" | xargs)"

        [[ -z "$asn" ]] && continue
        [[ "$asn" =~ ^# ]] && continue

        printf "%-12s | %s\n" "$asn" "$name"
        (( count++ )) || true
    done < "$BLOCKLIST"

    echo
    echo "Total blocked ASNs: ${count}"
}

#
# ------------------------------------------------------------
# STATUS
# ------------------------------------------------------------
#

status() {
    ensure_blocklist

    echo
    echo "========================================"
    echo "ASN Blocklist Status"
    echo "========================================"

    local ufw_status
    ufw_status=$(ufw status)

    while IFS='|' read -r asn name; do
        asn="$(echo "$asn" | xargs)"
        name="$(echo "$name" | xargs)"

        [[ -z "$asn" ]] && continue
        [[ "$asn" =~ ^# ]] && continue

        local count
        count=$(echo "$ufw_status" | grep -cF "# ${asn} |" || true)

        if [[ "$count" -gt 0 ]]; then
            printf "BLOCKED  %-12s | %-30s | %s UFW rules\n" \
                "$asn" "$name" "$count"
        else
            printf "MISSING  %-12s | %-30s | NOT IN UFW\n" \
                "$asn" "$name"
        fi
    done < "$BLOCKLIST"

    echo
    echo "========================================"
    echo "Master IP Blocklist Status"
    echo "========================================"

    local master_count
    master_count=$(echo "$ufw_status" | grep -cF "# ${MASTER_IP_TAG}" || true)
    echo "Active master IP rules: ${master_count}"
}

#
# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
#

COMMAND="${1:-}"

if [[ "$EUID" -ne 0 ]]; then
    die "Run this script as root."
fi

ensure_blocklist

# Prevent simultaneous manual/cron syncs.
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "Another blocklist operation is already running."
    exit 1
fi

case "$COMMAND" in

    block)
        [[ -n "${2:-}" ]] || die "Usage: $0 block <ASN>"
        block_asn "$2"
        ;;

    unblock)
        [[ -n "${2:-}" ]] || die "Usage: $0 unblock <ASN>"
        unblock_asn "$2"
        ;;

    sync)
        [[ -n "${2:-}" ]] || die "Usage: $0 sync <ASN>"
        sync_asn "$(normalize_asn "$2")"
        ;;

    sync-all)
        sync_all
        ;;

    sync-blocklist)
        sync_blocklist
        ;;

    list)
        list_blocked
        ;;

    status)
        status
        ;;

    *)
        cat <<EOF

ASN UFW Blocklist Manager

Usage:

  $0 block AS1234
      Add ASN to blocklist and block all current IP ranges via ipverse.

  $0 unblock AS1234
      Remove ASN from blocklist and remove its UFW rules.

  $0 sync AS1234
      Refresh one ASN's IP ranges from ipverse.

  $0 sync-all
      Refresh every ASN in blocklist.txt, then sync the master blocklist.

  $0 sync-blocklist
      Pull master ASN + IP lists from GitHub and apply to UFW.
      ASNs are expanded via ipverse. IPs are applied directly.
      All previous master-blocklist rules are cleanly replaced.

  $0 list
      Show the manual ASN blocklist.

  $0 status
      Show blocklist entries and UFW rule counts, plus master IP rule count.

Master blocklist URLs (override via environment variables):
  MASTER_ASN_URL  = ${MASTER_ASN_URL}
  MASTER_IPV4_URL = ${MASTER_IPV4_URL}
  MASTER_IPV6_URL = ${MASTER_IPV6_URL}

Manual blocklist file:
  ${BLOCKLIST}

EOF
        exit 1
        ;;
esac
