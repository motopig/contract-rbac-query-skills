#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  scan-permissions.sh — EVM Contract RBAC Permission Scanner    ║
# ║  Discovers roles, members, and function permissions             ║
# ║  Supports: AccessManager, AccessControl, Ownable, ERC1967      ║
# ║  Requires: foundry (cast), jq                                  ║
# ╚══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Arguments ────────────────────────────────────────────────────
ADDR="${1:?Usage: $0 <CONTRACT_ADDRESS> <RPC_URL> [FROM_BLOCK]}"
RPC="${2:?Usage: $0 <CONTRACT_ADDRESS> <RPC_URL> [FROM_BLOCK]}"
FROM_BLOCK="${3:-0}"

# Normalize address to checksum
ADDR=$(cast to-check-sum-address "$ADDR" 2>/dev/null || echo "$ADDR")

# ─── Setup ────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info()  { printf '\033[0;32m[✓]\033[0m %s\n' "$1" >&2; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$1" >&2; }
fail()  { printf '\033[0;31m[✗]\033[0m %s\n' "$1" >&2; }

# Check dependencies
for cmd in cast jq; do
    command -v "$cmd" >/dev/null 2>&1 || { fail "$cmd is required but not installed"; exit 1; }
done

# Create tmp subdirs
mkdir -p "$TMPDIR"/{am,ac,own}

# ─── Precompute common AccessControl role hashes ──────────────────
precompute_ac_role_names() {
    echo "0x0000000000000000000000000000000000000000000000000000000000000000|DEFAULT_ADMIN_ROLE" > "$TMPDIR/ac/known_roles.txt"
    local names=(MINTER_ROLE PAUSER_ROLE BURNER_ROLE UPGRADER_ROLE OPERATOR_ROLE MANAGER_ROLE MODERATOR_ROLE SNAPSHOT_ROLE TRANSFER_ROLE LOCKER_ROLE)
    for name in "${names[@]}"; do
        local hash
        hash=$(cast keccak "$name" 2>/dev/null || true)
        [[ -n "$hash" ]] && echo "${hash}|${name}" >> "$TMPDIR/ac/known_roles.txt"
    done
}

lookup_ac_role_name() {
    local hash="$1"
    local match
    match=$(grep -i "^${hash}|" "$TMPDIR/ac/known_roles.txt" 2>/dev/null | head -1 | cut -d'|' -f2 || true)
    echo "${match:-unknown}"
}

# ─── Helper: fetch logs with retry on block range error ───────────
fetch_logs() {
    local addr="$1"
    local sig="$2"
    local result
    result=$(cast logs "$sig" \
        --from-block "$FROM_BLOCK" \
        --address "$addr" \
        --rpc-url "$RPC" \
        --json 2>"$TMPDIR/fetch_err" || true)

    if [[ -z "$result" || "$result" == "null" ]]; then
        local err_msg
        err_msg=$(cat "$TMPDIR/fetch_err" 2>/dev/null || true)
        if echo "$err_msg" | grep -qi "range\|limit\|exceed\|too many"; then
            warn "Log query range too large for '$sig'. Try specifying a FROM_BLOCK closer to contract deployment."
        fi
        echo "[]"
    else
        echo "$result"
    fi
}

# ═════════════════════════════════════════════════════════════════
# Phase 1: Detect RBAC Patterns
# ═════════════════════════════════════════════════════════════════
TYPES=()
AM_ADDR=""
OWNER=""
PENDING_OWNER=""
PROXY_ADMIN=""
PROXY_IMPL=""

info "Detecting RBAC patterns for $ADDR ..."

# AccessManaged → authority()
if auth=$(cast call "$ADDR" "authority()(address)" --rpc-url "$RPC" 2>/dev/null); then
    auth=$(echo "$auth" | xargs)
    if [[ "$auth" != "0x0000000000000000000000000000000000000000" ]]; then
        TYPES+=("AccessManaged")
        AM_ADDR="$auth"
        info "AccessManaged → AccessManager: $AM_ADDR"
    fi
fi

# AccessManager itself → ADMIN_ROLE()
if cast call "$ADDR" "ADMIN_ROLE()(uint64)" --rpc-url "$RPC" >/dev/null 2>&1; then
    if [[ -z "$AM_ADDR" || "$AM_ADDR" == "$ADDR" ]]; then
        TYPES+=("AccessManager")
        AM_ADDR="$ADDR"
        info "AccessManager detected at $ADDR"
    fi
fi

# AccessControl → DEFAULT_ADMIN_ROLE()
if cast call "$ADDR" "DEFAULT_ADMIN_ROLE()(bytes32)" --rpc-url "$RPC" >/dev/null 2>&1; then
    TYPES+=("AccessControl")
    info "AccessControl detected"
fi

# Ownable → owner()
if owner_result=$(cast call "$ADDR" "owner()(address)" --rpc-url "$RPC" 2>/dev/null); then
    owner_result=$(echo "$owner_result" | xargs)
    if [[ "$owner_result" != "0x0000000000000000000000000000000000000000" ]]; then
        TYPES+=("Ownable")
        OWNER="$owner_result"
        info "Ownable → Owner: $OWNER"
    fi
fi

# Ownable2Step → pendingOwner()
if po=$(cast call "$ADDR" "pendingOwner()(address)" --rpc-url "$RPC" 2>/dev/null); then
    po=$(echo "$po" | xargs)
    if [[ "$po" != "0x0000000000000000000000000000000000000000" ]]; then
        PENDING_OWNER="$po"
        info "Ownable2Step → Pending Owner: $PENDING_OWNER"
    fi
fi

# ERC1967 Proxy → admin slot
admin_slot=$(cast storage "$ADDR" \
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" \
    --rpc-url "$RPC" 2>/dev/null || echo "0x0")
if [[ "$admin_slot" != "0x0000000000000000000000000000000000000000000000000000000000000000" && -n "$admin_slot" && "$admin_slot" != "0x0" ]]; then
    PROXY_ADMIN="0x$(echo "$admin_slot" | sed 's/0x//' | grep -o '.\{40\}$')"
    TYPES+=("ERC1967Proxy")
    info "ERC1967 Proxy → Admin: $PROXY_ADMIN"
fi

# ERC1967 → implementation slot
impl_slot=$(cast storage "$ADDR" \
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" \
    --rpc-url "$RPC" 2>/dev/null || echo "0x0")
if [[ "$impl_slot" != "0x0000000000000000000000000000000000000000000000000000000000000000" && -n "$impl_slot" && "$impl_slot" != "0x0" ]]; then
    PROXY_IMPL="0x$(echo "$impl_slot" | sed 's/0x//' | grep -o '.\{40\}$')"
    info "ERC1967 Proxy → Implementation: $PROXY_IMPL"
fi

if [[ ${#TYPES[@]} -eq 0 ]]; then
    fail "No known RBAC pattern detected at $ADDR"
    exit 1
fi

# ═════════════════════════════════════════════════════════════════
# Phase 2: AccessManager Scan
# ═════════════════════════════════════════════════════════════════
if [[ -n "$AM_ADDR" ]]; then
    info "Scanning AccessManager at $AM_ADDR ..."

    # Fetch events
    info "  Fetching RoleGranted events..."
    AM_GRANTS=$(fetch_logs "$AM_ADDR" "RoleGranted(uint64,address,uint32,uint48,bool)")

    info "  Fetching TargetFunctionRoleUpdated events..."
    AM_FUNCS=$(fetch_logs "$AM_ADDR" "TargetFunctionRoleUpdated(address,bytes4,uint64)")

    info "  Fetching RoleLabel events..."
    AM_LABELS=$(fetch_logs "$AM_ADDR" "RoleLabel(uint64,string)")

    # Parse grant events → unique (roleId_hex, account) pairs
    echo "$AM_GRANTS" | jq -r '
        .[] |
        [.topics[1] // "0x0", ("0x" + ((.topics[2] // "0x0") | ltrimstr("0x") | .[-40:]))] |
        @tsv
    ' 2>/dev/null | sort -u > "$TMPDIR/am/candidates.tsv"

    grant_count=$(wc -l < "$TMPDIR/am/candidates.tsv" | tr -d ' ')
    info "  Found $grant_count unique (role, account) candidates"

    # Parse function role events → (target, selector_hex, roleId_hex)
    echo "$AM_FUNCS" | jq -r '
        .[] |
        [
            ("0x" + ((.topics[1] // "0x0") | ltrimstr("0x") | .[-40:])),
            ("0x" + ((.data // "0x") | ltrimstr("0x") | .[0:8])),
            (.topics[2] // "0x0")
        ] | @tsv
    ' 2>/dev/null > "$TMPDIR/am/funcs_raw.tsv"

    # Parse label events → (roleId_hex, label_data)
    echo "$AM_LABELS" | jq -r '
        .[] | [(.topics[1] // "0x0"), (.data // "0x")] | @tsv
    ' 2>/dev/null > "$TMPDIR/am/labels_raw.tsv"

    # Decode labels
    while IFS=$'\t' read -r role_hex label_data; do
        [[ -z "$role_hex" || -z "$label_data" || "$label_data" == "0x" ]] && continue
        role_dec=$(printf "%d" "$role_hex" 2>/dev/null || echo "$role_hex")
        label=$(cast abi-decode "f(string)" "$label_data" 2>/dev/null | head -1 | tr -d '"' || echo "")
        [[ -n "$label" ]] && echo "${role_dec}|${label}" >> "$TMPDIR/am/labels.txt"
    done < "$TMPDIR/am/labels_raw.tsv"

    # Verify current membership with hasRole()
    info "  Verifying current role membership..."
    while IFS=$'\t' read -r role_hex account; do
        [[ -z "$role_hex" || -z "$account" ]] && continue
        role_dec=$(printf "%d" "$role_hex" 2>/dev/null || echo "0")

        result=$(cast call "$AM_ADDR" \
            "hasRole(uint64,address)(bool,uint32)" \
            "$role_dec" "$account" \
            --rpc-url "$RPC" 2>/dev/null || echo "")

        if [[ -n "$result" ]]; then
            is_member=$(echo "$result" | head -1 | xargs)
            delay=$(echo "$result" | sed -n '2p' | xargs)
            if [[ "$is_member" == "true" ]]; then
                echo "${role_dec}|${account}|${delay:-0}" >> "$TMPDIR/am/members.txt"
            fi
        fi
    done < "$TMPDIR/am/candidates.tsv"

    member_count=0
    [[ -f "$TMPDIR/am/members.txt" ]] && member_count=$(wc -l < "$TMPDIR/am/members.txt" | tr -d ' ')
    info "  Verified $member_count active role members"

    # Get role details (admin, guardian, grant delay)
    if [[ -f "$TMPDIR/am/members.txt" ]]; then
        cut -d'|' -f1 "$TMPDIR/am/members.txt" | sort -un > "$TMPDIR/am/role_ids.txt"

        info "  Fetching role configurations..."
        while IFS= read -r role_id; do
            admin=$(cast call "$AM_ADDR" "getRoleAdmin(uint64)(uint64)" "$role_id" --rpc-url "$RPC" 2>/dev/null | xargs || echo "0")
            guardian=$(cast call "$AM_ADDR" "getRoleGuardian(uint64)(uint64)" "$role_id" --rpc-url "$RPC" 2>/dev/null | xargs || echo "0")
            grant_delay=$(cast call "$AM_ADDR" "getRoleGrantDelay(uint64)(uint32)" "$role_id" --rpc-url "$RPC" 2>/dev/null | xargs || echo "0")
            echo "${role_id}|${admin}|${guardian}|${grant_delay}" >> "$TMPDIR/am/role_config.txt"
        done < "$TMPDIR/am/role_ids.txt"
    fi

    # Resolve function selectors and deduplicate (keep latest mapping per target+selector)
    info "  Resolving function selectors..."
    if [[ -s "$TMPDIR/am/funcs_raw.tsv" ]]; then
        # Deduplicate: keep the last entry for each (target, selector) pair
        tac "$TMPDIR/am/funcs_raw.tsv" | sort -t$'\t' -k1,2 -u > "$TMPDIR/am/funcs_dedup.tsv"

        while IFS=$'\t' read -r target selector role_hex; do
            [[ -z "$target" || -z "$selector" ]] && continue
            role_dec=$(printf "%d" "$role_hex" 2>/dev/null || echo "0")
            func_name=$(cast 4byte "$selector" 2>/dev/null | head -1 || echo "")
            [[ -z "$func_name" ]] && func_name="unknown"

            # Verify current mapping
            current_role_hex=$(cast call "$AM_ADDR" \
                "getTargetFunctionRole(address,bytes4)(uint64)" \
                "$target" "$selector" \
                --rpc-url "$RPC" 2>/dev/null | xargs || echo "")
            if [[ -n "$current_role_hex" ]]; then
                current_role=$(printf "%d" "$current_role_hex" 2>/dev/null || echo "$role_dec")
            else
                current_role="$role_dec"
            fi

            echo "${target}|${selector}|${func_name}|${current_role}" >> "$TMPDIR/am/permissions.txt"
        done < "$TMPDIR/am/funcs_dedup.tsv"
    fi

    func_count=0
    [[ -f "$TMPDIR/am/permissions.txt" ]] && func_count=$(wc -l < "$TMPDIR/am/permissions.txt" | tr -d ' ')
    info "  Mapped $func_count function permissions"
fi

# ═════════════════════════════════════════════════════════════════
# Phase 3: AccessControl Scan
# ═════════════════════════════════════════════════════════════════
AC_TARGET="$ADDR"
if [[ " ${TYPES[*]} " =~ " AccessControl " ]]; then
    info "Scanning AccessControl at $AC_TARGET ..."
    precompute_ac_role_names

    # Check if AccessControlEnumerable
    is_enumerable=false
    if cast call "$AC_TARGET" "getRoleMemberCount(bytes32)(uint256)" \
        "0x0000000000000000000000000000000000000000000000000000000000000000" \
        --rpc-url "$RPC" >/dev/null 2>&1; then
        is_enumerable=true
        info "  AccessControlEnumerable detected — using enumeration"
    fi

    # Discover roles from events
    info "  Fetching RoleGranted events..."
    AC_GRANTS=$(fetch_logs "$AC_TARGET" "RoleGranted(bytes32,address,address)")

    echo "$AC_GRANTS" | jq -r '.[] | .topics[1] // empty' 2>/dev/null | sort -u > "$TMPDIR/ac/role_hashes.txt"

    # Ensure DEFAULT_ADMIN_ROLE is included
    echo "0x0000000000000000000000000000000000000000000000000000000000000000" >> "$TMPDIR/ac/role_hashes.txt"
    sort -u -o "$TMPDIR/ac/role_hashes.txt" "$TMPDIR/ac/role_hashes.txt"

    role_hash_count=$(wc -l < "$TMPDIR/ac/role_hashes.txt" | tr -d ' ')
    info "  Discovered $role_hash_count unique role hashes"

    if [[ "$is_enumerable" == "true" ]]; then
        # Enumerate members for each role
        while IFS= read -r role_hash; do
            [[ -z "$role_hash" ]] && continue
            count_hex=$(cast call "$AC_TARGET" "getRoleMemberCount(bytes32)(uint256)" \
                "$role_hash" --rpc-url "$RPC" 2>/dev/null | xargs || echo "0")
            count=$(printf "%d" "$count_hex" 2>/dev/null || echo "0")

            for ((i = 0; i < count; i++)); do
                member=$(cast call "$AC_TARGET" "getRoleMember(bytes32,uint256)(address)" \
                    "$role_hash" "$i" --rpc-url "$RPC" 2>/dev/null | xargs || echo "")
                [[ -n "$member" ]] && echo "${role_hash}|${member}" >> "$TMPDIR/ac/members.txt"
            done
        done < "$TMPDIR/ac/role_hashes.txt"
    else
        # Event-based: extract candidates and verify
        echo "$AC_GRANTS" | jq -r '
            .[] |
            [.topics[1] // "0x0", ("0x" + ((.topics[2] // "0x0") | ltrimstr("0x") | .[-40:]))] |
            @tsv
        ' 2>/dev/null | sort -u > "$TMPDIR/ac/candidates.tsv"

        info "  Verifying current role membership..."
        while IFS=$'\t' read -r role_hash account; do
            [[ -z "$role_hash" || -z "$account" ]] && continue
            has_role=$(cast call "$AC_TARGET" "hasRole(bytes32,address)(bool)" \
                "$role_hash" "$account" --rpc-url "$RPC" 2>/dev/null | xargs || echo "false")
            if [[ "$has_role" == "true" ]]; then
                echo "${role_hash}|${account}" >> "$TMPDIR/ac/members.txt"
            fi
        done < "$TMPDIR/ac/candidates.tsv"
    fi

    # Get role admin for each role
    while IFS= read -r role_hash; do
        [[ -z "$role_hash" ]] && continue
        admin_hash=$(cast call "$AC_TARGET" "getRoleAdmin(bytes32)(bytes32)" \
            "$role_hash" --rpc-url "$RPC" 2>/dev/null | xargs || echo "0x0")
        role_name=$(lookup_ac_role_name "$role_hash")
        admin_name=$(lookup_ac_role_name "$admin_hash")
        echo "${role_hash}|${role_name}|${admin_hash}|${admin_name}" >> "$TMPDIR/ac/role_config.txt"
    done < "$TMPDIR/ac/role_hashes.txt"

    ac_member_count=0
    [[ -f "$TMPDIR/ac/members.txt" ]] && ac_member_count=$(wc -l < "$TMPDIR/ac/members.txt" | tr -d ' ')
    info "  Found $ac_member_count active role members"
fi

# ═════════════════════════════════════════════════════════════════
# Phase 4: Generate Report
# ═════════════════════════════════════════════════════════════════
CHAIN_ID=$(cast chain-id --rpc-url "$RPC" 2>/dev/null || echo "unknown")
BLOCK_NUM=$(cast block-number --rpc-url "$RPC" 2>/dev/null || echo "unknown")
NOW=$(date '+%Y-%m-%d %H:%M:%S')

ADDR_SHORT=$(echo "$ADDR" | cut -c1-10)
OUTPUT="rbac-report-${ADDR_SHORT}.md"

info "Generating report: $OUTPUT"

cat << HEADER > "$OUTPUT"
# RBAC Permission Report

| Property | Value |
|----------|-------|
| Contract | \`$ADDR\` |
| Chain ID | $CHAIN_ID |
| Block Height | $BLOCK_NUM |
| Scan Time | $NOW |
| RBAC Patterns | $(IFS=', '; echo "${TYPES[*]}") |
| From Block | $FROM_BLOCK |

---
HEADER

# ─── Ownership Section ────────────────────────────────────────────
if [[ -n "$OWNER" || -n "$PROXY_ADMIN" || -n "$PENDING_OWNER" ]]; then
    cat << 'SEC' >> "$OUTPUT"

## Ownership

| Property | Address |
|----------|---------|
SEC
    [[ -n "$OWNER" ]] && echo "| Owner | \`$OWNER\` |" >> "$OUTPUT"
    [[ -n "$PENDING_OWNER" ]] && echo "| Pending Owner | \`$PENDING_OWNER\` |" >> "$OUTPUT"
    [[ -n "$PROXY_ADMIN" ]] && echo "| Proxy Admin | \`$PROXY_ADMIN\` |" >> "$OUTPUT"
    [[ -n "$PROXY_IMPL" ]] && echo "| Implementation | \`$PROXY_IMPL\` |" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
fi

# ─── AccessManager Roles Section ──────────────────────────────────
if [[ -f "$TMPDIR/am/members.txt" ]]; then
    echo "" >> "$OUTPUT"
    echo "## AccessManager Roles" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "**AccessManager Address**: \`$AM_ADDR\`" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    while IFS= read -r role_id; do
        # Determine role name
        role_name=""
        if [[ -f "$TMPDIR/am/labels.txt" ]]; then
            role_name=$(grep "^${role_id}|" "$TMPDIR/am/labels.txt" 2>/dev/null | head -1 | cut -d'|' -f2 || true)
        fi
        if [[ -z "$role_name" ]]; then
            case "$role_id" in
                0) role_name="ADMIN_ROLE" ;;
                *) role_name="ROLE_$role_id" ;;
            esac
        fi

        # Get role config
        admin_role="" guardian_role="" g_delay=""
        if [[ -f "$TMPDIR/am/role_config.txt" ]]; then
            config_line=$(grep "^${role_id}|" "$TMPDIR/am/role_config.txt" 2>/dev/null | head -1 || true)
            if [[ -n "$config_line" ]]; then
                admin_role=$(echo "$config_line" | cut -d'|' -f2)
                guardian_role=$(echo "$config_line" | cut -d'|' -f3)
                g_delay=$(echo "$config_line" | cut -d'|' -f4)
            fi
        fi

        echo "### $role_name (ID: $role_id)" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
        [[ -n "$admin_role" ]] && echo "- **Admin Role**: $admin_role" >> "$OUTPUT"
        [[ -n "$guardian_role" && "$guardian_role" != "0" ]] && echo "- **Guardian Role**: $guardian_role" >> "$OUTPUT"
        [[ -n "$g_delay" && "$g_delay" != "0" ]] && echo "- **Grant Delay**: ${g_delay}s" >> "$OUTPUT"
        echo "" >> "$OUTPUT"

        echo "| Address | Execution Delay |" >> "$OUTPUT"
        echo "|---------|----------------|" >> "$OUTPUT"

        grep "^${role_id}|" "$TMPDIR/am/members.txt" | while IFS='|' read -r _ account delay; do
            delay_str="0"
            [[ "$delay" != "0" ]] && delay_str="${delay}s"
            echo "| \`$account\` | $delay_str |" >> "$OUTPUT"
        done

        echo "" >> "$OUTPUT"
    done < "$TMPDIR/am/role_ids.txt"

    # Function permissions
    if [[ -f "$TMPDIR/am/permissions.txt" && -s "$TMPDIR/am/permissions.txt" ]]; then
        echo "## Function Permissions (AccessManager)" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
        echo "| Target | Selector | Function | Required Role |" >> "$OUTPUT"
        echo "|--------|----------|----------|---------------|" >> "$OUTPUT"

        sort -t'|' -k4 -n "$TMPDIR/am/permissions.txt" | while IFS='|' read -r target selector func_name role; do
            echo "| \`$target\` | \`$selector\` | \`$func_name\` | $role |" >> "$OUTPUT"
        done

        echo "" >> "$OUTPUT"
    fi
fi

# ─── AccessControl Roles Section ──────────────────────────────────
if [[ -f "$TMPDIR/ac/members.txt" ]]; then
    echo "" >> "$OUTPUT"
    echo "## AccessControl Roles" >> "$OUTPUT"
    echo "" >> "$OUTPUT"

    while IFS='|' read -r role_hash role_name admin_hash admin_name; do
        [[ -z "$role_hash" ]] && continue

        # Count members for this role
        member_count=$(grep -c "^${role_hash}|" "$TMPDIR/ac/members.txt" 2>/dev/null || echo "0")
        [[ "$member_count" == "0" ]] && continue

        display_name="$role_name"
        [[ "$display_name" == "unknown" ]] && display_name="${role_hash:0:18}..."

        echo "### $display_name" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
        echo "- **Role Hash**: \`$role_hash\`" >> "$OUTPUT"
        echo "- **Admin**: $admin_name (\`$admin_hash\`)" >> "$OUTPUT"
        echo "" >> "$OUTPUT"

        echo "| Address |" >> "$OUTPUT"
        echo "|---------|" >> "$OUTPUT"

        grep "^${role_hash}|" "$TMPDIR/ac/members.txt" | while IFS='|' read -r _ account; do
            echo "| \`$account\` |" >> "$OUTPUT"
        done

        echo "" >> "$OUTPUT"
    done < "$TMPDIR/ac/role_config.txt"
fi

# ─── Summary ──────────────────────────────────────────────────────
echo "---" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "*Generated by rbac-scanner*" >> "$OUTPUT"

info "Report saved to: $OUTPUT"
echo "$OUTPUT"
