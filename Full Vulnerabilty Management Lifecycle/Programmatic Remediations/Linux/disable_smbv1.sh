
set -u

TAG="Samba-SMBv1"
CONF="/etc/samba/smb.conf"
BACKUP_DIR="/root/samba-backups"
# Matches "server min protocol" or "min protocol" set to an SMBv1-level value,
# any spacing/case, ignoring commented lines
SMB1_REGEX='^[[:space:]]*(server[[:space:]]+)?min[[:space:]]+protocol[[:space:]]*=[[:space:]]*(NT1|LANMAN1|LANMAN2|CORE|COREPLUS)[[:space:]]*$'
SMB1_VALUES_REGEX='^(NT1|LANMAN1|LANMAN2|CORE|COREPLUS)$'

log() { echo "[$TAG] $*"; }

# --- Root check --------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log "ERROR - This script must be run as root (use sudo)."
    exit 2
fi

if [[ ! -f "$CONF" ]]; then
    log "ERROR - $CONF not found. Is Samba installed?"
    exit 2
fi

if ! command -v testparm >/dev/null 2>&1; then
    log "ERROR - testparm not found. Is Samba installed?"
    exit 2
fi

get_min_protocol() {
    testparm -sv "$CONF" 2>/dev/null \
        | grep -i '^[[:space:]]*server min protocol[[:space:]]*=' \
        | head -n1 | cut -d= -f2 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

# --- Backup ------------------------------------------------------------------
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/smb.conf.$(date +%Y%m%d_%H%M%S).bak"
cp -p "$CONF" "$BACKUP_FILE"
log "Backup saved: $BACKUP_FILE"
log "Effective 'server min protocol' before: $(get_min_protocol)"

# --- Step 2: Remove SMBv1-level min protocol lines ---------------------------
if grep -Eiq "$SMB1_REGEX" "$CONF"; then
    log "Found SMBv1 setting(s):"
    grep -Ein "$SMB1_REGEX" "$CONF" | sed "s/^/[$TAG]   line /"
    sed -i -E "/${SMB1_REGEX}/Id" "$CONF"
    log "Removed SMBv1 'min protocol' line(s) from $CONF."
else
    log "No SMBv1 'min protocol' line found in $CONF."
fi

# --- Step 3: Make sure the effective minimum is SMB2 or higher ---------------
MIN_PROTO=$(get_min_protocol)
if [[ -z "$MIN_PROTO" || "$MIN_PROTO" =~ $SMB1_VALUES_REGEX ]]; then
    log "Samba would still allow SMBv1 (min protocol = ${MIN_PROTO:-unknown}). Setting SMB2_02 explicitly."
    if grep -q '^[[:space:]]*\[global\]' "$CONF"; then
        sed -i '0,/^[[:space:]]*\[global\]/s//&\n   server min protocol = SMB2_02/' "$CONF"
    else
        printf '\n[global]\n   server min protocol = SMB2_02\n' >> "$CONF"
    fi
fi

# --- Validate config ---------------------------------------------------------
if ! testparm -s "$CONF" >/dev/null 2>&1; then
    log "ERROR - testparm reports an invalid config. Restoring backup."
    cp -p "$BACKUP_FILE" "$CONF"
    exit 2
fi

# --- Step 4: Restart the service ---------------------------------------------
SERVICE=""
for svc in smbd smb; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
        SERVICE="$svc"; break
    fi
done

if [[ -n "$SERVICE" ]]; then
    if systemctl restart "$SERVICE"; then
        log "$SERVICE restarted."
    else
        log "FAILED - $SERVICE did not restart. Check: journalctl -u $SERVICE"
        exit 1
    fi
else
    log "WARNING - smbd/smb service not found; restart Samba manually."
fi

# --- Verify ------------------------------------------------------------------
MIN_PROTO=$(get_min_protocol)
if [[ -z "$MIN_PROTO" || "$MIN_PROTO" =~ $SMB1_VALUES_REGEX ]]; then
    log "FAILED - Effective 'server min protocol' is still ${MIN_PROTO:-unknown} (SMBv1 allowed)."
    exit 1
fi

log "SUCCESS - Effective 'server min protocol' = $MIN_PROTO. SMBv1 is no longer allowed."
exit 0
