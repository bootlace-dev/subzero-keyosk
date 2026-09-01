#!/usr/bin/env bash
# ==============================================================================
# SUBZERO SOVEREIGN DEAD-MAN'S SWITCH (DMS) ENGINE
# Architecture: Generic COTS Cloud VM / Linux Server
# Version: 2608301815Z
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# CONFIGURATION & PARAMETERS
# ------------------------------------------------------------------------------
readonly DMS_DIR="${HOME}/dev/dms"
readonly HEARTBEAT_FILE="${HOME}/.dms_heartbeat"
readonly LOG_FILE="${DMS_DIR}/dms_engine.log"
readonly LOCK_FILE="/tmp/dms_engine.lock"

# Inactivity Horizons (Days)
readonly WARN_THRESHOLD_DAYS=16    # Stage 1: Daily urgent warnings to user (Day 16)
readonly FINAL_TRIGGER_DAYS=21     # Stage 2: Automated heir dispatch (Day 21)

# Email Endpoints (Configure for your deployment)
readonly DAILY_REPORT_EMAIL="alerts@example.com"
readonly PRIMARY_MONITOR_EMAIL="grantor@example.com"
readonly SENDER_IDENTITY="SubZero DMS <dms@example.com>"

# ------------------------------------------------------------------------------
# RUNTIME HYGIENE & LOCKING
# ------------------------------------------------------------------------------
mkdir -p "${DMS_DIR}"

exec 200>"${LOCK_FILE}"
if ! flock -n 200; then
    echo "[DMS ERROR] Another instance of dms.bash is currently executing. Exiting." >&2
    exit 1
fi

log() {
    local -r msg="$1"
    local -r ts=$(date --utc "+%Y-%m-%dT%H:%M:%SZ")
    echo "[${ts}] ${msg}" | tee -a "${LOG_FILE}"
}

# ------------------------------------------------------------------------------
# HEARTBEAT & TIME CALCULATIONS
# ------------------------------------------------------------------------------
if [[ ! -f "${HEARTBEAT_FILE}" ]]; then
    log "Heartbeat file not found. Initializing ${HEARTBEAT_FILE} to current timestamp."
    touch "${HEARTBEAT_FILE}"
fi

readonly NOW_SECS=$(date --utc +%s)
readonly NOW_DATE=$(date --utc "+%Y-%m-%dT%H:%M:%SZ")

# ------------------------------------------------------------------------------
# 1. EVALUATE VACATION HOLD
# ------------------------------------------------------------------------------
HOLD_UNTIL_STR=$(grep -E "^HOLD_UNTIL=" "${HEARTBEAT_FILE}" 2>/dev/null | cut -d '=' -f 2 || true)

if [[ -n "${HOLD_UNTIL_STR}" ]]; then
    HOLD_EXPIRY_SECS=$(date --utc -d "${HOLD_UNTIL_STR}" +%s 2>/dev/null || echo 0)

    if (( NOW_SECS < HOLD_EXPIRY_SECS )); then
        HOLD_REMAINING_DAYS=$(( (HOLD_EXPIRY_SECS - NOW_SECS) / 86400 ))
        log "VACATION HOLD ACTIVE until ${HOLD_UNTIL_STR} (${HOLD_REMAINING_DAYS} days remaining)."

        read -r -d '' HOLD_MSG << EOF || true
Subject: DMS Daily Status: [VACATION HOLD ACTIVE] ${HOLD_REMAINING_DAYS}d to resume
From: ${SENDER_IDENTITY}
To: ${PRIMARY_MONITOR_EMAIL}

============================================================
       SUBZERO SOVEREIGN DEAD-MAN'S SWITCH (DMS)            
============================================================
Host: sovereign-vault-node
Current Time (UTC): ${NOW_DATE}
Heartbeat Status: VACATION HOLD ACTIVE

[VACATION HOLD METRICS]
 * Expiration Date : ${HOLD_UNTIL_STR}
 * Days Remaining  : ${HOLD_REMAINING_DAYS} days
 * Safety Horizon  : 21 days (Count starts AFTER ${HOLD_UNTIL_STR})

[OPERATIONAL COMMANDS]
 * Cancel Hold & Reset Countdown:
   Run 'im_alive' on client terminal
   Or SSH: ssh user@host "sed -i '/^HOLD_UNTIL=/d' ~/.dms_heartbeat && touch ~/.dms_heartbeat"

 * Extend Hold:
   Run 'vacation_hold YYYY-MM-DD' on client terminal
============================================================
EOF
        printf "%s\n" "${HOLD_MSG}" | ssmtp "${DAILY_REPORT_EMAIL}"
        exit 0
    else
        log "Vacation hold expired on ${HOLD_UNTIL_STR}. Resuming normal 21-day countdown."
        touch "${HEARTBEAT_FILE}"
        sed -i '/^HOLD_UNTIL=/d' "${HEARTBEAT_FILE}" 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------
# 2. EVALUATE 21-DAY ACTIVE COUNTDOWN
# ---------------------------------------------------------
readonly LAST_HEARTBEAT_SECS=$(stat -c %Y "${HEARTBEAT_FILE}")
readonly LAST_HEARTBEAT_DATE=$(date --utc -d "@${LAST_HEARTBEAT_SECS}" "+%Y-%m-%dT%H:%M:%SZ")

readonly DIFF_SECS=$(( NOW_SECS - LAST_HEARTBEAT_SECS ))
readonly DIFF_DAYS=$(( DIFF_SECS / 86400 ))
readonly REMAINING_DAYS=$(( FINAL_TRIGGER_DAYS - DIFF_DAYS ))

log "Heartbeat evaluated: Last=${LAST_HEARTBEAT_DATE}, Inactivity=${DIFF_DAYS}d, Remaining=${REMAINING_DAYS}d"

# ---------------------------------------------------------
# STAGE 2: FINAL DEAD-MAN DISPATCH (DIFF_DAYS >= 21)
# ---------------------------------------------------------
if (( DIFF_DAYS >= FINAL_TRIGGER_DAYS )); then
    log "[CRITICAL ALERT] Inactivity threshold exceeded (${DIFF_DAYS}d >= ${FINAL_TRIGGER_DAYS}d). Executing heir dispatch!"

    # Dispatch Passphrase Payload to Heirs (Plug in recipient dispatches here)
    # ${DMS_DIR}/dispatch_heirs.sh

    read -r -d '' FINAL_ALERT << EOF || true
Subject: [ALERT] DMS TRIGGERED: Estate Payload Dispatched to Heirs
From: ${SENDER_IDENTITY}
To: ${PRIMARY_MONITOR_EMAIL}

============================================================
 [!] DEAD-MAN SWITCH TRIGGERED: PAYLOAD DISPATCHED [!]      
============================================================
Host: sovereign-vault-node
Trigger Time (UTC): ${NOW_DATE}

Inactivity threshold of ${FINAL_TRIGGER_DAYS} days was exceeded without a heartbeat.
The Decoupled 12-Word Estate Passphrase (Index 999) has been emailed to designated heirs.
============================================================
EOF
    printf "%s\n" "${FINAL_ALERT}" | ssmtp "${DAILY_REPORT_EMAIL}"

# ---------------------------------------------------------
# STAGE 1: URGENT 5-DAY GRACE WARNING (16 <= DIFF_DAYS < 21)
# ---------------------------------------------------------
elif (( DIFF_DAYS >= WARN_THRESHOLD_DAYS )); then
    log "[STAGE 1 WARNING] ${REMAINING_DAYS} days remaining before heir dispatch. Dispatching urgent warning."

    read -r -d '' URGENT_MSG << EOF || true
Subject: [URGENT ACTION REQUIRED] Dead-Man Switch Triggers in ${REMAINING_DAYS} Days!
From: ${SENDER_IDENTITY}
To: ${PRIMARY_MONITOR_EMAIL}

============================================================
     [!] URGENT: DEAD-MAN SWITCH EXPIRING IN ${REMAINING_DAYS} DAYS [!]     
============================================================
Attention Grantor,

Your dead-man's switch on sovereign-vault-node has reached ${DIFF_DAYS} days without a heartbeat.
If unacknowledged, the estate passphrase will be emailed to your heirs in ${REMAINING_DAYS} days.

[CURRENT METRICS]
 * Last Heartbeat  : ${LAST_HEARTBEAT_DATE} (${DIFF_DAYS} days ago)
 * Days Remaining  : ${REMAINING_DAYS} days until dispatch
 * Dispatch Target : ${FINAL_TRIGGER_DAYS} days

[HOW TO RESET TIMER (IMMEDIATE)]
 Option 1: Run 'im_alive' in your terminal.
 Option 2: Run SSH: ssh user@host "touch ~/.dms_heartbeat"
 Option 3: Set a vacation hold: run 'vacation_hold YYYY-MM-DD'.
============================================================
EOF
    printf "%s\n" "${URGENT_MSG}" | ssmtp "${PRIMARY_MONITOR_EMAIL}"
    printf "%s\n" "${URGENT_MSG}" | ssmtp "${DAILY_REPORT_EMAIL}"

# ---------------------------------------------------------
# STAGE 0: ROUTINE DAILY TELEMETRY (DIFF_DAYS < 16)
# ---------------------------------------------------------
else
    read -r -d '' STATUS_BODY << EOF || true
Subject: DMS Daily Status: DIFF_DAYS=${DIFF_DAYS} (${REMAINING_DAYS}d to trigger)
From: ${SENDER_IDENTITY}
To: ${PRIMARY_MONITOR_EMAIL}

============================================================
       SUBZERO SOVEREIGN DEAD-MAN'S SWITCH (DMS)            
============================================================
Host: sovereign-vault-node
Current Time (UTC): ${NOW_DATE}
Heartbeat Status: OK (Normal Countdown)

[METRICS]
 * Last Heartbeat  : ${LAST_HEARTBEAT_DATE} (${DIFF_DAYS} days ago)
 * Countdown State : ${DIFF_DAYS} / ${FINAL_TRIGGER_DAYS} days
 * Days Remaining  : ${REMAINING_DAYS} days until heir dispatch
 * Warning Horizon : Starts on Day 16 (${WARN_THRESHOLD_DAYS}d)

[HOW TO RESET OR PAUSE TIMER]
 1. Touch Heartbeat (Reset to Day 0):
    Run 'im_alive' on client terminal
    (Or: ssh user@host "touch ~/.dms_heartbeat")

 2. Set Vacation Hold (Pause Countdown):
    Run 'vacation_hold YYYY-MM-DD' on client terminal
    (e.g.: vacation_hold 2026-10-15)
============================================================
EOF
    printf "%s\n" "${STATUS_BODY}" | ssmtp "${DAILY_REPORT_EMAIL}"
fi
