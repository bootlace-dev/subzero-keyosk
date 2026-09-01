#!/bin/bash
# ===========================================================================
#                 SubZero Keyosk: PII Leak Prevention Hook
# ===========================================================================
set -euo pipefail

# Blocked terms reconstructed dynamically to prevent diff self-triggering
T1=$(echo -ne "\x70\x65\x74\x6a\x61\x6c")
T2=$(echo -ne "\x4a\x61\x6c\x61\x6a\x61\x73")
T3=$(echo -ne "\x31\x30\x30\x2e\x36\x38\x2e")
T4=$(echo -ne "\x31\x30\x2e\x30\x2e\x30\x2e")

BLOCKED_TERMS=("$T1" "$T2" "$T3" "$T4")

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

FORBIDDEN_FOUND=0

for FILE in $STAGED_FILES; do
    # Skip binary files or vendor fixtures
    if [[ "$FILE" == *".png" || "$FILE" == *".jpg" || "$FILE" == *".pdf" || "$FILE" == *".img" || "$FILE" == *"privates.json" || "$FILE" == *"points.json" ]]; then
        continue
    fi

    # Verify file exists
    if [ ! -f "$FILE" ]; then
        continue
    fi

    for TERM in "${BLOCKED_TERMS[@]}"; do
        # Search only the newly added lines in the diff
        if git diff --cached "$FILE" | grep -E "^\+[^*]*$TERM" >/dev/null; then
            echo "====================================================================="
            echo " [SECURITY BLOCK] Forbidden PII term '$TERM' found in staged changes!"
            echo " File: $FILE"
            echo "====================================================================="
            FORBIDDEN_FOUND=1
        fi
    done
done

if [ $FORBIDDEN_FOUND -ne 0 ]; then
    echo "Commit aborted to prevent PII leakage to remote repository."
    exit 1
fi

exit 0
