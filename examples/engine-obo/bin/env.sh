# Shared configuration for bin/ scripts. Reads the live-run state written by the
# provisioning step; secrets and tokens live outside the repo.
set -euo pipefail
: "${LIVE_DIR:?set LIVE_DIR to the directory holding state.json}"
state() { python3 -I -c "import json,sys; print(json.load(open('$LIVE_DIR/state.json'))[sys.argv[1]])" "$1"; }
export KEYCARD_ZONE_URL="${KEYCARD_ZONE_URL:?set KEYCARD_ZONE_URL to the zone URL}"
export CLI_CLIENT_ID="$(state cli_client_id)"
export ENGINE_V2_CLIENT_ID="$(state engine_v2_client_id)"
export ENGINE_APP_IDENTIFIER="urn:app:java-sdk-engine"
export ENGINE_RESOURCE="https://engine.java-sdk.test"
export LEDGER_RESOURCE="https://ledger.java-sdk.test"
export SUBJECT_TOKEN_FILE="$LIVE_DIR/subject-token"
export SVID_FILE="$LIVE_DIR/svid.jwt"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
