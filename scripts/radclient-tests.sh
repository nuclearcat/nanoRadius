#!/usr/bin/env bash
# Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/target/release/nanoRadius"
CONFIG="${ROOT_DIR}/ci-nanoradius.toml"
LOG_FILE="${ROOT_DIR}/ci-logs/nanoradius.log"
SERVER_LOG="${ROOT_DIR}/ci-logs/server.log"
AUTH_PORT=4812
ACCT_PORT=4813
SECRET="testing123"

if ! command -v radclient >/dev/null 2>&1; then
  echo "radclient is required to run these integration tests" >&2
  exit 1
fi

if [ ! -x "${BIN}" ]; then
  echo "nanoRadius binary not found at ${BIN}. Run 'cargo build --release' first." >&2
  exit 1
fi

mkdir -p "$(dirname "${LOG_FILE}")"
rm -f "${LOG_FILE}"
rm -f "${SERVER_LOG}"

"${BIN}" -c "${CONFIG}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

cleanup() {
  set +e
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  if [ -f "${SERVER_LOG}" ]; then
    echo "--- server stdout (tail) ---"
    tail -n 200 "${SERVER_LOG}"
    echo "----------------------------"
  fi
  if [ -f "${LOG_FILE}" ]; then
    echo "--- server logfile (tail) ---"
    tail -n 200 "${LOG_FILE}"
    echo "-----------------------------"
  fi
}
trap cleanup EXIT

wait_for_port() {
  python3 - "$1" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
for _ in range(100):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            sys.exit(0)
    except OSError:
        time.sleep(0.05)

sys.exit(1)
PY
}

wait_for_log() {
  local pattern=$1
  local file=$2
  for _ in $(seq 1 100); do
    if grep -q "${pattern}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

echo "Waiting for auth/acct servers to report readiness..."
if ! wait_for_log "Auth server listening" "${LOG_FILE}"; then
  echo "Auth server did not report readiness" >&2
  exit 1
fi
if ! wait_for_log "Accounting server listening" "${LOG_FILE}"; then
  echo "Accounting server did not report readiness" >&2
  exit 1
fi

pap_output=$(cat <<EOF | radclient -x 127.0.0.1:${AUTH_PORT} auth "${SECRET}"
User-Name = "alice"
User-Password = "secret"
EOF
)
echo "${pap_output}"
if ! grep -q "Access-Accept" <<<"${pap_output}"; then
  echo "PAP authentication failed" >&2
  exit 1
fi

read -r CHAP_PAYLOAD CHAP_CHALLENGE <<<"$(python3 - <<'PY'
import hashlib

chap_id = 7
password = "secret"
challenge = bytes.fromhex("00112233445566778899aabbccddeeff")
digest = hashlib.md5(bytes([chap_id]) + password.encode() + challenge).digest()
payload = bytes([chap_id]) + digest
print(payload.hex(), challenge.hex())
PY
)"

chap_output=$(cat <<EOF | radclient -x 127.0.0.1:${AUTH_PORT} auth "${SECRET}"
User-Name = "alice"
CHAP-Password = 0x${CHAP_PAYLOAD}
CHAP-Challenge = 0x${CHAP_CHALLENGE}
EOF
)
echo "${chap_output}"
if ! grep -q "Access-Accept" <<<"${chap_output}"; then
  echo "CHAP authentication failed" >&2
  exit 1
fi

acct_output=$(cat <<EOF | radclient -x 127.0.0.1:${ACCT_PORT} acct "${SECRET}"
User-Name = "alice"
Acct-Status-Type = Start
Acct-Session-Id = "ci-session-1"
NAS-IP-Address = 127.0.0.1
EOF
)
echo "${acct_output}"
if ! grep -q "Accounting-Response" <<<"${acct_output}"; then
  echo "Accounting request failed" >&2
  exit 1
fi

sleep 1
if ! grep -q "\[ACCT Start\] user=alice" "${LOG_FILE}"; then
  echo "Accounting log entry missing" >&2
  exit 1
fi

echo "radclient integration tests passed"
