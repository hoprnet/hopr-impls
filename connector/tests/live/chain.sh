#!/usr/bin/env bash
# Brings up a local chain for the live connector tests: anvil, the HOPR contract deployment, then bloklid.
# Runs in the foreground until interrupted; anvil and bloklid are stopped on exit.
#
# Required environment:
#   BLOKLID_BIN    path to bloklid
#   DEPLOYER_BIN   path to blokli-contract-deployer
#   ANVIL_BIN      path to anvil
#   DATA_DIR       scratch directory, wiped on start
# Optional:
#   ANVIL_PORT (default 18545), BLOKLI_PORT (default 18080)
#   UNMINED_TIMEOUT (default 15s): bloklid's unmined transaction timeout, set through
#     BLOKLI_API_TRANSACTIONS_UNMINED_TIMEOUT. Builds that do not know the key ignore it.
set -euo pipefail

: "${BLOKLID_BIN:?}" "${DEPLOYER_BIN:?}" "${ANVIL_BIN:?}" "${DATA_DIR:?}"
anvil_port="${ANVIL_PORT:-18545}"
blokli_port="${BLOKLI_PORT:-18080}"
rpc_url="http://127.0.0.1:${anvil_port}"
config="${DATA_DIR}/bloklid-config.toml"

for bin in "${BLOKLID_BIN}" "${DEPLOYER_BIN}" "${ANVIL_BIN}"; do
  [ -x "${bin}" ] || {
    echo "chain.sh: missing binary '${bin}'" >&2
    exit 1
  }
done

rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

anvil_pid="" bloklid_pid=""
cleanup() {
  [ -n "${bloklid_pid}" ] && kill "${bloklid_pid}" 2>/dev/null || true
  [ -n "${anvil_pid}" ] && kill "${anvil_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Interval mining is needed for the deployment only. The test switches anvil to manual mining.
"${ANVIL_BIN}" --host 127.0.0.1 --port "${anvil_port}" --block-time 1 --accounts 10 --balance 10000 \
  >"${DATA_DIR}/anvil.log" 2>&1 &
anvil_pid=$!

for _ in $(seq 1 60); do
  curl -sf -X POST "${rpc_url}" -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' >/dev/null && break
  sleep 0.5
done

if ! "${DEPLOYER_BIN}" --rpc-url "${rpc_url}" --output "${DATA_DIR}/contracts-deploy.toml" \
  >"${DATA_DIR}/deployer.log" 2>&1; then
  echo "chain.sh: contract deployment failed, last lines:" >&2
  tail -40 "${DATA_DIR}/deployer.log" >&2
  exit 1
fi

cat >"${config}" <<TOML
data_directory = "${DATA_DIR}"
network = "anvil-localhost"
rpc_url = "${rpc_url}"
max_rpc_requests_per_sec = 0

[database]
type = "sqlite"
index_path = "${DATA_DIR}/bloklid-index.db"
logs_path = "${DATA_DIR}/bloklid-logs.db"
max_connections = 10

[indexer]
fast_sync = false
enable_logs_snapshot = false

[api]
bind_address = "127.0.0.1:${blokli_port}"
enabled = true
playground_enabled = false

[api.health]
max_indexer_lag = 10
timeout = "5s"
readiness_check_interval = "5s"
TOML
cat "${DATA_DIR}/contracts-deploy.toml" >>"${config}"

BLOKLI_API_TRANSACTIONS_UNMINED_TIMEOUT="${UNMINED_TIMEOUT:-15s}" \
  "${BLOKLID_BIN}" -c "${config}" >"${DATA_DIR}/bloklid.log" 2>&1 &
bloklid_pid=$!

for _ in $(seq 1 60); do
  curl -sf -X POST "http://127.0.0.1:${blokli_port}/graphql" -H 'content-type: application/json' \
    --data '{"query":"{__typename}"}' >/dev/null 2>&1 && break
  kill -0 "${bloklid_pid}" 2>/dev/null || {
    echo "chain.sh: bloklid exited during startup, last lines:" >&2
    tail -40 "${DATA_DIR}/bloklid.log" >&2
    exit 1
  }
  sleep 1
done

echo "BLOKLI_URL=http://127.0.0.1:${blokli_port}"
echo "ANVIL_URL=${rpc_url}"
echo "logs: ${DATA_DIR}/{anvil,deployer,bloklid}.log"
wait "${bloklid_pid}"
