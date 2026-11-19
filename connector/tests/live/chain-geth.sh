#!/usr/bin/env bash
# Same as chain.sh, but runs a real execution client (go-ethereum in dev mode) instead of anvil, so the
# transaction pool behaves like a production node: a transaction whose fee cap is below the base fee stays
# pending and mines once the base fee falls, a nonce gap stays queued, nothing is evicted when a block is mined.
# There is no anvil_setAutomine, anvil_mine, anvil_dropTransaction or setNextBlockBaseFee; the base fee follows
# block fullness (EIP-1559), see the comment at the genesis below.
# Runs in the foreground until interrupted; geth and bloklid are stopped on exit.
#
# Required environment:
#   BLOKLID_BIN    path to bloklid
#   DEPLOYER_BIN   path to blokli-contract-deployer
#   GETH_BIN       path to geth (tested with 1.17.10)
#   DATA_DIR       scratch directory, wiped on start
# Optional:
#   GETH_PORT (default 18545), BLOKLI_PORT (default 18080)
#   BLOCK_TIME (default 1): seconds between blocks
#   UNMINED_TIMEOUT (default 15s): bloklid's unmined transaction timeout, set through
#     BLOKLI_API_TRANSACTIONS_UNMINED_TIMEOUT. Builds that do not know the key ignore it.
set -euo pipefail

: "${BLOKLID_BIN:?}" "${DEPLOYER_BIN:?}" "${GETH_BIN:?}" "${DATA_DIR:?}"
geth_port="${GETH_PORT:-18545}"
blokli_port="${BLOKLI_PORT:-18080}"
rpc_url="http://127.0.0.1:${geth_port}"
config="${DATA_DIR}/bloklid-config.toml"

for bin in "${BLOKLID_BIN}" "${DEPLOYER_BIN}" "${GETH_BIN}"; do
  [ -x "${bin}" ] || {
    echo "chain.sh: missing binary '${bin}'" >&2
    exit 1
  }
done

rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

geth_pid="" bloklid_pid=""
cleanup() {
  [ -n "${bloklid_pid}" ] && kill "${bloklid_pid}" 2>/dev/null || true
  [ -n "${geth_pid}" ] && kill "${geth_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Chain id 31337 and the two funded anvil dev accounts (#0 and #1, public keys) are what the deployer expects.
# The block gas limit is pinned low (geth dev mode otherwise drifts it up to 60M) so that a single large-gas
# transaction fills a block: filling blocks raises the base fee by about 12% per block (from 7 wei), empty
# blocks lower it by about 12% per block.
cat >"${DATA_DIR}/genesis.json" <<JSON
{"config":{"chainId":31337,"homesteadBlock":0,"eip150Block":0,"eip155Block":0,"eip158Block":0,"byzantiumBlock":0,
"constantinopleBlock":0,"petersburgBlock":0,"istanbulBlock":0,"berlinBlock":0,"londonBlock":0,"shanghaiTime":0,
"cancunTime":0,"terminalTotalDifficulty":0,
"blobSchedule":{"cancun":{"target":3,"max":6,"baseFeeUpdateFraction":3338477}}},
"difficulty":"0","gasLimit":"15000000","baseFeePerGas":"1000","alloc":{
"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266":{"balance":"0x21e19e0c9bab2400000"},
"0x70997970C51812dc3A010C7d01b50e0d17dc79C8":{"balance":"0x21e19e0c9bab2400000"}}}
JSON
geth_dir="${DATA_DIR}/g"
"${GETH_BIN}" --datadir "${geth_dir}" init "${DATA_DIR}/genesis.json" >"${DATA_DIR}/geth-init.log" 2>&1
"${GETH_BIN}" --datadir "${geth_dir}" --dev --dev.period "${BLOCK_TIME:-1}" --miner.gaslimit 15000000 \
  --ipcdisable --nodiscover --port "$((geth_port + 1))" --authrpc.port "$((geth_port + 2))" \
  --http --http.addr 127.0.0.1 --http.port "${geth_port}" --http.api eth,net,web3,txpool,debug \
  --rpc.allow-unprotected-txs --rpc.txfeecap 0 >"${DATA_DIR}/geth.log" 2>&1 &
geth_pid=$!

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
echo "RPC_URL=${rpc_url}"
echo "logs: ${DATA_DIR}/{geth,deployer,bloklid}.log"
wait "${bloklid_pid}"
