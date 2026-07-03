#!/bin/bash
# Start a miner on testnet (netuid 138). Wallet names, port etc. come from .env
set -a
source "$(dirname "$0")/.env"
set +a

python3 -m neurons.miner \
    --netuid 138 \
    --subtensor.network test \
    --blacklist.force_validator_permit \
    --wallet.name "${COLDKEY_NAME:-default}" \
    --wallet.hotkey "${HOTKEY_NAME:-default}" \
    --axon.port "${PORT:-8091}" \
    --logging.debug
