#!/bin/bash
# Helper script to mine blocks on demand in Regtest mode

if [ -z "$1" ]; then
    BLOCKS=1
else
    BLOCKS=$1
fi

# Get receiving address or generate one if not supplied
if [ -z "$2" ]; then
    # Create default wallet if it doesn't exist
    docker exec subzero-regtest bitcoin-cli -regtest -rpcuser=subzero -rpcpassword=keygenpass createwallet default >/dev/null 2>&1 || true
    ADDR=$(docker exec subzero-regtest bitcoin-cli -regtest -rpcuser=subzero -rpcpassword=keygenpass getnewaddress)
else
    ADDR=$2
fi

echo "Mining $BLOCKS block(s) to address: $ADDR"
docker exec subzero-regtest bitcoin-cli -regtest -rpcuser=subzero -rpcpassword=keygenpass generatetoaddress $BLOCKS $ADDR
