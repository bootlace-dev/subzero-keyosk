# Local private Regtest Node Setup

This folder contains a Docker Compose setup to run a local private Bitcoin blockchain (Regtest mode) using Bitcoin Core. Regtest allows you to instantly mine blocks on demand for rapid testing of transactions and addresses derived by SubZero Keyosk.

## How to Start the Node

1. Make sure Docker and Docker Compose are installed.
2. Spin up the container:
   ```bash
   docker compose up -d
   ```
3. Verify the container is running:
   ```bash
   docker ps
   ```

## How to Mine Blocks (Instant Confirmation)

Use the helper script `mine.sh` to generate blocks instantly.

1. Mine 1 block to a fresh address in the container's wallet:
   ```bash
   ./mine.sh
   ```
2. Mine a specific number of blocks (e.g. 100 blocks to activate coinbases):
   ```bash
   ./mine.sh 101
   ```
3. Mine blocks to a specific address derived by SubZero Keyosk (e.g., to fund a test balance):
   ```bash
   ./mine.sh 10 tb1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

## Configuration Details
* **RPC Port:** `18443`
* **RPC User:** `subzero`
* **RPC Password:** `keygenpass`
* **Network:** `regtest`
