# Architecture Specification: Testnet4 Sovereign Developer API & Faucet Engine

---

## 1. Executive Summary & Product Thesis

### The Problem in Bitcoin Developer Tooling
Current Bitcoin Testnet infrastructure is notoriously brittle:
1. **Public Faucet Atrophy**: Free faucets are routinely drained by bots, rate-limited behind tedious cloudflare/image CAPTCHAs, or abandoned after hard forks (e.g. the Testnet3 block storms and deprecation).
2. **High-Latency Friction over Tor**: Traditional pay-per-request models (L402) require synchronous multi-step handshakes (get invoice $\to$ pay Lightning route $\to$ poll preimage $\to$ claim UTXO), introducing multi-second delays over high-latency Tor (`.onion`) transport.
3. **Enterprise Testing Complexity**: Production wallet teams (multi-sig, lightning nodes, enterprise custodians) need **batched, scheduled, multi-address UTXO distributions**, not single dust drips.

### The Solution: The Optimistic Multi-Rail Faucet Engine
A high-uptime, Tor-native developer appliance hosted on GCP / local node infrastructure that provides:
- **Instant Optimistic Dispense (0-Latency Execution)**: Testnet4 sats are signed and broadcast to the mempool in $<50\text{ms}$ upon receipt of payment intent, while payment clearance (Lightning / Liquid 0-conf) settles asynchronously in the background.
- **Multi-Rail Direct-to-Maintainer Inflows**: Developers pay in real mainnet satoshis via Lightning (`faucet@getalby.com`), Liquid Network (L-BTC with `OP_RETURN`), or Cashu (eCash bearer tokens).
- **Batch & Scheduled UTXO Synthesizer**: Enterprise JSON/Protobuf payloads for staged multi-sig testing and automated CI/CD pipelines.

---

## 2. System Architecture & The 3 Inflow Pipelines

```
                                    [SOVEREIGN TESTNET4 FAUCET & DEV API]
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         ▼                                            ▼                                            ▼
[INFLOW 1: LIGHTNING LUD-12 / L402]          [INFLOW 2: LIQUID NETWORK L-BTC]             [INFLOW 3: CASHU ECASH BEARER]
• Send 21–10k sats to faucet@getalby.com     • Send L-sats to Liquid Address              • Send Cashu blinded token string
• Destination in Payment Memo / Comment      • Destination in tx OP_RETURN / Memo        • Attached in HTTP X-Cashu header
• Handled via Alby Webhook / L402            • Handled via Liquid Mempool Websocket       • Validated & claimed in <5ms
```

---

## 3. The Optimistic 0-Conf Settlement Flow (Tor-Native Speed)

To ensure automated CI/CD runners over Tor (`.onion`) receive sub-100ms response times:

```
[Developer CI/CD Script over Tor]
   │
   │ 1. POST http://faucetxxxxxxxxxxxx.onion/v1/drip
   │    Payload: { "address": "tb1qqujk...", "amount_sats": 50000, "proof": "<lightning_hash | liquid_txid | cashu_token>" }
   ▼
[Faucet Daemon on GCP (btc-node-spot)]
   │
   │ 2. Instant Sanity Check (<10ms):
   │    • Address valid & not in blacklisted fraud database? YES.
   │    • Payment intent / 0-conf mempool tx detected? YES.
   ▼
[INSTANT TESTNET4 DISPENSE (0ms Latency)]
   │
   │ 3. Signs & broadcasts Testnet4 transaction to public mempool.
   │ 4. Returns HTTP 200 OK + {"status": "success", "txid": "4a5e1e..."} immediately.
   ▼
[BACKGROUND ASYNCHRONOUS SETTLEMENT]
   │
   │ 5. Daemon monitors background payment settlement:
   │    • Lightning HTLC settles to faucet@getalby.com (2–5 sec).
   │    • Liquid 1-minute block confirms on-chain.
   │ 6. If payment completes: Transaction permanently marked CLEARED in SQLite DB.
   │ 7. If payment fails / is double-spent: Destination testnet address is added to Blacklist.
   │    (Risk to maintainer: $0.00 since testnet coins carry zero production capital cost).
```

---

## 4. Enterprise UTXO Synthesizer (Batch & Scheduled Payloads)

For enterprise test suites (multi-sig treasuries, exchange hot-wallets, lightning channel testing):

### Request Payload (`POST /v1/bundle`):
```json
{
  "project": "Multi-Sig Staged Treasury Test",
  "auth": {
    "payment_method": "lightning",
    "preimage": "8f14e45fceea167a5a36dedd4bea2543..."
  },
  "allocations": [
    { "address": "tb1qqujk5789ke2hxs8n4xt3wxvlkmeu287p642pnv", "amount_sats": 50000, "delay_blocks": 0 },
    { "address": "tb1qqujk5789ke2hxs8n4xt3wxvlkmeu287p642pnv", "amount_sats": 25000, "delay_blocks": 1 },
    { "address": "tb1qucaluu78c4e3plek2hat0nf6gsmzzuzc4l0ucs", "amount_sats": 100000, "delay_blocks": 3 },
    { "address": "tb1qp65tg6lrlazrhkf0c2nran498hchfsaafszxgx", "amount_sats": 500000, "delay_blocks": 6 }
  ],
  "webhook_callback": "https://ci.devcompany.com/webhooks/testnet4-funded"
}
```

### High-Margin B2B Rate Card:
- **Smoke-Test Tier (100 Real Sats / ~$0.06)**: 50,000 Testnet4 sats.
- **CI/CD Pipeline Tier (1,000 Real Sats / ~$0.60)**: 1,000,000 Testnet4 sats (0.01 tBTC).
- **Exchange / Whale Test Pack (10,000 Real Sats / ~$6.00)**: 20,000,000 Testnet4 sats (0.20 tBTC).
- **Enterprise Monthly SaaS ($49–$199/mo)**: Dedicated RPC relay, unthrottled scheduled batch streaming, Protobuf endpoints.

---

## 5. Security, Anti-Abuse & Infrastructure Guardrails

1. **Kernel-Level Abuse Throttling (`fail2ban` + `nftables`)**:
   - Progressive exponential backoff (`bantime.increment = true`, factor 2).
   - Nginx rate-limiting on burst API queries.
2. **Tor Rate Limiting by Proof-of-Work**:
   - For free tier (Tier 1) users over Tor, an in-browser 5-to-10 second Hashcash SHA-256 challenge eliminates automated bot spam without CAPTCHAs.
3. **GCP Spot VM Resuscitation & Persistence**:
   - Hosted concurrently on `btc-node-spot` (`e2-small` Spot instance) with local SQLite state.
   - Zero additional cloud infrastructure expenditure ($0 marginal compute cost).
