# The "Million-Dollar Password" Proof-of-Work Economics

---

## 1. The Core Economic Principle
An attacker will only attempt a brute-force attack if:
$$\mathbb{E}[\text{Profit}] = P(\text{Success}) \times \text{Prize} - \text{Cost of Compute} > 0$$

If the electrical, hardware, and amortization cost to search a percentage of the keyspace exceeds **\$1,000,000**, the attack is mathematically irrational and an economic failure.

---

## 2. Attack Economics by Algorithm Class

Assuming pure coin-flip physical entropy (1 flip = 1.000 bit of true uniform entropy):

### A. Fast / ASIC-Accelerable Hashes (e.g. Raw SHA-256 / MD5 / Bitcoin PoW)
- **State of the Art (2026)**: Antminer S21 Pro / custom FPGA clusters achieve **~350 TH/s ($3.5 \times 10^{14}$ hashes/sec)** at **15 J/TH (15 W per TH/s)**.
- **Cost of 1 kWh Electricity**: \$0.05 (industrial wholesale).
- **Hashes per \$1.00 of Electricity**:
  $$\frac{1 \text{ kWh}}{\$0.05} \times \frac{1 \text{ TH}}{15 \text{ Wh}} \times 10^{12} = 1.33 \times 10^{15} \text{ hashes / dollar}$$
- **Hashes per \$1,000,000 of Electricity**:
  $$\approx 1.33 \times 10^{21} \text{ hashes} \approx 2^{70} \text{ hashes}$$

> **Result for Raw Fast Hashes**:
> To cost an attacker **\$1 Million** to crack a raw fast hash, you need **71 bits of pure coin entropy** (71 coin flips).
> An 80-bit password ($2^{80}$) costs **\$500+ Million** to crack.

---

### B. Memory-Hard KDFs (e.g. Argon2id / Scrypt / `age`)
- **Key Derivation Cost**: Each guess requires 64MB–1GB of dedicated SRAM/DRAM and cannot be pipelined onto cheap ASIC bit-flippers.
- **Top GPU (NVIDIA RTX 4090)**: Yields only **~10,000 Argon2id attempts/sec** (~350 Watts).
- **Cost per Attempt**: ~\$0.00000005 per guess.
- **Hashes per \$1,000,000 of Electricity + GPU Amortization**:
  $$\approx 10^{13} \text{ attempts} \approx 2^{43} \text{ attempts}$$

> **Result for Memory-Hard KDFs**:
> To cost an attacker **\$1 Million** to crack an Argon2id / Scrypt protected file, you only need **44 bits of pure coin entropy** (44 coin flips).
> A 50-bit password ($2^{50}$) costs **\$64+ Million** to crack.

---

### C. Iterated PBKDF2-HMAC-SHA256 (600,000 Iterations — Subzero Keyosk `vault.json`)
- **Top Hashcat Rig (8x RTX 4090)**: Yields **~500,000 guesses/sec** at 3,200 Watts.
- **Attempts per \$1,000,000**:
  $$\approx 5 \times 10^{14} \text{ attempts} \approx 2^{49} \text{ attempts}$$

> **Result for Subzero Keyosk `vault.json` (600k iters)**:
> To cost an attacker **\$1 Million** to crack `vault.json`, you need **50 bits of pure coin entropy** (50 coin flips).

---

## 3. The 12-Word Standard vs. The \$1 Million Threshold

| Entropy Source | Bits | Attacker Cost to Crack (Raw SHA-256) | Attacker Cost to Crack (Keyosk `vault.json`) |
| :--- | :--- | :--- | :--- |
| **40 Coin Flips** | 40 bits | \$0.0008 | \$2,000 |
| **50 Coin Flips** | 50 bits | \$0.80 | **\$2,000,000 (\$2M)** |
| **60 Coin Flips** | 60 bits | \$850 | **\$2 Billion (\$2B)** |
| **71 Coin Flips** | 71 bits | **\$1,000,000 (\$1M)** | **\$4 Trillion** |
| **Subzero 12 Words** | **128 bits** | **\$250,000,000,000,000,000,000 (\$250 Quintillion)** | **Exceeds total energy in the observable universe** |

---

## 4. The "Attacker Motivation" Curve (Game Theory)

1. **The \$1M Prize vs. 128 Bits**:
   - If an attacker knows with 100% certainty that a 12-word encrypted payload holds **\$1,000,000,000 (\$1 Billion)** in Bitcoin, the expected return on running their GPU cluster is:
     $$\mathbb{E}[\text{Return}] = \frac{\$1,000,000,000}{2^{128}} - \text{Cost} = \$0.000000000000000000000000000029 - \text{Electricity} < 0$$
   - The rational attacker shuts off the computer immediately.

2. **Thermodynamic Asymmetry**:
   - It takes you **15 seconds to flip 12 coins / roll dice**.
   - It takes the world's most powerful nation-state **more money than the global GDP** to test the combinations.
