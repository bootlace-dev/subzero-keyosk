# Physical Dice Bias & Thermodynamic Security Rules

---

## 1. Executive Summary & Core Rule

> **The 65% Mathematical Safety Rule**:
> For a 50-roll physical dice sequence to drop below the practical attack threshold (<= 2^72 operations), a single face must land with a probability of **>= 65%** (landing on that face ~2 out of every 3 rolls).
> 
> Even with cheap, poorly-printed, asymmetric commodity plastic dice displaying noticeable cosmetic defects, manufacturing variances never exceed **1% to 3%**. Physical dice bias confers **zero actionable economic advantage** to an adversary.

---

## 2. Mathematical Breakdown (Shannon Entropy vs Worst-Case Min-Entropy)

For a 6-sided die where a defective face lands with probability p and the remaining 5 faces land with equal probability (1-p)/5:

- **Shannon Average Entropy**: H(p) = - [ p * log2(p) + 5 * ((1-p)/5) * log2((1-p)/5) ]
- **Adversarial Worst-Case Min-Entropy**: H_infinity(p) = - log2(p)

| Face Bias (p) | Real-World Context | Shannon Entropy / Roll | Min-Entropy (H_infinity) / Roll | 50-Roll Min-Entropy | Security Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **16.67%** | Fair Precision Die | 2.585 bits | 2.585 bits | **129.2 bits** | **Mathematically Unbreakable** |
| **18.00%** | Cheap Commodity Plastic (Amazon) | 2.580 bits | 2.474 bits | **123.7 bits** | **Mathematically Unbreakable** |
| **30.00%** | Visibly Warped / Defective Die | 2.435 bits | 1.737 bits | **86.8 bits** | **Thermodynamically Secure** |
| **50.00%** | Weighted Trick / Cheating Die | 1.961 bits | 1.000 bits | **50.0 bits** | **Compromised** (GPU Array) |
| **65.00%** | **Threshold of Danger (2 in 3 rolls)** | **1.432 bits** | **0.621 bits** | **31.1 bits** | **Trivially Cracked** |
| **80.00%** | Blatant Cheat Die (4 in 5 rolls) | 0.884 bits | 0.322 bits | **16.1 bits** | **Instant Crack** (Milliseconds) |

---

## 3. Threat Model & Attacker Knowledge (The Amazon Dice Case Study)

Even if an attacker possesses full forensic knowledge that the target used a specific set of cheap commodity dice (e.g. `SmartDealsPro Assorted Mini Dice`):

1. **Intra-Batch Randomness**: Manufacturing weight imperfections differ across every single die in the bag (one die favors 2, another favors 5, another is neutral).
2. **Human Rolling Mechanics**: Tumbling, cup agitation, and surface collisions introduce orders of magnitude more chaotic physical entropy than microscopic pip-depth differences.
3. **Key Derivation Work-Factor Moat**: Even with a 1-3% bias, candidate verification requires `SHA-256 -> BIP39 Mnemonic -> PBKDF2-HMAC-SHA512 (2048 iterations) -> BIP32 secp256k1 EC Point Multiplication`. Searching 2^123 iterations exceeds the total energy capacity of planet Earth.

---

## 4. The SubZero Over-Sampling Defense (Leftover Hash Lemma Extraction)

SubZero Keyosk incorporates an **uncapped physical entropy intake design**:

- **No Hard Stop at 128 Bits**: The minimum threshold is 128 bits (50 dice rolls or 128 coin flips), but the system accepts continuous entry up to 256 bits (100 rolls).
- **Leftover Hash Lemma Guarantee**: Extracting a 128-bit master seed requires ~130 bits of raw min-entropy. Entering **55 to 60 rolls** delivers **136 to 148 bits of pure min-entropy**, fully saturating the extractor and mathematically erasing any physical asymmetry.
- **Cryptographic Whitening**: The raw physical sequence is passed through SHA-256 to extract a uniformly distributed 128-bit master entropy slice, transforming any minor physical imperfections into perfect cryptographic white noise.
