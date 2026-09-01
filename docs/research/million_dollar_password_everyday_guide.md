# The Everyday User's Guide to the "$1 Million Password"

How long does a truly random password need to be so that it costs an attacker **\$1,000,000 in electricity & hardware** to crack offline?

---

## 1. The Entropy Targets (At \$0.05 / kWh Industrial Power)

1. **Against Fast Raw Hashes (MD5 / SHA-256 / ZIP Passwords)**:
   - Requires **71 bits of true physical entropy**.
2. **Against Memory-Hard / Keyosk Vaults (Argon2id / PBKDF2 600,000 iters)**:
   - Requires **50 bits of true physical entropy**.

---

## 2. Character Lengths Required for a "$1M Password"

If every character is selected with **true uniform randomness** (e.g. dice, coins, or CSPRNG):

| Password Alphabet / Source | Bits per Char | Minimum Chars for **\$1M Fast-Hash Armor** (71 bits) | Minimum Chars for **\$1M Keyosk / Argon2 Armor** (50 bits) | Example Format |
| :--- | :--- | :--- | :--- | :--- |
| **Coin Flips (0/1)** | $1.00 \text{ bit}$ | **71 flips** | **50 flips** | `101100101...` |
| **Physical Dice (1–6)** | $2.58 \text{ bits}$ | **28 rolls** | **20 rolls** | `351624...` |
| **Lowercase Letters Only (`[a-z]`, 26 chars)** | $4.70 \text{ bits}$ | **16 characters** | **11 characters** | `qvmxwtpzbkmplkja` |
| **Upper + Lowercase (`[a-zA-Z]`, 52 chars)** | $5.70 \text{ bits}$ | **13 characters** | **9 characters** | `kNpQwZxLmbTqA` |
| **Alphanumeric (`[a-zA-Z0-9]`, 62 chars)** | $5.95 \text{ bits}$ | **12 characters** | **9 characters** | `7kNp9wZxLm8T` |
| **Full Keyboard (`[a-zA-Z0-9!@#...]`, 94 chars)** | $6.55 \text{ bits}$ | **11 characters** | **8 characters** | `7k#Np9!wZx$` |
| **EFF Diceware Words (7,776 words)** | $12.92 \text{ bits}$ | **6 words** | **4 words** | `correct horse battery staple` |
| **BIP-39 English Words (2,048 words)** | $11.00 \text{ bits}$ | **7 words** | **5 words** | `laptop ozone reason vote theme funny` |

---

## 3. The "Human Mental Model" Breakdown

### A. The 11-Character Special Characters Fallacy
- Non-technical users often believe an 8-character password with `!@#$` is invincible.
- In reality, an 8-character password with special characters is only **~52 bits** ($94^8 \approx 6 \times 10^{15}$ combinations).
- On a fast GPU cluster (8x RTX 4090 cracking raw NTLM/MD5 at 100 GH/s), **8 characters takes under 1 minute and costs \$0.02**.
- To reach the **\$1,000,000 threshold on fast hashes**, you must reach **11 full-keyboard characters** or **16 lowercase letters**.

### B. The Word-Based Revolution (Diceware / BIP-39)
- **4 Diceware words** (`~52 bits`) costs **\$2,000,000** to crack on a memory-hard vault (`vault.json` / `vault.age`).
- **6 Diceware words** (`~78 bits`) costs **\$100+ Million** to crack even on raw ASIC-accelerated SHA-256.
- **12 BIP-39 words** (`128 bits`) costs more than the total energy output of our solar system.

---

## 4. Visual Summary for Non-Technical Users

```
  ==============================================================
                 THE $1,000,000 PASSWORD RULER                  
  ==============================================================
   [44-50 Bits]   5 BIP-39 Words   or   9 Mixed Alphanumeric Chars
                  --> Costs $1M+ to crack on Memory-Hard Vaults
  --------------------------------------------------------------
   [71-80 Bits]   7 BIP-39 Words   or  12 Mixed Alphanumeric Chars
                  --> Costs $1M+ to crack on Fast Raw Hashes (ASICs)
  --------------------------------------------------------------
   [128 Bits]    12 BIP-39 Words   or  22 Mixed Alphanumeric Chars
                  --> Absolute Mathematical Immortality (Subzero Standard)
  ==============================================================
```
