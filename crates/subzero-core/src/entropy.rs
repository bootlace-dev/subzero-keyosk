//! Cooperative Two-Tier Entropy Engine (`subzero-core::entropy`).
//!
//! WHY TWO EXPLICIT TIERS:
//! A Cold Vault and its human operator are teammates, not adversaries. Earlier drafts blurred
//! two fundamentally different physical trust models and accidentally undermined both:
//!   - Tier 1 (Physical Discrete Entropy: Coins, Dice, 52-Card Playing Deck) requires 0% trust
//!     in the host CPU clock and is 100% reproducible on an independent second calculator.
//!   - Tier 2 (Cooperative Biomechanical Keystroke Timing) relies on an unclamped monotonic
//!     host clock (`Instant::now()` on Linux TTY1 or unclamped `performance.now()`), forces
//!     slow cross-row visual-motor search + `Backspace` error recovery over a deterministic
//!     zero-OS-RNG 200-character obstacle course, blocks clamped timers (`Tor Browser` 100ms),
//!     and meters conservative pre-hash NIST SP 800-90B Non-IID min-entropy (>= 192 bits).

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SubZeroError;
use crate::presets::{preset_entropy, PRESET_COUNT};

type HmacSha512 = Hmac<Sha512>;

pub const MIN_COIN_FLIPS: usize = 128;
pub const MIN_DICE_ROLLS: usize = 50;
pub const RECOMMENDED_DICE_ROLLS: usize = 60;
pub const DECK_CARD_COUNT: usize = 52;
pub const OBSTACLE_COURSE_LEN: usize = 200;
pub const MIN_TIER2_ENTROPY_BITS: f64 = 192.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyTrustTier {
    /// Physical discrete input (Coins, Dice, 52-Card Deck, Raw TRNG Hex):
    /// 0% host clock trust; 100% verifiable on any independent offline calculator.
    SecondDeviceReproducible,
    /// Cooperative keystroke timing course:
    /// Strong against external brute-force, but relies on an unclamped host clock and cannot
    /// be re-derived on a second calculator from the prompt string alone.
    HostClockDependent,
    /// Public deterministic Testnet4 rehearsal vector (`Preset 0..9`): 0 bits secret entropy.
    DeterministicRehearsalPreset,
    /// Watch-only descriptor or extended public key (`0` private keys in RAM).
    WatchOnlyNoSecrets,
}

impl EntropyTrustTier {
    pub fn badge(&self) -> &'static str {
        match self {
            Self::SecondDeviceReproducible => {
                "Tier 1: Physical Discrete Entropy (2nd-Device Verifiable - 0% Host Clock Trust)"
            }
            Self::HostClockDependent => {
                "Tier 2: Cooperative Keystroke Timing (Unclamped Host Clock Required - Not Re-Derivable on a 2nd Calculator)"
            }
            Self::DeterministicRehearsalPreset => {
                "Public Testnet4 Rehearsal Preset (0 Bits Secret Entropy - Never Use for Real Funds)"
            }
            Self::WatchOnlyNoSecrets => {
                "Watch-Only Public Descriptor (Zero Private Keys in Memory)"
            }
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ConditionedEntropy {
    pub bytes: [u8; 16],
    #[zeroize(skip)]
    pub trust_tier: EntropyTrustTier,
    pub method_label: String,
    pub audit_summary: String,
    #[zeroize(skip)]
    pub estimated_min_entropy_bits: f64,
    pub repro_formula_hint: String,
}

impl core::fmt::Debug for ConditionedEntropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConditionedEntropy")
            .field("bytes", &"[REDACTED 16B]")
            .field("trust_tier", &self.trust_tier)
            .field("method_label", &self.method_label)
            .field("estimated_min_entropy_bits", &self.estimated_min_entropy_bits)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalAudit {
    pub passed: bool,
    pub max_markov_prob: f64,
    pub chi_squared: f64,
    pub summary: String,
}

/// Check whether a 16-byte entropy buffer matches any of the 10 public Testnet4 rehearsal presets.
pub fn is_known_public_preset_entropy(bytes: &[u8; 16]) -> Option<u8> {
    for id in 0..(PRESET_COUNT as u8) {
        if let Ok(p_bytes) = preset_entropy(id) {
            if &p_bytes == bytes {
                return Some(id);
            }
        }
    }
    None
}

fn reject_known_preset_as_live(bytes: &[u8; 16]) -> Result<(), SubZeroError> {
    if let Some(id) = is_known_public_preset_entropy(bytes) {
        return Err(SubZeroError::Entropy(format!(
            "Entropy matches public Testnet4 rehearsal Preset #{id} (0 bits of secret entropy). Select Preset #{id} in Rehearsal Presets for practice, or supply genuine physical entropy for a live vault."
        )));
    }
    Ok(())
}

/// First-order Markov transition audit on raw discrete symbols (`0/1` or `1..6`) BEFORE hashing.
pub fn audit_discrete_markov(clean: &str, max_allowed_prob: f64, min_row_obs: usize) -> Result<f64, SubZeroError> {
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() < 16 {
        return Err(SubZeroError::Entropy(
            "Need at least 16 symbols before running statistical transition checks.".into(),
        ));
    }

    let mut counts: BTreeMap<char, BTreeMap<char, usize>> = BTreeMap::new();
    let mut row_totals: BTreeMap<char, usize> = BTreeMap::new();

    for pair in chars.windows(2) {
        *counts.entry(pair[0]).or_default().entry(pair[1]).or_insert(0) += 1;
        *row_totals.entry(pair[0]).or_insert(0) += 1;
    }

    let mut max_cond_prob = 0.0f64;
    for (prev, next_map) in &counts {
        let total = row_totals[prev];
        if total < min_row_obs {
            continue;
        }
        for &cnt in next_map.values() {
            let p = (cnt as f64) / (total as f64);
            if p > max_cond_prob {
                max_cond_prob = p;
            }
        }
    }

    if max_cond_prob > max_allowed_prob {
        return Err(SubZeroError::Entropy(format!(
            "Predictable transition pattern detected (max conditional transition {:.0}% > {:.0}% limit). Use genuine physical flips/rolls rather than typing alternating patterns by hand.",
            max_cond_prob * 100.0,
            max_allowed_prob * 100.0
        )));
    }
    Ok(max_cond_prob)
}

/// Pearson's Chi-squared uniformity check on raw discrete symbols BEFORE hashing.
pub fn audit_discrete_chi_squared(clean: &str, alphabet: &[char], critical_value: f64) -> Result<f64, SubZeroError> {
    let n = clean.len();
    let k = alphabet.len();
    let expected = (n as f64) / (k as f64);
    let mut chi2 = 0.0f64;

    for &sym in alphabet {
        let obs = clean.chars().filter(|&c| c == sym).count() as f64;
        chi2 += (obs - expected).powi(2) / expected;
    }

    if chi2 > critical_value {
        return Err(SubZeroError::Entropy(format!(
            "Symbol frequency is heavily skewed (Chi-squared {:.2} > {:.2} at p=0.001). Check for stuck keys or biased transcription.",
            chi2, critical_value
        )));
    }
    Ok(chi2)
}

/// Detect long single-symbol runs or short periodic copy-paste chunks in discrete streams.
pub fn reject_periodic_patterns(clean: &str, is_binary: bool) -> Result<(), SubZeroError> {
    let chars: Vec<char> = clean.chars().collect();
    if is_binary {
        if clean.contains("0000000000000000") || clean.contains("1111111111111111") {
            return Err(SubZeroError::Entropy(
                "Detected 16+ identical coin flips in a row. Double-check your flip log or append additional flips.".into(),
            ));
        }
        for size in 2..=8 {
            let reps = match size {
                2 => 9,
                3 => 6,
                4 => 5,
                _ => 4,
            };
            if chars.len() >= size * reps {
                for i in 0..=chars.len() - size * reps {
                    let base = &chars[i..i + size];
                    if (1..reps).all(|r| &chars[i + r * size..i + (r + 1) * size] == base) {
                        return Err(SubZeroError::Entropy(
                            "Detected repeating periodic sequence in coin flips. Check for accidental chunk copy-paste.".into(),
                        ));
                    }
                }
            }
        }
        for size in 18..=(chars.len() / 2) {
            for i in 0..=chars.len() - 2 * size {
                if chars[i..i + size] == chars[i + size..i + 2 * size] {
                    return Err(SubZeroError::Entropy(
                        "Detected duplicated block in coin flips (possible accidental paste).".into(),
                    ));
                }
            }
        }
    } else {
        for size in 1..=6 {
            let reps = match size {
                1 => 8,
                2 => 6,
                3 => 4,
                _ => 3,
            };
            if chars.len() >= size * reps {
                for i in 0..=chars.len() - size * reps {
                    let base = &chars[i..i + size];
                    if (1..reps).all(|r| &chars[i + r * size..i + (r + 1) * size] == base) {
                        return Err(SubZeroError::Entropy(
                            "Detected repeating sequence in dice rolls (e.g. 123456 or repeated digit run).".into(),
                        ));
                    }
                }
            }
        }
        for size in 10..=(chars.len() / 2) {
            for i in 0..=chars.len() - 2 * size {
                if chars[i..i + size] == chars[i + size..i + 2 * size] {
                    return Err(SubZeroError::Entropy(
                        "Detected duplicated block of 10+ dice rolls (possible accidental paste).".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Tier 1A: Harvest physical coin flips (`128+` flips of `0/1` or `H/T`).
///
/// WHY 128 EXACT vs >128 SHA-256:
/// - Exact 128 flips map 1:1 big-endian into 16 bytes so standard BIP-39 binary calculators
///   (SeedSigner, Coldcard, offline Python) produce the exact same 12 words.
/// - More than 128 flips are conditioned via `SHA256(stream)[0..16]` so extra flips are NEVER
///   silently truncated.
pub fn harvest_coins(raw_input: &str) -> Result<ConditionedEntropy, SubZeroError> {
    let mut clean = String::with_capacity(raw_input.len());
    for (idx, ch) in raw_input.chars().enumerate() {
        if ch.is_whitespace() || ch == ',' || ch == '-' || ch == '_' {
            continue;
        }
        match ch {
            '0' | 't' | 'T' => clean.push('0'),
            '1' | 'h' | 'H' => clean.push('1'),
            other => {
                return Err(SubZeroError::Entropy(format!(
                    "Unexpected character '{}' at position {} in coin stream (use 1/0 or H/T).",
                    other,
                    idx + 1
                )));
            }
        }
    }

    if clean.len() < MIN_COIN_FLIPS {
        return Err(SubZeroError::Entropy(format!(
            "Need at least {} coin flips for 128-bit security (currently {} flips).",
            MIN_COIN_FLIPS,
            clean.len()
        )));
    }

    let max_m = audit_discrete_markov(&clean, 0.82, 8)?;
    let chi2 = audit_discrete_chi_squared(&clean, &['0', '1'], 10.828)?;
    reject_periodic_patterns(&clean, true)?;

    let mut bytes = [0u8; 16];
    let (method_label, repro_formula_hint) = if clean.len() == 128 {
        for (i, chunk) in clean.as_bytes().chunks_exact(8).enumerate() {
            let s = core::str::from_utf8(chunk).unwrap();
            bytes[i] = u8::from_str_radix(s, 2).unwrap();
        }
        (
            "Tier 1 Physical Coin Flips (128-Bit Direct BIP-39 Binary)".to_string(),
            "2nd-Device Check: Convert 128 bits (H=1, T=0) in 8-bit big-endian bytes -> BIP-39".to_string(),
        )
    } else {
        let digest = Sha256::digest(clean.as_bytes());
        bytes.copy_from_slice(&digest[..16]);
        (
            format!("Tier 1 Physical Coin Flips ({} Flips -> SHA-256)", clean.len()),
            "2nd-Device Check: printf '%s' '<01-stream>' | sha256sum | cut -c1-32 -> BIP-39".to_string(),
        )
    };
    reject_known_preset_as_live(&bytes)?;

    Ok(ConditionedEntropy {
        bytes,
        trust_tier: EntropyTrustTier::SecondDeviceReproducible,
        method_label,
        audit_summary: format!(
            "Coins OK ({} flips, Markov max {:.0}%, Chi2 {:.2} <= 10.83)",
            clean.len(),
            max_m * 100.0,
            chi2
        ),
        estimated_min_entropy_bits: clean.len() as f64,
        repro_formula_hint,
    })
}

/// Tier 1B: Harvest physical 6-sided dice rolls (`50+` rolls of `1..6`; `60` recommended).
pub fn harvest_dice(raw_input: &str) -> Result<ConditionedEntropy, SubZeroError> {
    let mut clean = String::with_capacity(raw_input.len());
    for (idx, ch) in raw_input.chars().enumerate() {
        if ch.is_whitespace() || ch == ',' || ch == '-' || ch == '_' {
            continue;
        }
        if ('1'..='6').contains(&ch) {
            clean.push(ch);
        } else {
            return Err(SubZeroError::Entropy(format!(
                "Unexpected character '{}' at position {} in dice stream (use digits 1 through 6).",
                ch,
                idx + 1
            )));
        }
    }

    if clean.len() < MIN_DICE_ROLLS {
        return Err(SubZeroError::Entropy(format!(
            "Need at least {} dice rolls for >=128 bits of entropy ({} recommended; currently {} rolls).",
            MIN_DICE_ROLLS,
            RECOMMENDED_DICE_ROLLS,
            clean.len()
        )));
    }

    let max_m = audit_discrete_markov(&clean, 0.78, 6)?;
    let chi2 = audit_discrete_chi_squared(&clean, &['1', '2', '3', '4', '5', '6'], 20.515)?;
    reject_periodic_patterns(&clean, false)?;

    let digest = Sha256::digest(clean.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    reject_known_preset_as_live(&bytes)?;

    let raw_bits = (clean.len() as f64) * 6.0f64.log2();
    Ok(ConditionedEntropy {
        bytes,
        trust_tier: EntropyTrustTier::SecondDeviceReproducible,
        method_label: format!("Tier 1 Physical Dice Rolls ({} Rolls -> SHA-256)", clean.len()),
        audit_summary: format!(
            "Dice OK ({} rolls = {:.1} raw bits, Markov max {:.0}%, Chi2 {:.2} <= 20.52)",
            clean.len(),
            raw_bits,
            max_m * 100.0,
            chi2
        ),
        estimated_min_entropy_bits: raw_bits,
        repro_formula_hint: "2nd-Device Check: printf '%s' '<1-6-rolls>' | sha256sum | cut -c1-32 -> BIP-39"
            .to_string(),
    })
}

const RANKS: [char; 13] = ['a', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'j', 'q', 'k'];
const SUITS: [char; 4] = ['c', 'd', 'h', 's'];

fn rank_index(r: char) -> Option<usize> {
    RANKS.iter().position(|&x| x == r)
}

fn suit_index(s: char) -> Option<usize> {
    SUITS.iter().position(|&x| x == s)
}

fn card_code_from_id(id: usize) -> String {
    let suit = SUITS[id / 13];
    let rank = RANKS[id % 13];
    format!("{rank}{suit}")
}

/// Count rising sequences of permutation `deck` relative to a reference 52-card factory ordering.
/// For a genuinely shuffled 52-card deck (wash + 7-8 riffles), Eulerian distribution gives
/// mean = 26.5, std = 2.1016; [19, 34] covers >99.93% of true uniform permutations while
/// catching unshuffled (1), reversed (52), cut (2), or under-shuffled (1..4 riffles <= 16) decks.
pub fn count_rising_sequences_against(deck_ids: &[usize; 52], ref_order: &[usize; 52]) -> usize {
    // Map each canonical card id -> its rank in `ref_order` (0..51)
    let mut ref_rank = [0usize; 52];
    for (r_idx, &cid) in ref_order.iter().enumerate() {
        ref_rank[cid] = r_idx;
    }
    // Map each ref_rank (0..51) -> its position in `deck_ids` (0..51)
    let mut pos_in_deck = [0usize; 52];
    for (pos, &cid) in deck_ids.iter().enumerate() {
        pos_in_deck[ref_rank[cid]] = pos;
    }
    let mut rising = 1usize;
    for v in 0..51 {
        if pos_in_deck[v + 1] < pos_in_deck[v] {
            rising += 1;
        }
    }
    rising
}

/// Detect deterministic affine/pile-deal/perfect-faro permutations relative to a factory deck.
///
/// WHY RISING SEQUENCES ALONE ARE INSUFFICIENT (`[H-05]` FIX):
/// Dealing a factory-ordered deck once into 2 piles (`even` then `odd`) or performing 5x/7x
/// perfect faro shuffles produces ~26 rising sequences (inside `19..=34`) with 0 bits of secret
/// entropy! Because pile-deals and in/out faro shuffles act as affine index maps modulo 51, 52,
/// or 53, they preserve constant rank-step differences `(r[i + lag] - r[i]) mod M` across dozens
/// of pairs. In a genuinely washed + 7x riffle-shuffled deck, the maximum collisions in any single
/// modular step bucket across lags `1..=4` and `M in [51, 52, 53]` is ~3..5 (`<= 9` at >99.96%).
fn max_affine_step_concentration(deck_ids: &[usize; 52], ref_order: &[usize; 52]) -> usize {
    let mut ref_rank = [0usize; 52];
    for (r_idx, &cid) in ref_order.iter().enumerate() {
        ref_rank[cid] = r_idx;
    }
    let mapped: Vec<usize> = deck_ids.iter().map(|&cid| ref_rank[cid]).collect();
    let mut worst = 0usize;
    for lag in 1..=4usize {
        for modulus in [51usize, 52usize, 53usize] {
            let mut buckets = [0usize; 53];
            for i in 0..(52 - lag) {
                let a = mapped[i] % modulus;
                let b = mapped[i + lag] % modulus;
                let diff = (b + modulus - a) % modulus;
                buckets[diff] += 1;
                if buckets[diff] > worst {
                    worst = buckets[diff];
                }
            }
        }
    }
    worst
}

/// Tier 1C: Harvest a full physical 52-card playing deck (`log2(52!) = 225.58` bits theoretical max).
///
/// Cooperative guardrails:
/// 1. Accepts spaces, commas, or continuous pairs (`ah 4c 10d...` or `ah4ctd...`), case-insensitive.
/// 2. Full 52-card bijection check reports exact duplicate AND missing cards so the user can fix
///    a single transcription typo without re-shuffling.
/// 3. Bayer-Diaconis rising-sequence check (`19..=34`) + multi-lag affine step detector (`<= 9`)
///    against both standard suit order and USPCC Bicycle factory new-deck order catches unshuffled,
///    cut, pile-dealt, or perfect-faro decks.
pub fn harvest_playing_cards(raw_input: &str) -> Result<ConditionedEntropy, SubZeroError> {
    let chars_in: Vec<char> = raw_input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '-' && *c != ';')
        .flat_map(|c| c.to_lowercase())
        .collect();

    if chars_in.is_empty() {
        return Err(SubZeroError::Entropy(
            "Enter all 52 shuffled playing cards (e.g. 'ah 4c td ks ...'). Wash 30-60s + 7 riffle shuffles first."
                .into(),
        ));
    }

    let mut parsed_ids: Vec<usize> = Vec::with_capacity(52);
    let mut cursor = 0usize;

    while cursor < chars_in.len() {
        let (rank_ch, suit_ch, consumed) = if cursor + 2 < chars_in.len()
            && chars_in[cursor] == '1'
            && chars_in[cursor + 1] == '0'
        {
            ('t', chars_in[cursor + 2], 3)
        } else if cursor + 1 < chars_in.len() {
            (chars_in[cursor], chars_in[cursor + 1], 2)
        } else {
            return Err(SubZeroError::Entropy(format!(
                "Trailing incomplete card character '{}' at end of input ({} complete cards parsed so far).",
                chars_in[cursor],
                parsed_ids.len()
            )));
        };

        let r_idx = rank_index(rank_ch).ok_or_else(|| {
            SubZeroError::Entropy(format!(
                "Invalid card rank '{}' at card #{} (valid ranks: A,2,3,4,5,6,7,8,9,T/10,J,Q,K).",
                rank_ch,
                parsed_ids.len() + 1
            ))
        })?;
        let s_idx = suit_index(suit_ch).ok_or_else(|| {
            SubZeroError::Entropy(format!(
                "Invalid card suit '{}' at card #{} (valid suits: c=clubs, d=diamonds, h=hearts, s=spades).",
                suit_ch,
                parsed_ids.len() + 1
            ))
        })?;

        parsed_ids.push(s_idx * 13 + r_idx);
        cursor += consumed;
    }

    // Bijection check over all 52 canonical cards
    let mut counts = [0usize; 52];
    for &cid in &parsed_ids {
        counts[cid] += 1;
    }

    let duplicates: Vec<String> = (0..52)
        .filter(|&cid| counts[cid] > 1)
        .map(|cid| format!("{} (x{})", card_code_from_id(cid), counts[cid]))
        .collect();
    let missing: Vec<String> = (0..52)
        .filter(|&cid| counts[cid] == 0)
        .map(card_code_from_id)
        .collect();

    if parsed_ids.len() != DECK_CARD_COUNT || !duplicates.is_empty() || !missing.is_empty() {
        let mut parts = Vec::new();
        parts.push(format!("Parsed {}/52 cards.", parsed_ids.len()));
        if !duplicates.is_empty() {
            parts.push(format!("Duplicate card(s): [{}].", duplicates.join(", ")));
        }
        if !missing.is_empty() {
            let preview = if missing.len() <= 12 {
                missing.join(", ")
            } else {
                format!("{} ... ({} missing total)", missing[..12].join(", "), missing.len())
            };
            parts.push(format!("Missing card(s): [{}].", preview));
        }
        parts.push("Fix the typo in your list rather than re-shuffling.".to_string());
        return Err(SubZeroError::Entropy(parts.join(" ")));
    }

    let mut deck_arr = [0usize; 52];
    deck_arr.copy_from_slice(&parsed_ids);

    // Reference Order 1: Canonical Bridge/Suit order (Ac..Kc, Ad..Kd, Ah..Kh, As..Ks)
    let mut std_order = [0usize; 52];
    for (i, slot) in std_order.iter_mut().enumerate() {
        *slot = i;
    }

    // Reference Order 2: USPCC / Bicycle factory new-deck order (Ah..Kh, Ac..Kc, Kd..Ad, Ks..As)
    let mut uspcc_order = [0usize; 52];
    let mut idx = 0;
    for r in 0..13 {
        uspcc_order[idx] = 2 * 13 + r; // Hearts A..K
        idx += 1;
    }
    for r in 0..13 {
        uspcc_order[idx] = r; // Clubs A..K
        idx += 1;
    }
    for r in (0..13).rev() {
        uspcc_order[idx] = 13 + r; // Diamonds K..A
        idx += 1;
    }
    for r in (0..13).rev() {
        uspcc_order[idx] = 3 * 13 + r; // Spades K..A
        idx += 1;
    }

    let rising_std = count_rising_sequences_against(&deck_arr, &std_order);
    let rising_uspcc = count_rising_sequences_against(&deck_arr, &uspcc_order);

    if !(19..=34).contains(&rising_std) || !(19..=34).contains(&rising_uspcc) {
        return Err(SubZeroError::Entropy(format!(
            "Deck appears insufficiently shuffled (Bayer-Diaconis rising sequences: suit-order={}, bicycle-order={}; expected 19..34 for a thoroughly shuffled deck). Wash the cards face-down for 30-60 seconds and perform 7-8 riffle shuffles.",
            rising_std, rising_uspcc
        )));
    }

    // Guard against deterministic pile-deals and perfect in/out faro shuffles
    let affine_std = max_affine_step_concentration(&deck_arr, &std_order);
    let affine_uspcc = max_affine_step_concentration(&deck_arr, &uspcc_order);
    if affine_std > 9 || affine_uspcc > 9 {
        return Err(SubZeroError::Entropy(format!(
            "Deck exhibits structured pile-deal or faro-shuffle periodicity (step concentration {}/{} > 9). Perform a 30-60s face-down table wash plus 7 imperfect riffle shuffles.",
            affine_std, affine_uspcc
        )));
    }

    // Also guard against custom sorted suit runs (adjacent cards of same suit and +/-1 rank)
    let mut same_suit_adj = 0usize;
    for pair in deck_arr.windows(2) {
        let (s0, r0) = (pair[0] / 13, pair[0] % 13);
        let (s1, r1) = (pair[1] / 13, pair[1] % 13);
        if s0 == s1 && r0.abs_diff(r1) == 1 {
            same_suit_adj += 1;
        }
    }
    if same_suit_adj > 8 {
        return Err(SubZeroError::Entropy(format!(
            "Deck retains {} adjacent sequential suited card pairs (expected ~2 in a shuffled deck). Perform a 30-60s table wash + 7 riffle shuffles.",
            same_suit_adj
        )));
    }

    let mut canonical_104 = String::with_capacity(104);
    for &cid in &deck_arr {
        canonical_104.push_str(&card_code_from_id(cid));
    }

    let digest = Sha256::digest(canonical_104.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    reject_known_preset_as_live(&bytes)?;

    Ok(ConditionedEntropy {
        bytes,
        trust_tier: EntropyTrustTier::SecondDeviceReproducible,
        method_label: "Tier 1 Physical 52-Card Playing Deck (104-Char Canonical SHA-256)".to_string(),
        audit_summary: format!(
            "52-Card Bijection OK (Rising seqs: {}/{}, affine step max: {}/{} <= 9, suited neighbors: {} <= 8; wash+7x riffles required, 225.6 bits max)",
            rising_std, rising_uspcc, affine_std, affine_uspcc, same_suit_adj
        ),
        estimated_min_entropy_bits: 160.0,
        repro_formula_hint:
            "2nd-Device Check: printf '%s' '<104-char-lowercase-rank-suit-stream>' | sha256sum | cut -c1-32 -> BIP-39"
                .to_string(),
    })
}

/// Tier 1D: Raw 128-bit (32 hex chars) external Hardware TRNG import.
pub fn harvest_raw_hex(raw_input: &str) -> Result<ConditionedEntropy, SubZeroError> {
    let clean: String = raw_input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect();
    let clean = clean.strip_prefix("0x").unwrap_or(&clean);
    if clean.len() != 32 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SubZeroError::Entropy(format!(
            "Raw hex import requires 32 hexadecimal characters (128 bits for 12 words); got {} chars.",
            clean.len()
        )));
    }
    let decoded = hex::decode(clean)
        .map_err(|e| SubZeroError::Entropy(format!("Invalid hexadecimal string: {e}")))?;
    if decoded.iter().all(|&b| b == decoded[0]) {
        return Err(SubZeroError::Entropy(
            "Constant-byte hex string rejected as live entropy (use Preset 0..3 if rehearsing)."
                .into(),
        ));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&decoded);
    reject_known_preset_as_live(&bytes)?;
    Ok(ConditionedEntropy {
        bytes,
        trust_tier: EntropyTrustTier::SecondDeviceReproducible,
        method_label: "Tier 1 External Hardware TRNG Hex (128-Bit Direct)".to_string(),
        audit_summary: "128-bit hexadecimal TRNG entropy imported directly.".to_string(),
        estimated_min_entropy_bits: 128.0,
        repro_formula_hint: "2nd-Device Check: Direct 16-byte BIP-39 entropy -> 12 words".to_string(),
    })
}

/// Deterministic, **zero-OS-RNG** cross-row obstacle prompt generator for Tier 2 keystroke timing.
///
/// WHY UNAMBIGUOUS CROSS-ROW POOLS:
/// 1. Excludes visually ambiguous lookalikes (`0`/`O`, `1`/`l`/`I`, `` ` ``/`'`) so the human operator
///    never wastes effort squinting at console fonts.
/// 2. Rotates deterministically across 4 distinct keyboard row/modifier pools (shifted symbols,
///    digits + punctuation, uppercase QWERTY, lowercase QWERTY) and forbids adjacent character
///    repeats so the user cannot drum on home-row keys or hold down auto-repeat.
pub fn generate_obstacle_prompt(round_counter: u32, length: usize) -> String {
    const POOL_SYM: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";
    const POOL_NUM: &[u8] = b"23456789";
    const POOL_UPP: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const POOL_LOW: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    let pools: [&[u8]; 4] = [POOL_LOW, POOL_SYM, POOL_UPP, POOL_NUM];

    let target_len = length.clamp(32, 4096);
    let mut out = String::with_capacity(target_len);
    let mut block_idx = 0u32;
    let mut prev_ch = '\0';
    let mut prev_pool_idx: Option<usize> = None;

    while out.len() < target_len {
        let mut hasher = Sha256::new();
        hasher.update(b"subzero:obstacle:prompt:v2:");
        hasher.update(round_counter.to_le_bytes());
        hasher.update(block_idx.to_le_bytes());
        let digest = hasher.finalize();
        block_idx = block_idx.wrapping_add(1);

        for pair in digest.chunks_exact(2) {
            if out.len() >= target_len {
                break;
            }
            // Strictly jump to a DIFFERENT pool every single character (`0%` adjacent same-pool pairs)
            let pool_idx = match prev_pool_idx {
                None => (pair[0] as usize) % 4,
                Some(prev_p) => (prev_p + 1 + ((pair[0] as usize) % 3)) % 4,
            };
            prev_pool_idx = Some(pool_idx);
            let pool = pools[pool_idx];
            let mut ch = pool[(pair[1] as usize) % pool.len()] as char;
            if ch == prev_ch {
                ch = pool[((pair[1] as usize) + 1) % pool.len()] as char;
            }
            prev_ch = ch;
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeystrokeSample {
    /// Key identifier (`"Backspace"` or single printable character).
    pub key: String,
    /// Elapsed monotonic microseconds since the previous accepted keydown event.
    pub delta_us: u64,
    pub is_backspace: bool,
    pub was_typo: bool,
    #[serde(default)]
    pub is_repeat: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeHealthReport {
    pub accepted_events: usize,
    pub backspace_events: usize,
    pub typo_events: usize,
    pub timer_quantum_ok: bool,
    pub timer_diagnostic: String,
    pub estimated_min_entropy_bits: f64,
    pub required_min_entropy_bits: f64,
}

fn timing_octave_bucket(delta_us: u64) -> usize {
    match delta_us {
        0..=59_999 => 0,        // < 60 ms
        60_000..=99_999 => 1,   // 60 - 100 ms
        100_000..=149_999 => 2, // 100 - 150 ms
        150_000..=219_999 => 3, // 150 - 220 ms
        220_000..=319_999 => 4, // 220 - 320 ms
        320_000..=499_999 => 5, // 320 - 500 ms
        500_000..=899_999 => 6, // 500 - 900 ms
        _ => 7,                 // >= 900 ms (Shift chord / visual search / Backspace recovery)
    }
}

/// Inspect raw inter-keystroke deltas (microseconds) for clamped clocks or synthetic macro paste,
/// and compute conservative pre-hash NIST SP 800-90B Non-IID min-entropy.
pub fn evaluate_keystroke_health(samples: &[KeystrokeSample]) -> Result<KeystrokeHealthReport, SubZeroError> {
    let filtered: Vec<&KeystrokeSample> = samples.iter().filter(|s| !s.is_repeat).collect();
    if filtered.len() < 16 {
        return Err(SubZeroError::Entropy(format!(
            "Need at least {} non-repeat keystroke timing events (currently {}).",
            OBSTACLE_COURSE_LEN,
            filtered.len()
        )));
    }

    // Skip index 0 if its delta_us is 0 (initial keydown anchor)
    let deltas: Vec<u64> = filtered
        .iter()
        .enumerate()
        .filter_map(|(i, s)| if i == 0 && s.delta_us == 0 { None } else { Some(s.delta_us) })
        .collect();

    if deltas.len() < 15 {
        return Err(SubZeroError::Entropy(
            "Insufficient inter-keystroke intervals recorded.".into(),
        ));
    }

    let n = deltas.len();
    let zero_count = deltas.iter().filter(|&&d| d == 0).count();
    if zero_count * 10 >= n {
        return Err(SubZeroError::Entropy(
            "Host timer appears frozen (>=10% zero-duration intervals). Switch to Tier 1 Physical Entropy (Coins, Dice, or 52-Card Deck).".into(),
        ));
    }

    // 1. Clamped-clock detection: Tor Browser / Firefox privacy.resistFingerprinting clamps
    // `performance.now()` to 100ms (100_000 us), 16.67ms frame boundaries (~16_667 / 16_600 / 16_700 us),
    // or >= 2ms..10ms coarse buckets.
    let mult_100ms = deltas.iter().filter(|&&d| d > 0 && d % 100_000 == 0).count();
    let mult_10ms = deltas.iter().filter(|&&d| d > 0 && d % 10_000 == 0).count();
    let mult_5ms = deltas.iter().filter(|&&d| d > 0 && d % 5_000 == 0).count();
    let mult_2ms = deltas.iter().filter(|&&d| d > 0 && d % 2_000 == 0).count();
    let mult_frame_60hz = deltas
        .iter()
        .filter(|&&d| {
            if d == 0 {
                return false;
            }
            let rem_exact = (d as f64) % 16_666.666_7;
            let near_exact = rem_exact < 150.0 || (16_666.666_7 - rem_exact) < 150.0;
            let near_rounded = (d % 16_600 <= 120) || (d % 16_700 <= 120);
            near_exact || near_rounded
        })
        .count();

    if mult_100ms * 100 / n >= 75
        || mult_10ms * 100 / n >= 80
        || mult_5ms * 100 / n >= 85
        || mult_2ms * 100 / n >= 90
        || mult_frame_60hz * 100 / n >= 80
    {
        return Err(SubZeroError::Entropy(
            "Clamped or coarse host timer detected (>=2ms / 10ms / 16.67ms / 100ms quantization, e.g. Tor Browser or resistFingerprinting). Tier 2 keystroke timing is disabled to protect you; use Tier 1 Physical Entropy (Coins, Dice, or 52-Card Deck), which needs 0% clock trust.".into(),
        ));
    }

    // 2. Reject robotic paste / macro injection (< 25ms median interval or < 8ms stddev)
    let mut sorted = deltas.clone();
    sorted.sort_unstable();
    let median_us = sorted[n / 2];
    if median_us < 25_000 {
        return Err(SubZeroError::Entropy(format!(
            "Inter-keystroke median ({:.1} ms) is faster than human cross-row typing (< 25 ms), indicating pasted or scripted input. Type the obstacle string naturally key-by-key.",
            (median_us as f64) / 1000.0
        )));
    }

    let mean = (deltas.iter().map(|&d| d as f64).sum::<f64>()) / (n as f64);
    let variance = deltas
        .iter()
        .map(|&d| {
            let diff = (d as f64) - mean;
            diff * diff
        })
        .sum::<f64>()
        / (n as f64);
    let stddev_us = variance.sqrt();
    if stddev_us < 8_000.0 {
        return Err(SubZeroError::Entropy(format!(
            "Timing jitter standard deviation ({:.2} ms) is synthetically uniform (< 8 ms). Type naturally without automated macros.",
            stddev_us / 1000.0
        )));
    }

    // 3. Conservative Non-IID Timing Min-Entropy Estimation (SP 800-90B §6.3.1 MCV + Octave Markov):
    //    (a) MCV estimator on 2ms-binned intervals (prevents high-res nanosecond uniqueness from
    //        over-crediting constant-rhythm drumming!)
    let mut bin2ms_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for &d in &deltas {
        // Cap extreme pauses > 2000ms into a single saturation bin so long coffee pauses don't look like distinct entropy symbols
        let b = (d.min(2_000_000)) / 2_000;
        *bin2ms_counts.entry(b).or_insert(0) += 1;
    }
    let max_bin_cnt = *bin2ms_counts.values().max().unwrap_or(&n);
    let p_hat = (max_bin_cnt as f64) / (n as f64);
    let p_u_mcv = (p_hat + 2.576 * ((p_hat * (1.0 - p_hat)) / ((n.saturating_sub(1).max(1)) as f64)).sqrt())
        .min(0.999_999);
    let h_mcv = -p_u_mcv.log2();

    //    (b) First-Order Markov estimator over 8 octave timing buckets (catches rhythmic drumming!)
    let mut oct_trans = [[0usize; 8]; 8];
    let mut oct_totals = [0usize; 8];
    for w in deltas.windows(2) {
        let a = timing_octave_bucket(w[0]);
        let b = timing_octave_bucket(w[1]);
        oct_trans[a][b] += 1;
        oct_totals[a] += 1;
    }
    let mut max_oct_cond = 0.20f64;
    for a in 0..8 {
        if oct_totals[a] >= 5 {
            for b in 0..8 {
                let p = (oct_trans[a][b] as f64) / (oct_totals[a] as f64);
                if p > max_oct_cond {
                    max_oct_cond = p;
                }
            }
        }
    }
    let h_markov = (-max_oct_cond.min(0.999).log2()).max(0.0);

    //    (c) Consecutive near-collision penalty (|d[i] - d[i-1]| <= 2ms)
    let near_collisions = deltas
        .windows(2)
        .filter(|w| w[0].abs_diff(w[1]) <= 2_000)
        .count();
    let collision_ratio = (near_collisions as f64) / ((n - 1).max(1) as f64);
    let h_collision_cap = if collision_ratio > 0.25 {
        (-collision_ratio.min(0.99).log2()).max(0.0)
    } else {
        4.0
    };

    // Cap conservative credit at 3.5 bits/keystroke max
    let bits_per_event = h_mcv.min(h_markov * 2.2).min(h_collision_cap).min(3.5);
    let total_bits = (n as f64) * bits_per_event;

    let backspace_events = filtered.iter().filter(|s| s.is_backspace).count();
    let typo_events = filtered.iter().filter(|s| s.was_typo).count();

    let sub_ms = deltas.iter().filter(|&&d| d % 1_000 != 0).count();
    let res_label = if sub_ms * 10 >= n {
        "sub-millisecond monotonic clock"
    } else {
        "1ms monotonic clock"
    };

    Ok(KeystrokeHealthReport {
        accepted_events: filtered.len(),
        backspace_events,
        typo_events,
        timer_quantum_ok: true,
        timer_diagnostic: format!(
            "Healthy {} (median {:.0} ms, sigma {:.0} ms, {:.2} conservative bits/key)",
            res_label,
            (median_us as f64) / 1000.0,
            stddev_us / 1000.0,
            bits_per_event
        ),
        estimated_min_entropy_bits: total_bits,
        required_min_entropy_bits: MIN_TIER2_ENTROPY_BITS,
    })
}

/// Tier 2: Finalize the 200-char Base-94/83 obstacle course + Backspace timing stream into 128-bit entropy.
///
/// Enforces:
/// 1. `final_transcribed == expected_prompt` (`>= 200` chars) - typos MUST have been corrected via `Backspace`.
/// 2. Zero `is_repeat` OS key-repeats accepted.
/// 3. Unclamped host timer (`evaluate_keystroke_health`).
/// 4. Conservative pre-hash NIST SP 800-90B min-entropy `>= 192.0` bits.
pub fn harvest_keystroke_course(
    expected_prompt: &str,
    final_transcribed: &str,
    samples: &[KeystrokeSample],
) -> Result<ConditionedEntropy, SubZeroError> {
    if expected_prompt.len() < OBSTACLE_COURSE_LEN {
        return Err(SubZeroError::Entropy(format!(
            "Obstacle prompt must be at least {} characters (got {}).",
            OBSTACLE_COURSE_LEN,
            expected_prompt.len()
        )));
    }
    if final_transcribed != expected_prompt {
        return Err(SubZeroError::Entropy(format!(
            "Obstacle transcription does not match target prompt ({}/{} chars). Use Backspace to fix red-highlighted typos before finishing.",
            final_transcribed.len(),
            expected_prompt.len()
        )));
    }

    // Independently replay recorded key/Backspace samples so callers cannot submit dummy samples
    let mut replayed = String::with_capacity(expected_prompt.len());
    for s in samples.iter().filter(|s| !s.is_repeat) {
        if s.is_backspace || s.key == "Backspace" {
            let _ = replayed.pop();
        } else if s.key.chars().count() == 1 {
            replayed.push_str(&s.key);
        }
    }
    if replayed != expected_prompt {
        return Err(SubZeroError::Entropy(format!(
            "Keystroke sample transcript replay ({} chars) does not match target prompt ({} chars). Reset and re-type the obstacle course.",
            replayed.len(),
            expected_prompt.len()
        )));
    }

    let health = evaluate_keystroke_health(samples)?;
    if health.accepted_events < OBSTACLE_COURSE_LEN {
        return Err(SubZeroError::Entropy(format!(
            "Recorded only {} genuine keydown events for a {}-character prompt (paste or key-repeat detected).",
            health.accepted_events, OBSTACLE_COURSE_LEN
        )));
    }
    if health.estimated_min_entropy_bits < MIN_TIER2_ENTROPY_BITS {
        return Err(SubZeroError::Entropy(format!(
            "Conservative Non-IID timing min-entropy is {:.1} bits (minimum {:.0} bits required). Type a bit longer or switch to Tier 1 Physical Entropy.",
            health.estimated_min_entropy_bits, MIN_TIER2_ENTROPY_BITS
        )));
    }

    let mut mac = HmacSha512::new_from_slice(b"subzero:entropy:tier2:obstacle:v2")
        .map_err(|_| SubZeroError::Entropy("HMAC initialization failed.".into()))?;
    mac.update((expected_prompt.len() as u32).to_le_bytes().as_slice());
    mac.update(expected_prompt.as_bytes());

    for s in samples.iter().filter(|s| !s.is_repeat) {
        let flags: u8 = (u8::from(s.is_backspace)) | (u8::from(s.was_typo) << 1);
        mac.update(&[flags]);
        mac.update(&(s.key.len() as u16).to_le_bytes());
        mac.update(s.key.as_bytes());
        mac.update(&s.delta_us.to_le_bytes());
    }

    let prk = ZeroizeOnDropContainer(mac.finalize().into_bytes().into());
    let mut sha = Sha256::new();
    sha.update(b"subzero:entropy:tier2:expand:v2:");
    sha.update(&prk.0);
    let final_digest = sha.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&final_digest[..16]);
    reject_known_preset_as_live(&bytes)?;

    Ok(ConditionedEntropy {
        bytes,
        trust_tier: EntropyTrustTier::HostClockDependent,
        method_label: format!(
            "Tier 2 Cooperative Keystroke Course ({} Keys, {} Backspaces, {:.0} Bits 90B)",
            health.accepted_events, health.backspace_events, health.estimated_min_entropy_bits
        ),
        audit_summary: format!(
            "Tier 2 OK: {} ({:.1} >= {:.0} bits)",
            health.timer_diagnostic, health.estimated_min_entropy_bits, MIN_TIER2_ENTROPY_BITS
        ),
        estimated_min_entropy_bits: health.estimated_min_entropy_bits,
        repro_formula_hint:
            "Host-Timed Only: Depends on exact microsecond keydown timings; back up the resulting 12-word BIP-39 mnemonic immediately."
                .to_string(),
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizeOnDropContainer([u8; 64]);

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_shuffled_deck(seed_tag: &[u8]) -> String {
        // Fisher-Yates shuffle driven by SHA-256 counter blocks for deterministic unit testing
        let mut deck: Vec<usize> = (0..52).collect();
        for i in (1..52).rev() {
            let mut h = Sha256::new();
            h.update(seed_tag);
            h.update((i as u32).to_le_bytes());
            let d = h.finalize();
            let j = (u64::from_le_bytes(d[..8].try_into().unwrap()) as usize) % (i + 1);
            deck.swap(i, j);
        }
        deck.into_iter()
            .map(card_code_from_id)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn test_tier1_coins_exact_128_and_extended() {
        // Generate 128 pseudo-random physical coin flips via SHA-512 x 2
        let mut bits = String::new();
        for blk in 0..3u8 {
            let d = Sha256::digest([b'c', blk]);
            for &b in &d[..8] {
                for bit in (0..8).rev() {
                    bits.push(if (b >> bit) & 1 == 1 { '1' } else { '0' });
                }
            }
        }
        let exact_128 = &bits[..128];
        let res_128 = harvest_coins(exact_128).unwrap();
        assert_eq!(res_128.trust_tier, EntropyTrustTier::SecondDeviceReproducible);
        assert!(res_128.method_label.contains("128-Bit Direct"));

        // Extended 144 flips MUST differ from truncated 128 flips (proving zero silent truncation!)
        let ext_144 = &bits[..144];
        let res_144 = harvest_coins(ext_144).unwrap();
        assert_ne!(res_128.bytes, res_144.bytes);
    }

    #[test]
    fn test_tier1_dice_quality_and_rejection() {
        // Bad alternating dice rejected
        let bad = "1212121212121212121212121212121212121212121212121212";
        assert!(harvest_dice(bad).is_err());

        // Realistic 60-roll stream from SHA-256 rejections mod 6
        let mut rolls = String::new();
        let mut ctr = 0u32;
        while rolls.len() < 60 {
            let d = Sha256::digest(ctr.to_le_bytes());
            ctr += 1;
            for &b in d.as_slice() {
                if b < 252 && rolls.len() < 60 {
                    rolls.push(char::from_digit(((b % 6) + 1) as u32, 10).unwrap());
                }
            }
        }
        let ok = harvest_dice(&rolls).unwrap();
        assert_eq!(ok.trust_tier, EntropyTrustTier::SecondDeviceReproducible);
        assert!(ok.estimated_min_entropy_bits > 150.0);
    }

    #[test]
    fn test_tier1_playing_cards_bijection_and_bayer_diaconis() {
        // 1. Valid shuffled 52-card deck passes
        let good_deck = deterministic_shuffled_deck(b"subzero-unit-deck-1");
        let ok = harvest_playing_cards(&good_deck).unwrap();
        assert_eq!(ok.trust_tier, EntropyTrustTier::SecondDeviceReproducible);

        // Also verify '10h' notation maps to identical canonical seed as 'th'
        let with_10 = good_deck.replace("th", "10h").replace("tc", "10c");
        let ok2 = harvest_playing_cards(&with_10).unwrap();
        assert_eq!(ok.bytes, ok2.bytes);

        // 2. Duplicate/missing typo reports BOTH duplicate AND missing card
        let mut cards: Vec<String> = good_deck.split_whitespace().map(String::from).collect();
        let replaced = cards[10].clone();
        let dup = cards[0].clone();
        cards[10] = dup.clone();
        let err = harvest_playing_cards(&cards.join(" ")).unwrap_err().to_string();
        assert!(err.contains(&dup), "err should name duplicate: {err}");
        assert!(err.contains(&replaced), "err should name missing: {err}");

        // 3. Unshuffled factory deck is caught by Bayer-Diaconis rising-sequence check!
        let unshuffled: String = (0..52).map(card_code_from_id).collect::<Vec<_>>().join(" ");
        let err_unshuf = harvest_playing_cards(&unshuffled).unwrap_err().to_string();
        assert!(err_unshuf.contains("insufficiently shuffled"), "got: {err_unshuf}");

        // 4. Deterministic 2-pile deal & 5x/7x perfect faro shuffles MUST be rejected (`[H-05]` regression)!
        let uspcc_2pile = "2s 4s 6s 8s ts qs ad 3d 5d 7d 9d jd kd qc tc 8c 6c 4c 2c kh jh 9h 7h 5h 3h ah as 3s 5s 7s 9s js ks 2d 4d 6d 8d td qd kc jc 9c 7c 5c 3c ac qh th 8h 6h 4h 2h";
        assert!(
            harvest_playing_cards(uspcc_2pile).is_err(),
            "USPCC 2-pile deal must be rejected!"
        );
        let suit_2pile = "qs ts 8s 6s 4s 2s kh jh 9h 7h 5h 3h ah qd td 8d 6d 4d 2d kc jc 9c 7c 5c 3c ac ks js 9s 7s 5s 3s as qh th 8h 6h 4h 2h kd jd 9d 7d 5d 3d ad qc tc 8c 6c 4c 2c";
        assert!(
            harvest_playing_cards(suit_2pile).is_err(),
            "Suit-order 2-pile deal must be rejected!"
        );
        // Simulate 5x and 7x perfect out-faro shuffles from canonical deck
        let mut faro: Vec<usize> = (0..52).collect();
        for round in 1..=7 {
            let half = 26;
            let mut next = Vec::with_capacity(52);
            for i in 0..half {
                next.push(faro[i]);
                next.push(faro[half + i]);
            }
            faro = next;
            if round == 5 || round == 7 {
                let faro_str = faro.iter().copied().map(card_code_from_id).collect::<Vec<_>>().join(" ");
                assert!(
                    harvest_playing_cards(&faro_str).is_err(),
                    "{round}x perfect out-faro must be rejected!"
                );
            }
        }
    }

    #[test]
    fn test_public_preset_entropies_blocked_on_live_paths() {
        for id in 0..(PRESET_COUNT as u8) {
            let p_hex = hex::encode(preset_entropy(id).unwrap());
            assert!(
                harvest_raw_hex(&p_hex).is_err(),
                "Public Preset #{id} hex must be blocked on live TRNG import!"
            );
            let p_bits: String = preset_entropy(id)
                .unwrap()
                .iter()
                .flat_map(|b| (0..8).rev().map(move |bit| if (b >> bit) & 1 == 1 { '1' } else { '0' }))
                .collect();
            assert!(
                harvest_coins(&p_bits).is_err(),
                "Public Preset #{id} 128-bit coin stream must be blocked on live coin import!"
            );
        }
    }

    #[test]
    fn test_tier2_keystroke_obstacle_clamped_clock_and_valid_course() {
        let prompt = generate_obstacle_prompt(1, OBSTACLE_COURSE_LEN);
        assert_eq!(prompt.len(), OBSTACLE_COURSE_LEN);
        // Ensure zero adjacent duplicate characters in prompt
        assert!(prompt.as_bytes().windows(2).all(|w| w[0] != w[1]));

        // 1. Clamped Tor Browser 100ms clock MUST be rejected!
        let mut tor_samples = Vec::new();
        for (i, ch) in prompt.chars().enumerate() {
            let bucket = ((i * 7 + 3) % 4 + 1) as u64; // 100ms, 200ms, 300ms, 400ms
            tor_samples.push(KeystrokeSample {
                key: ch.to_string(),
                delta_us: bucket * 100_000,
                is_backspace: false,
                was_typo: false,
                is_repeat: false,
            });
        }
        let err_tor = harvest_keystroke_course(&prompt, &prompt, &tor_samples)
            .unwrap_err()
            .to_string();
        assert!(err_tor.contains("Clamped or coarse host timer"), "got: {err_tor}");

        // 2. Realistic human cross-row timings + Backspace typo recovery MUST succeed!
        let mut human_samples = Vec::new();
        for (i, ch) in prompt.chars().enumerate() {
            let h = Sha256::digest((i as u32 + 900).to_le_bytes());
            let jitter_us = 75_000 + (u32::from_le_bytes(h[..4].try_into().unwrap()) % 650_000) as u64;
            if i % 29 == 7 {
                // Simulate a typo + Backspace recovery spike
                human_samples.push(KeystrokeSample {
                    key: "x".into(),
                    delta_us: jitter_us,
                    is_backspace: false,
                    was_typo: true,
                    is_repeat: false,
                });
                human_samples.push(KeystrokeSample {
                    key: "Backspace".into(),
                    delta_us: 240_317 + (h[4] as u64) * 913,
                    is_backspace: true,
                    was_typo: false,
                    is_repeat: false,
                });
            }
            human_samples.push(KeystrokeSample {
                key: ch.to_string(),
                delta_us: jitter_us + (h[5] as u64) * 311,
                is_backspace: false,
                was_typo: false,
                is_repeat: false,
            });
        }
        let ok = harvest_keystroke_course(&prompt, &prompt, &human_samples).unwrap();
        assert_eq!(ok.trust_tier, EntropyTrustTier::HostClockDependent);
        assert!(ok.estimated_min_entropy_bits >= MIN_TIER2_ENTROPY_BITS);
    }
}
