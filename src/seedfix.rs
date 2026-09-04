use bip39::{Language, Mnemonic};

#[derive(Debug, Clone)]
pub struct SeedFixCandidate {
    pub twelfth_word: String,
    pub full_mnemonic: String,
    pub distance: usize,
}

pub fn solve_twelfth_word(
    eleven_words: &str,
    typo_opt: Option<&str>,
) -> Result<Vec<SeedFixCandidate>, String> {
    let words_11: Vec<&str> = eleven_words.split_whitespace().collect();
    if words_11.len() != 11 {
        return Err(format!("Expected 11 words, got {}", words_11.len()));
    }

    let wordlist = Language::English.word_list();
    let prefix = words_11.join(" ");
    let typo = typo_opt.unwrap_or("");

    let mut valid_candidates = Vec::with_capacity(128);

    // BIP-39 has exactly 128 mathematically valid checksums for any 11-word prefix
    for &cand in wordlist.iter() {
        let trial_phrase = format!("{} {}", prefix, cand);
        if Mnemonic::parse_in_normalized(Language::English, &trial_phrase).is_ok() {
            let dist = if typo.is_empty() {
                0
            } else {
                levenshtein_distance(typo, cand)
            };
            valid_candidates.push(SeedFixCandidate {
                twelfth_word: cand.to_string(),
                full_mnemonic: trial_phrase,
                distance: dist,
            });
        }
    }

    // Rank by closest edit distance, then alphabetically
    if !typo.is_empty() {
        valid_candidates.sort_by(|a, b| {
            a.distance
                .cmp(&b.distance)
                .then_with(|| a.twelfth_word.cmp(&b.twelfth_word))
        });
    }

    Ok(valid_candidates)
}

/// Compute Levenshtein distance between two strings
pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let v1: Vec<char> = s1.chars().collect();
    let v2: Vec<char> = s2.chars().collect();
    let l1 = v1.len();
    let l2 = v2.len();

    if l1 == 0 { return l2; }
    if l2 == 0 { return l1; }

    let mut matrix = vec![vec![0; l2 + 1]; l1 + 1];

    for i in 0..=l1 { matrix[i][0] = i; }
    for j in 0..=l2 { matrix[0][j] = j; }

    for i in 1..=l1 {
        for j in 1..=l2 {
            let cost = if v1[i - 1] == v2[j - 1] { 0 } else { 1 };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1),
                matrix[i - 1][j - 1] + cost,
            );
        }
    }

    matrix[l1][l2]
}
