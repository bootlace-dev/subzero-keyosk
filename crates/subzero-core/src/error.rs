use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SubZeroError {
    #[error("{0}")]
    Entropy(String),
    #[error("{0}")]
    Mnemonic(String),
    #[error("BIP-32 derivation error: {0}")]
    Bip32(String),
    #[error("Descriptor error: {0}")]
    Descriptor(String),
    #[error("PSBT error: {0}")]
    Psbt(String),
    #[error("Vault encryption/decryption error: {0}")]
    Vault(String),
    #[error("pipe-k1 error: {0}")]
    PipeK1(String),
    #[error("QR codec error: {0}")]
    Qr(String),
}
