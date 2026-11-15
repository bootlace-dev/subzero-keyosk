//! Canonical BIP-380 Output Script Descriptor Checksum Engine.
//!
//! WHY THIS LIVES IN `subzero-core`:
//! Previously, the TypeScript web bundle had a broken polymod implementation (`descriptor.ts`)
//! that generated invalid 8-character `#checksum` suffixes rejected by Bitcoin Core and Sparrow.
//! Centralizing Bitcoin Core's exact `DescriptorChecksum` (`src/script/descriptor.cpp`) in Rust
//! guarantees identical valid BIP-380 descriptors across both Bare-Metal Linux and WASM HTML.

use crate::error::SubZeroError;

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const POLYMOD_GEN: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

fn polymod(mut c: u64, val: u64) -> u64 {
    let c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    for (i, &gen_val) in POLYMOD_GEN.iter().enumerate() {
        if ((c0 >> i) & 1) != 0 {
            c ^= gen_val;
        }
    }
    c
}

/// Compute the 8-character BIP-380 checksum for a raw descriptor string (without `#...`).
pub fn descriptor_checksum(raw_desc: &str) -> Result<String, SubZeroError> {
    if raw_desc.is_empty() {
        return Err(SubZeroError::Descriptor("Descriptor body is empty.".into()));
    }
    if raw_desc.contains('#') {
        return Err(SubZeroError::Descriptor(
            "Pass descriptor body without '#' suffix to descriptor_checksum.".into(),
        ));
    }

    let mut c = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0u64;

    for &b in raw_desc.as_bytes() {
        let pos = INPUT_CHARSET.iter().position(|&x| x == b).ok_or_else(|| {
            SubZeroError::Descriptor(format!(
                "Invalid character {:?} in BIP-380 descriptor.",
                b as char
            ))
        })? as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut ret = String::with_capacity(8);
    for j in 0..8 {
        let idx = ((c >> (5 * (7 - j))) & 31) as usize;
        ret.push(CHECKSUM_CHARSET[idx] as char);
    }
    Ok(ret)
}

/// Format `<raw_desc>#<8-char-checksum>`.
pub fn attach_descriptor_checksum(raw_desc: &str) -> Result<String, SubZeroError> {
    let csum = descriptor_checksum(raw_desc)?;
    Ok(format!("{raw_desc}#{csum}"))
}

/// Split an optional `#checksum` suffix and verify it if present. Returns the clean descriptor body.
pub fn verify_and_strip_checksum(desc: &str) -> Result<&str, SubZeroError> {
    let trimmed = desc.trim();
    if let Some((body, provided)) = trimmed.rsplit_once('#') {
        if provided.len() != 8 {
            return Err(SubZeroError::Descriptor(format!(
                "Descriptor checksum must be 8 characters (got '{}').",
                provided
            )));
        }
        let expected = descriptor_checksum(body)?;
        if expected != provided {
            return Err(SubZeroError::Descriptor(format!(
                "Descriptor checksum mismatch: expected #{expected}, got #{provided}."
            )));
        }
        Ok(body)
    } else {
        let _ = descriptor_checksum(trimmed)?;
        Ok(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip380_official_vectors() {
        // Official BIP-380 specification test vectors:
        assert_eq!(
            descriptor_checksum("raw(deadbeef)").unwrap(),
            "89f8spxm"
        );
        let wpkh = "wpkh([d34db33f/84'/0'/0']xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrhmxyyoEAmUHQbY/0/*)";
        let with_csum = attach_descriptor_checksum(wpkh).unwrap();
        assert_eq!(verify_and_strip_checksum(&with_csum).unwrap(), wpkh);
        let bad = format!("{wpkh}#deadbeef");
        assert!(verify_and_strip_checksum(&bad).is_err());
    }
}
