//! Headless, Zero-OS-RNG UNIX CLI for `subzero` (`crates/subzero-tui/src/cli.rs`).
//!
//! WHY STRICT FD/STDIN SECRET INTAKE & ZERO `HashMap`:
//! 1. Passing mnemonics or passphrases as CLI argv values exposes them to local `ps aux` and
//!    shell history logs. All CLI secret arguments (`--mnemonic-stdin`, `--mnemonic-fd`,
//!    `--passphrase-stdin`, `--passphrase-fd`) read strictly from stdin, pipes/fds (`>= 3`),
//!    or files while `--preset` accepts ONLY public zero-entropy Testnet4 vectors (`0..9`).
//! 2. Executing CLI subcommands before TUI initialization avoids `ratatui`/`HashMap` setup,
//!    preserving `0` `getrandom` syscalls under `strace` across all headless crypto pipelines.

use std::fs;
use std::io::{self, Read};
use std::os::unix::io::FromRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, Zeroizing};

use subzero_core::descriptor::attach_descriptor_checksum;
use subzero_core::entropy::{harvest_coins, harvest_dice, harvest_raw_hex};
use subzero_core::keys::{
    derive_bip85_children, export_sparrow_watch_only_json, import_wallet_material,
    load_rehearsal_preset, wallet_from_conditioned_entropy, WalletProfile,
};
use subzero_core::presets::preset_entropy;
use subzero_core::psbt::{inspect_psbt, parse_psbt_any, sign_psbt};
use subzero_core::qr_codec::AirgapQrAssembler;
use subzero_core::seedfix::solve_twelfth_word;
use subzero_core::vault::{decrypt_vault_json, encrypt_vault_payload, DecryptedVaultPayload};
use subzero_core::{SUBZERO_NETWORK, SUBZERO_VERSION};

/// Convert Unix seconds to UTC `YYYY-MM-DDTHH:MM:SSZ` without pulling external calendar crates.
pub(crate) fn current_utc_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (exact proleptic Gregorian UTC date)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

pub(crate) fn cli_usage() -> String {
    format!(
        "subzero {SUBZERO_VERSION} ({SUBZERO_NETWORK})

USAGE:
  subzero                       Launch interactive bare-metal TTY1 TUI
  subzero --version | -V        Print version and network guard
  subzero --self-test           Run built-in deterministic KAT suite (0 OS RNG calls)
  subzero <subcommand> [flags]  Run headless zero-OS-RNG UNIX CLI mode

SUBCOMMANDS:
  derive               (--preset <0..9> | --coins <bits> | --dice <1-6> | --hex <32hex> |
                        --watch-only <desc> | --mnemonic-stdin | --mnemonic-fd <N>)
                       [--public-only | --sparrow-json]
  inspect-psbt         [--preset <0..9> | --mnemonic-stdin | --mnemonic-fd <N>]
                       [--psbt-file <path>] [--strict]
  sign-psbt            (--preset <0..9> | --mnemonic-stdin | --mnemonic-fd <N>)
                       [--psbt-file <path>] [--json]
  vault-seal           (--preset <0..9> | --mnemonic-stdin | --mnemonic-fd <N>)
                       (--passphrase-fd <N> | --passphrase-stdin) [--utc <iso8601>]
  vault-unseal         (--passphrase-fd <N> | --passphrase-stdin) [--vault-file <path>]
                       [--public-only]
  seedfix              --eleven \"w1 ... w11\" [--hint <partial>]
  descriptor-checksum  <raw_descriptor>

SECURITY NOTE: Secret mnemonics/passphrases are accepted only via stdin or --*-fd <N>=3+.
"
    )
}

fn read_secret_from_stdin() -> Result<Zeroizing<String>, String> {
    let mut raw = Vec::new();
    io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| format!("Failed reading stdin: {e}"))?;
    let s = String::from_utf8(raw.clone()).map_err(|e| {
        raw.zeroize();
        format!("Invalid UTF-8 on stdin: {e}")
    })?;
    raw.zeroize();
    let trimmed = Zeroizing::new(s.trim().to_string());
    let mut orig = s;
    orig.zeroize();
    Ok(trimmed)
}

fn read_secret_from_fd(fd_str: &str) -> Result<Zeroizing<String>, String> {
    let fd: i32 = fd_str
        .parse()
        .map_err(|_| format!("Invalid file descriptor '{fd_str}' (expected integer >= 3)."))?;
    if fd < 3 {
        return Err(format!(
            "Refusing fd {fd}: pass fd >= 3 (use --*-stdin for fd 0)."
        ));
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let mut raw = Vec::new();
    let res = file.read_to_end(&mut raw);
    if let Err(e) = res {
        raw.zeroize();
        return Err(format!("Failed reading fd {fd}: {e}"));
    }
    let s = String::from_utf8(raw.clone()).map_err(|e| {
        raw.zeroize();
        format!("Invalid UTF-8 on fd {fd}: {e}")
    })?;
    raw.zeroize();
    let trimmed = Zeroizing::new(s.trim().to_string());
    let mut orig = s;
    orig.zeroize();
    Ok(trimmed)
}

fn take_flag_val(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("Missing value for {flag}"))
}

fn parse_preset_id(s: &str) -> Result<u8, String> {
    let id: u8 = s
        .parse()
        .map_err(|_| format!("Invalid preset '{s}' (expected 0..9)."))?;
    preset_entropy(id).map_err(|e| e.to_string())?;
    Ok(id)
}

fn load_mnemonic_source(
    preset: Option<u8>,
    mnem_stdin: bool,
    mnem_fd: Option<&str>,
) -> Result<Zeroizing<String>, String> {
    match (preset, mnem_stdin, mnem_fd) {
        (Some(id), false, None) => {
            let p = load_rehearsal_preset(id).map_err(|e| e.to_string())?;
            p.mnemonic
                .clone()
                .map(Zeroizing::new)
                .ok_or_else(|| "Preset missing mnemonic.".into())
        }
        (None, true, None) => read_secret_from_stdin(),
        (None, false, Some(fd)) => read_secret_from_fd(fd),
        _ => Err("Specify exactly one secret source: --preset <0..9>, --mnemonic-stdin, or --mnemonic-fd <N>.".into()),
    }
}

fn read_psbt_bytes(psbt_file: Option<&str>, stdin_taken: bool) -> Result<Vec<u8>, String> {
    let raw = if let Some(path) = psbt_file {
        fs::read(path).map_err(|e| format!("Failed reading PSBT '{path}': {e}"))?
    } else {
        if stdin_taken {
            return Err("Cannot read PSBT from stdin when stdin is used for secrets; pass --psbt-file <path> or use --mnemonic-fd 3.".into());
        }
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("Failed reading PSBT from stdin: {e}"))?;
        buf
    };
    if let Ok(txt) = core::str::from_utf8(&raw) {
        let lines: Vec<&str> = txt.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if lines.len() > 1 && lines.iter().all(|l| l.starts_with("B$")) {
            let mut asm = AirgapQrAssembler::default();
            for line in lines {
                if let subzero_core::qr_codec::ScannedAirgapPayload::CompleteBinary(b) =
                    asm.ingest_qr_string(line).map_err(|e| e.to_string())?
                {
                    return Ok(b);
                }
            }
        }
    }
    Ok(raw)
}

fn sanitize_profile(mut prof: WalletProfile, public_only: bool) -> WalletProfile {
    if public_only {
        prof.mnemonic = None;
    }
    prof
}

fn cmd_derive(args: &[String]) -> Result<(), String> {
    let mut preset = None;
    let mut coins = None;
    let mut dice = None;
    let mut hex_str = None;
    let mut watch_only = None;
    let mut mnem_stdin = false;
    let mut mnem_fd = None;
    let mut public_only = false;
    let mut sparrow_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preset" => preset = Some(parse_preset_id(&take_flag_val(args, &mut i, "--preset")?)?),
            "--coins" => coins = Some(take_flag_val(args, &mut i, "--coins")?),
            "--dice" => dice = Some(take_flag_val(args, &mut i, "--dice")?),
            "--hex" => hex_str = Some(take_flag_val(args, &mut i, "--hex")?),
            "--watch-only" => watch_only = Some(take_flag_val(args, &mut i, "--watch-only")?),
            "--mnemonic-stdin" => mnem_stdin = true,
            "--mnemonic-fd" => mnem_fd = Some(take_flag_val(args, &mut i, "--mnemonic-fd")?),
            "--public-only" => public_only = true,
            "--sparrow-json" => sparrow_json = true,
            other => return Err(format!("Unknown derive flag: {other}")),
        }
        i += 1;
    }

    let prof = if let Some(id) = preset {
        load_rehearsal_preset(id).map_err(|e| e.to_string())?
    } else if let Some(c) = coins {
        let ent = harvest_coins(&c).map_err(|e| e.to_string())?;
        wallet_from_conditioned_entropy(&ent).map_err(|e| e.to_string())?
    } else if let Some(d) = dice {
        let ent = harvest_dice(&d).map_err(|e| e.to_string())?;
        wallet_from_conditioned_entropy(&ent).map_err(|e| e.to_string())?
    } else if let Some(h) = hex_str {
        let ent = harvest_raw_hex(&h).map_err(|e| e.to_string())?;
        wallet_from_conditioned_entropy(&ent).map_err(|e| e.to_string())?
    } else if let Some(w) = watch_only {
        import_wallet_material(&w).map_err(|e| e.to_string())?
    } else if mnem_stdin || mnem_fd.is_some() {
        let m = if mnem_stdin {
            read_secret_from_stdin()?
        } else {
            read_secret_from_fd(mnem_fd.as_deref().unwrap())?
        };
        import_wallet_material(&m).map_err(|e| e.to_string())?
    } else {
        return Err("Missing source flag for derive (e.g. --preset 0 or --mnemonic-stdin).".into());
    };

    if sparrow_json {
        println!(
            "{}",
            export_sparrow_watch_only_json(&prof).map_err(|e| e.to_string())?
        );
    } else {
        let out = sanitize_profile(prof, public_only);
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn cmd_inspect_psbt(args: &[String]) -> Result<(), String> {
    let mut preset = None;
    let mut mnem_stdin = false;
    let mut mnem_fd = None;
    let mut psbt_file = None;
    let mut strict = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preset" => preset = Some(parse_preset_id(&take_flag_val(args, &mut i, "--preset")?)?),
            "--mnemonic-stdin" => mnem_stdin = true,
            "--mnemonic-fd" => mnem_fd = Some(take_flag_val(args, &mut i, "--mnemonic-fd")?),
            "--psbt-file" => psbt_file = Some(take_flag_val(args, &mut i, "--psbt-file")?),
            "--strict" => strict = true,
            other => return Err(format!("Unknown inspect-psbt flag: {other}")),
        }
        i += 1;
    }

    let mnem_opt = if preset.is_some() || mnem_stdin || mnem_fd.is_some() {
        Some(load_mnemonic_source(preset, mnem_stdin, mnem_fd.as_deref())?)
    } else {
        None
    };
    let psbt_bytes = read_psbt_bytes(psbt_file.as_deref(), mnem_stdin)?;
    let psbt = parse_psbt_any(&psbt_bytes).map_err(|e| e.to_string())?;
    let report = inspect_psbt(&psbt, mnem_opt.as_deref().map(|s| s.as_str()), None)
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    if strict && !report.fatal_blocks.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_sign_psbt(args: &[String]) -> Result<(), String> {
    let mut preset = None;
    let mut mnem_stdin = false;
    let mut mnem_fd = None;
    let mut psbt_file = None;
    let mut json_out = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preset" => preset = Some(parse_preset_id(&take_flag_val(args, &mut i, "--preset")?)?),
            "--mnemonic-stdin" => mnem_stdin = true,
            "--mnemonic-fd" => mnem_fd = Some(take_flag_val(args, &mut i, "--mnemonic-fd")?),
            "--psbt-file" => psbt_file = Some(take_flag_val(args, &mut i, "--psbt-file")?),
            "--json" => json_out = true,
            other => return Err(format!("Unknown sign-psbt flag: {other}")),
        }
        i += 1;
    }

    let mnem = load_mnemonic_source(preset, mnem_stdin, mnem_fd.as_deref())?;
    let psbt_bytes = read_psbt_bytes(psbt_file.as_deref(), mnem_stdin)?;
    let mut psbt = parse_psbt_any(&psbt_bytes).map_err(|e| e.to_string())?;
    let signed = sign_psbt(&mut psbt, &mnem, None).map_err(|e| e.to_string())?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())?
        );
    } else {
        println!("{}", signed.signed_psbt_base64);
    }
    Ok(())
}

fn cmd_vault_seal(args: &[String]) -> Result<(), String> {
    let mut preset = None;
    let mut mnem_stdin = false;
    let mut mnem_fd = None;
    let mut pass_stdin = false;
    let mut pass_fd = None;
    let mut utc = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preset" => preset = Some(parse_preset_id(&take_flag_val(args, &mut i, "--preset")?)?),
            "--mnemonic-stdin" => mnem_stdin = true,
            "--mnemonic-fd" => mnem_fd = Some(take_flag_val(args, &mut i, "--mnemonic-fd")?),
            "--passphrase-stdin" => pass_stdin = true,
            "--passphrase-fd" => pass_fd = Some(take_flag_val(args, &mut i, "--passphrase-fd")?),
            "--utc" => utc = Some(take_flag_val(args, &mut i, "--utc")?),
            other => return Err(format!("Unknown vault-seal flag: {other}")),
        }
        i += 1;
    }
    if mnem_stdin && pass_stdin {
        return Err("Cannot read both mnemonic and passphrase from stdin; use --*-fd 3 for at least one.".into());
    }
    let mnem = load_mnemonic_source(preset, mnem_stdin, mnem_fd.as_deref())?;
    let pass = match (pass_stdin, pass_fd.as_deref()) {
        (true, None) => read_secret_from_stdin()?,
        (false, Some(fd)) => read_secret_from_fd(fd)?,
        _ => return Err("Specify exactly one passphrase source: --passphrase-stdin or --passphrase-fd <N>.".into()),
    };

    let prof = import_wallet_material(&mnem).map_err(|e| e.to_string())?;
    let children = derive_bip85_children(&mnem, 4).map_err(|e| e.to_string())?;
    let payload = DecryptedVaultPayload {
        version: SUBZERO_VERSION.into(),
        created_utc: utc.unwrap_or_else(current_utc_iso8601),
        master_root_mnemonic: mnem.as_str().to_string(),
        descriptor: prof.wpkh_descriptor.clone(),
        heir_treasuries: if children.len() > 1 {
            children[1..].to_vec()
        } else {
            Vec::new()
        },
    };
    let enc = encrypt_vault_payload(&payload, &pass).map_err(|e| e.to_string())?;
    println!("{enc}");
    Ok(())
}

fn cmd_vault_unseal(args: &[String]) -> Result<(), String> {
    let mut pass_stdin = false;
    let mut pass_fd = None;
    let mut vault_file = None;
    let mut public_only = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passphrase-stdin" => pass_stdin = true,
            "--passphrase-fd" => pass_fd = Some(take_flag_val(args, &mut i, "--passphrase-fd")?),
            "--vault-file" => vault_file = Some(take_flag_val(args, &mut i, "--vault-file")?),
            "--public-only" => public_only = true,
            other => return Err(format!("Unknown vault-unseal flag: {other}")),
        }
        i += 1;
    }

    let pass = match (pass_stdin, pass_fd.as_deref()) {
        (true, None) => read_secret_from_stdin()?,
        (false, Some(fd)) => read_secret_from_fd(fd)?,
        _ => return Err("Specify exactly one passphrase source: --passphrase-stdin or --passphrase-fd <N>.".into()),
    };
    let vault_json = if let Some(path) = vault_file {
        fs::read_to_string(&path).map_err(|e| format!("Failed reading vault '{path}': {e}"))?
    } else if !pass_stdin {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("Failed reading vault from stdin: {e}"))?;
        s
    } else {
        return Err("Pass --vault-file <path> when reading passphrase from stdin.".into());
    };

    let dec = decrypt_vault_json(&vault_json, &pass).map_err(|e| e.to_string())?;
    if public_only {
        let prof = import_wallet_material(&dec.master_root_mnemonic).map_err(|e| e.to_string())?;
        let out = serde_json::json!({
            "version": dec.version,
            "created_utc": dec.created_utc,
            "fingerprint": prof.fingerprint,
            "descriptor": dec.descriptor,
            "heir_count": dec.heir_treasuries.len(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&dec).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn cmd_seedfix(args: &[String]) -> Result<(), String> {
    let mut eleven = None;
    let mut hint = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--eleven" => eleven = Some(take_flag_val(args, &mut i, "--eleven")?),
            "--hint" => hint = Some(take_flag_val(args, &mut i, "--hint")?),
            other => return Err(format!("Unknown seedfix flag: {other}")),
        }
        i += 1;
    }
    let prefix = eleven.ok_or_else(|| "Missing --eleven \"w1 ... w11\"".to_string())?;
    let cands = solve_twelfth_word(&prefix, hint.as_deref()).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&cands).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub(crate) fn run_cli_subcommand(args: &[String]) -> Option<Result<(), String>> {
    let first = args.first()?.as_str();
    let rest = &args[1..];
    match first {
        "--help" | "-h" | "help" => {
            println!("{}", cli_usage());
            Some(Ok(()))
        }
        "derive" => Some(cmd_derive(rest)),
        "inspect-psbt" => Some(cmd_inspect_psbt(rest)),
        "sign-psbt" => Some(cmd_sign_psbt(rest)),
        "vault-seal" => Some(cmd_vault_seal(rest)),
        "vault-unseal" => Some(cmd_vault_unseal(rest)),
        "seedfix" => Some(cmd_seedfix(rest)),
        "descriptor-checksum" => Some(match rest.first() {
            Some(raw) => attach_descriptor_checksum(raw)
                .map(|full| println!("{full}"))
                .map_err(|e| e.to_string()),
            None => Err("Usage: subzero descriptor-checksum <raw_descriptor>".into()),
        }),
        _ => None,
    }
}
