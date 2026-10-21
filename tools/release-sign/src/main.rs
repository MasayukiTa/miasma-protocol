use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use miasma_release_sign as rs;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "release-sign",
    about = "Create, sign with and verify offline Ed25519 release keys (no network)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Hex,
    Base64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a key; write it passphrase-encrypted; print the public key.
    Keygen {
        /// Directory for the encrypted key file (must not be in a git work
        /// tree or a synchronised folder).
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Sign SHA256SUMS.txt (the exact bytes of the file).
    Sign {
        /// The encrypted key file made by `keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Signature file to write (default: <sums file>.sig).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "hex")]
        format: Format,
        /// Replace an existing signature file.
        #[arg(long)]
        force: bool,
        sums: PathBuf,
    },
    /// Verify a signature with one or more public keys (64 hex characters).
    Verify {
        /// Public key; repeat for several keys (any one may match).
        #[arg(long = "pubkey", required = true)]
        pubkeys: Vec<String>,
        sums: PathBuf,
        sig: PathBuf,
    },
    /// Print the public key of a key file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
        /// Ask for the passphrase and confirm the file decrypts to this key.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Keygen { out_dir } => keygen(&out_dir),
        Cmd::Sign {
            key,
            out,
            format,
            force,
            sums,
        } => sign(&key, &sums, out, format, force),
        Cmd::Verify { pubkeys, sums, sig } => verify(&pubkeys, &sums, &sig),
        Cmd::Pubkey { key, check } => pubkey(&key, check),
    }
}

/// Read a passphrase from the terminal without echo. Never from arguments or
/// the environment.
fn ask(prompt: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read the passphrase from the terminal: {e}"))
}

fn print_public(pk: &[u8; 32]) {
    println!("public key (hex): {}", hex_str(pk));
    println!("UPDATE_PUBKEYS entry:");
    println!("{}", rs::rust_array(pk));
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn keygen(out_dir: &Path) -> Result<(), String> {
    rs::safety::check_output_dir(out_dir)?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    // Check again now that it exists (a link could point elsewhere).
    rs::safety::check_output_dir(out_dir)?;

    let p1 = ask("New passphrase (at least 12 characters): ")?;
    if p1.chars().count() < 12 {
        return Err("the passphrase must have at least 12 characters".into());
    }
    let p2 = ask("Repeat the passphrase: ")?;
    if *p1 != *p2 {
        return Err("the two passphrases differ".into());
    }

    let key = rs::generate_key();
    let pk = *key.verifying_key().as_bytes();
    let file =
        rs::encrypt_key(&key, p1.as_bytes(), rs::KdfParams::STRONG).map_err(|e| e.to_string())?;
    let path = out_dir.join(format!("miasma-release-{}.key", &hex_str(&pk)[..8]));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&file)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    drop(f);

    // Read it back and decrypt before announcing anything.
    let back = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let k2 = rs::decrypt_key(&back, p1.as_bytes()).map_err(|e| e.to_string())?;
    if *k2.verifying_key().as_bytes() != pk {
        return Err("the written key file does not decrypt to the same key".into());
    }

    println!("wrote {}", path.display());
    print_public(&pk);
    println!("Keep this file offline. There is no other copy of the secret key.");
    Ok(())
}

fn sign(
    key: &Path,
    sums: &Path,
    out: Option<PathBuf>,
    format: Format,
    force: bool,
) -> Result<(), String> {
    let sums_bytes = std::fs::read(sums).map_err(|e| format!("{}: {e}", sums.display()))?;
    let n = rs::validate_sums(&sums_bytes).map_err(|e| e.to_string())?;
    let file = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let pass = ask("Passphrase: ")?;
    let sk = rs::decrypt_key(&file, pass.as_bytes()).map_err(|e| e.to_string())?;
    drop(pass);

    let sig = rs::sign_sums(&sk, &sums_bytes).map_err(|e| e.to_string())?;
    let out = out.unwrap_or_else(|| {
        let mut s = sums.as_os_str().to_owned();
        s.push(".sig");
        PathBuf::from(s)
    });
    if out.exists() && !force {
        return Err(format!(
            "{} already exists (use --force to replace it)",
            out.display()
        ));
    }
    let fmt = match format {
        Format::Hex => rs::SigFormat::Hex,
        Format::Base64 => rs::SigFormat::Base64,
    };
    std::fs::write(&out, rs::encode_signature(&sig, fmt))
        .map_err(|e| format!("{}: {e}", out.display()))?;

    // Verify what was written, from disk, with the public key only.
    let pk = *sk.verifying_key().as_bytes();
    let written = std::fs::read(&out).map_err(|e| e.to_string())?;
    rs::verify_sums(&sums_bytes, &written, &[pk]).map_err(|e| e.to_string())?;

    println!("signed {} ({n} entries)", sums.display());
    println!("wrote {}", out.display());
    println!("public key (hex): {}", hex_str(&pk));
    println!("Do not edit SHA256SUMS.txt now (a changed line ending breaks the signature).");
    Ok(())
}

fn verify(pubkeys: &[String], sums: &Path, sig: &Path) -> Result<(), String> {
    let keys = pubkeys
        .iter()
        .map(|k| rs::parse_public_key(k).map_err(|e| format!("{k}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let s = std::fs::read(sums).map_err(|e| format!("{}: {e}", sums.display()))?;
    let g = std::fs::read(sig).map_err(|e| format!("{}: {e}", sig.display()))?;
    let i = rs::verify_sums(&s, &g, &keys).map_err(|e| e.to_string())?;
    println!("OK: valid signature by key {} ({})", i + 1, pubkeys[i]);
    Ok(())
}

fn pubkey(key: &Path, check: bool) -> Result<(), String> {
    let file = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let pk = rs::key_file_public(&file).map_err(|e| e.to_string())?;
    if check {
        let pass = ask("Passphrase: ")?;
        let sk = rs::decrypt_key(&file, pass.as_bytes()).map_err(|e| e.to_string())?;
        if *sk.verifying_key().as_bytes() != pk {
            return Err("the key file does not match its public key".into());
        }
        println!("passphrase and key file confirmed");
    }
    print_public(&pk);
    Ok(())
}
