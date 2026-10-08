use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};
use std::{env, fs, process};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let public_key_path = args.next().ok_or("expected: PUBLIC_KEY_FILE SIGNATURE_FILE INSTALLER_EXE")?;
    let signature_path = args.next().ok_or("expected: PUBLIC_KEY_FILE SIGNATURE_FILE INSTALLER_EXE")?;
    let installer_path = args.next().ok_or("expected: PUBLIC_KEY_FILE SIGNATURE_FILE INSTALLER_EXE")?;
    if args.next().is_some() {
        return Err("expected exactly three arguments".into());
    }

    // Tauri stores Minisign's text format as base64 in both .pub and .sig.
    let public_key_b64 = fs::read_to_string(&public_key_path)?;
    let signature_b64 = fs::read_to_string(&signature_path)?;
    let public_key_text = String::from_utf8(STANDARD.decode(public_key_b64.trim())?)?;
    let signature_text = String::from_utf8(STANDARD.decode(signature_b64.trim())?)?;
    let public_key = PublicKey::decode(&public_key_text)?;
    let signature = Signature::decode(&signature_text)?;
    let installer = fs::read(&installer_path)?;
    public_key.verify(&installer, &signature, false)?;
    println!("OK: assinatura do atualizador corresponde ao instalador e à chave pública.");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Falha na verificação: {error}");
        process::exit(1);
    }
}
