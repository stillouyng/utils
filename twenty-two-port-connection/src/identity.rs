use crate::crypto::{decrypt_bytes, encrypt_bytes};
use crate::structs::EncryptedSecret;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::fs;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

const PUBKEY_PREFIX: &str = "twc1:";

fn identity_key_path() -> PathBuf {
    dirs::config_dir()
        .expect("Cannot find config directory")
        .join("twc")
        .join("identity.key")
}

fn identity_pub_path() -> PathBuf {
    dirs::config_dir()
        .expect("Cannot find config directory")
        .join("twc")
        .join("identity.pub")
}

pub fn format_pubkey(pk: &PublicKey) -> String {
    format!("{}{}", PUBKEY_PREFIX, B64.encode(pk.as_bytes()))
}

pub fn parse_pubkey(s: &str) -> Option<PublicKey> {
    let b64 = s.strip_prefix(PUBKEY_PREFIX)?;
    let bytes: Vec<u8> = B64.decode(b64).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(PublicKey::from(arr))
}

/// Returns the stored public key string without requiring the master key.
/// Returns None if no identity has been generated yet.
pub fn get_pubkey_string() -> Option<String> {
    let path = identity_pub_path();
    if path.exists() {
        fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
    } else {
        None
    }
}

/// Generates a new X25519 keypair if one doesn't exist yet, encrypts the private
/// key with `master_key` (Argon2 + AES-256-GCM), and saves both to the twc
/// config directory. Returns the formatted public key string (`twc1:<base64>`).
///
/// If a keypair already exists the private key is NOT re-read — only the stored
/// `identity.pub` is returned so the master key is not required for display.
pub fn get_or_create_pubkey(master_key: &str) -> String {
    let key_path = identity_key_path();
    let pub_path = identity_pub_path();

    if key_path.exists() && pub_path.exists() {
        return get_pubkey_string().expect("identity.pub exists but is unreadable");
    }

    // Generate new keypair from OS entropy
    use rand::RngCore;
    let mut key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);

    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    let pubkey_str = format_pubkey(&public);

    // Encrypt private key bytes and persist
    let encrypted: EncryptedSecret = encrypt_bytes(&key_bytes, master_key);
    let json = serde_json::to_string(&encrypted).expect("Serialization failed");

    if let Some(dir) = key_path.parent() {
        fs::create_dir_all(dir).expect("Cannot create twc config dir");
    }
    fs::write(&key_path, &json).expect("Failed to write identity.key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }

    fs::write(&pub_path, &pubkey_str).expect("Failed to write identity.pub");

    pubkey_str
}

/// Loads and decrypts the stored X25519 private key using `master_key`.
/// Returns None if no identity exists or decryption fails.
pub fn load_private_key(master_key: &str) -> Option<StaticSecret> {
    let key_path = identity_key_path();
    if !key_path.exists() {
        return None;
    }
    let json = fs::read_to_string(&key_path).ok()?;
    let encrypted: EncryptedSecret = serde_json::from_str(&json).ok()?;
    let key_bytes = decrypt_bytes(&encrypted, master_key)?;
    let arr: [u8; 32] = key_bytes.try_into().ok()?;
    Some(StaticSecret::from(arr))
}
