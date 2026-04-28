use crate::structs::{EciesEnvelope, EncryptedSecret};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

const KEY_LEN: usize = 32;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Key derivation failed");
    key
}

// ── Argon2-based symmetric crypto (master-key operations) ────────────────────

pub fn encrypt(secret: &str, master_password: &str) -> EncryptedSecret {
    encrypt_bytes(secret.as_bytes(), master_password)
}

pub fn decrypt(secret: &EncryptedSecret, master_password: &str) -> Option<String> {
    let plain = decrypt_bytes(secret, master_password)?;
    String::from_utf8(plain).ok()
}

pub fn encrypt_bytes(data: &[u8], master_password: &str) -> EncryptedSecret {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    let key = derive_key(master_password, &salt_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, data).expect("Encryption failed");

    EncryptedSecret {
        salt: salt_bytes.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    }
}

pub fn decrypt_bytes(secret: &EncryptedSecret, master_password: &str) -> Option<Vec<u8>> {
    let key = derive_key(master_password, &secret.salt);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce: Nonce<_> = secret.nonce.as_slice().try_into().ok()?;
    cipher.decrypt(&nonce, secret.ciphertext.as_ref()).ok()
}

// ── X25519 ECIES (share-blob operations) ─────────────────────────────────────

/// Derives a 32-byte AES key from an X25519 shared secret via HKDF-SHA256.
/// Uses the ephemeral public key as the HKDF salt for domain separation.
fn hkdf_derive(shared_secret: &[u8], eph_pub_bytes: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(eph_pub_bytes), shared_secret);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"twc-share-v1", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// Encrypts `plaintext` for `recipient_pub` using ECIES
/// (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM).
pub fn ecies_encrypt(plaintext: &[u8], recipient_pub: &PublicKey) -> EciesEnvelope {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(recipient_pub);

    let aes_key = hkdf_derive(shared.as_bytes(), eph_pub.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("ECIES encryption failed");

    EciesEnvelope {
        eph_pub: eph_pub.as_bytes().to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    }
}

/// Decrypts an ECIES envelope using `priv_key`.
/// Returns None if the key is wrong or the ciphertext is corrupted.
pub fn ecies_decrypt(envelope: &EciesEnvelope, priv_key: &StaticSecret) -> Option<Vec<u8>> {
    let eph_pub_bytes: [u8; 32] = envelope.eph_pub.as_slice().try_into().ok()?;
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let shared = priv_key.diffie_hellman(&eph_pub);

    let aes_key = hkdf_derive(shared.as_bytes(), &envelope.eph_pub);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).ok()?;
    let nonce: Nonce<_> = envelope.nonce.as_slice().try_into().ok()?;

    cipher.decrypt(&nonce, envelope.ciphertext.as_ref()).ok()
}
