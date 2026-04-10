use crate::structs::EncryptedSecret;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use rand::RngCore;
use rand::rngs::OsRng;

const KEY_LEN: usize = 32;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Key derivation failed");
    key
}

pub fn encrypt(secret: &str, master_password: &str) -> EncryptedSecret {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    let key = derive_key(master_password, &salt_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .expect("Encryption failed");

    EncryptedSecret {
        salt: salt_bytes.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    }
}

pub fn decrypt(secret: &EncryptedSecret, master_password: &str) -> Option<String> {
    let key = derive_key(master_password, &secret.salt);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let nonce: Nonce<_> = secret.nonce.as_slice().try_into().ok()?;
    let decrypted = cipher.decrypt(&nonce, secret.ciphertext.as_ref()).ok()?;
    String::from_utf8(decrypted).ok()
}
