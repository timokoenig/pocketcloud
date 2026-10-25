//! Master key, recovery phrase, authenticated encryption of stored secrets, password hashing.
use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

/// 256-bit master key. Generated on the user's machine during setup, stored on the server in
/// /etc/pocketcloud/master.key, recoverable from the 24-word phrase.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut k);
        MasterKey(Zeroizing::new(k))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = b.try_into().map_err(|_| anyhow!("master key must be {KEY_LEN} bytes"))?;
        Ok(MasterKey(Zeroizing::new(arr)))
    }

    /// Key file format: 64 hex characters and a newline.
    pub fn from_hex(s: &str) -> Result<Self> {
        let b = hex::decode(s.trim()).context("master key is not hex")?;
        Self::from_bytes(&b)
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.0))
    }

    pub fn phrase(&self) -> Zeroizing<String> {
        let m = bip39::Mnemonic::from_entropy(&*self.0).expect("32 bytes of entropy");
        Zeroizing::new(m.to_string())
    }

    /// Accepts the words separated by any whitespace; numbers and punctuation (as in the numbered display) are ignored.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let words: Vec<String> = phrase
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_ascii_lowercase())
            .collect();
        if words.len() != 24 {
            return Err(anyhow!("recovery phrase must have 24 words, got {}", words.len()));
        }
        let m = bip39::Mnemonic::parse_normalized(&words.join(" ")).context("invalid recovery phrase")?;
        let (entropy, len) = m.to_entropy_array();
        if len != KEY_LEN {
            return Err(anyhow!("recovery phrase must have 24 words"));
        }
        Self::from_bytes(&entropy[..len])
    }

    /// A password for another tool (restic), derived from the key: SHA-256 over key and purpose, hex.
    pub fn derive(&self, purpose: &str) -> Zeroizing<String> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&*self.0);
        h.update(b"pocketcloud/");
        h.update(purpose.as_bytes());
        Zeroizing::new(hex::encode(h.finalize()))
    }

    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new((&*self.0).into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).expect("encrypt");
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 24 + 16 {
            return Err(anyhow!("sealed value too short"));
        }
        let cipher = XChaCha20Poly1305::new((&*self.0).into());
        let pt = cipher
            .decrypt(XNonce::from_slice(&sealed[..24]), &sealed[24..])
            .map_err(|_| anyhow!("decryption failed: wrong master key or corrupt value"))?;
        Ok(Zeroizing::new(pt))
    }

    pub fn open_string(&self, sealed: &[u8]) -> Result<Zeroizing<String>> {
        let pt = self.open(sealed)?;
        Ok(Zeroizing::new(String::from_utf8(pt.to_vec()).context("secret is not utf-8")?))
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hash password: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

pub fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_roundtrip() {
        let k = MasterKey::generate();
        let p = k.phrase();
        assert_eq!(p.split_whitespace().count(), 24);
        let k2 = MasterKey::from_phrase(&p).unwrap();
        assert_eq!(*k.to_hex(), *k2.to_hex());
        let numbered: String = p.split_whitespace().enumerate().map(|(i, w)| format!("{:>2} {:<10}", i + 1, w)).collect::<Vec<_>>().join("\n");
        assert_eq!(*MasterKey::from_phrase(&numbered).unwrap().to_hex(), *k.to_hex());
    }

    #[test]
    fn seal_open() {
        let k = MasterKey::generate();
        let s = k.seal(b"hello");
        assert_eq!(&*k.open(&s).unwrap(), b"hello");
        assert!(MasterKey::generate().open(&s).is_err());
    }

    #[test]
    fn password() {
        let h = hash_password("pw").unwrap();
        assert!(verify_password("pw", &h));
        assert!(!verify_password("no", &h));
    }
}
