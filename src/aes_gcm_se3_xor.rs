#![allow(clippy::upper_case_acronyms, non_snake_case)]

//! Instantiation of SE3 online authenticated encryption scheme using AES128-GCM
//! and AES-XOR as described in the paper [Security of Streaming Encryption in
//! Google's Tink Library][1].
//!
//! Externally, uses a 256-bit key and 176-bit nonce.
//!
//! Internally, derives a 128-bit key and a 96-bit nonce (consisting of a 56-bit
//! nonce prefix, an 8-bit "last block" flag, and a 32-bit counter.)
//!
//! [1]: https://eprint.iacr.org/2020/1019
//!
//! ### Usage
//!
//! ```
//! use no_noncense::aes_gcm_se3_xor::Aes128GcmSE3Xor;
//! use aead::stream::StreamPrimitive;
//!
//! let key = Aes128GcmSE3Xor::generate_key();
//! let nonce = Aes128GcmSE3Xor::generate_nonce();
//!
//! let x = Aes128GcmSE3Xor::new(&key, &nonce);
//! let mut encryptor = x.encryptor();
//!
//! let y = Aes128GcmSE3Xor::new(&key, &nonce);
//! let mut decryptor = y.decryptor();
//!
//! // --> sender
//! let msg1 = vec![1, 2, 3];
//! let ad1 = b"ad123";
//! let mut buf1 = msg1.clone();
//! encryptor.encrypt_next_in_place(ad1, &mut buf1).unwrap();
//!
//! // <-- recipient
//! decryptor.decrypt_next_in_place(ad1, &mut buf1).unwrap();
//! assert_eq!(msg1, buf1);
//!
//! // --> sender
//! let msg2 = vec![4, 5, 6];
//! let ad2 = b"ad456";
//! let mut buf2 = msg2.clone();
//! encryptor.encrypt_last_in_place(ad2, &mut buf2).unwrap();
//!
//! // <-- recipient
//! decryptor.decrypt_last_in_place(ad2, &mut buf2).unwrap();
//! assert_eq!(msg2, buf2);
//! ```

use aead::{
    consts::{U24, U32, U5, U7},
    generic_array::GenericArray,
    rand_core::RngCore,
    stream::StreamPrimitive,
    AeadInPlace, KeyInit, OsRng,
};
use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes_gcm::Aes128Gcm;

/// SE3<AES128-GCM, AES128-XOR> key
pub type Key = GenericArray<u8, U32>;
/// SE3<AES128-GCM, AES128-XOR> nonce
pub type Nonce = GenericArray<u8, U24>;

/// SE3<AES128-GCM, AES128-XOR>
#[derive(Clone)]
pub struct Aes128GcmSE3Xor {
    aead: Aes128Gcm,
    nonce_prefix: GenericArray<u8, U7>,
}

impl StreamPrimitive<Aes128Gcm> for Aes128GcmSE3Xor {
    /// 40 bits = 8-bit "last block" flag and a 32-bit counter.
    type NonceOverhead = U5;
    type Counter = u32;
    const COUNTER_INCR: u32 = 1;
    const COUNTER_MAX: u32 = core::u32::MAX;

    fn encrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn aead::Buffer,
    ) -> aead::Result<()> {
        let nonce = self.derived_nonce(position, last_block);
        self.aead.encrypt_in_place(&nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        position: Self::Counter,
        last_block: bool,
        associated_data: &[u8],
        buffer: &mut dyn aead::Buffer,
    ) -> aead::Result<()> {
        let nonce = self.derived_nonce(position, last_block);
        self.aead.decrypt_in_place(&nonce, associated_data, buffer)
    }
}

impl Aes128GcmSE3Xor {
    /// Randomly generates a new key using the OsRng.
    pub fn generate_key() -> Key {
        let mut key = Key::default();
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Randomly generates a new nonce using the OsRng.
    ///
    /// Since the nonce size is 176 bits, after 2^72 random nonces, the chance
    /// of a collision is ~2^-32. If we assume a more conservative threshold of
    /// 2^-64, then we can generate ~2^56 random nonces. If we assume a
    /// maximally conservative threshold of 2^-128, then we can generate ~2^24
    /// nonces.
    pub fn generate_nonce() -> Nonce {
        let mut nonce = Nonce::default();
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Creates a new SE3<AES128-GCM, AES128-XOR> instance.
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        // Initialize as defined in Figure 12 of https://eprint.iacr.org/2020/1019.
        let R = &nonce[..15]; // 120 bits to randomize key derivation
        let P = &nonce[15..22]; // 56 bits to generate the nonce prefix

        // Do key derivation using the XOR construction as defined in Section 5 of
        // https://eprint.iacr.org/2020/1019.
        let G = |K: &[u8], X: &[u8], domain_separator: u8| {
            let J = &K[..16];
            let L = &K[16..];
            let E_J = Aes128::new(J.into());

            // Computes E_J((X||domain_sep) ^ L) ^ L
            let mut out = [0u8; 16];
            for i in 0..15 {
                out[i] = X[i] ^ L[i]
            }
            out[15] = L[15] ^ domain_separator;
            E_J.encrypt_block(&mut out.into());
            for i in 0..16 {
                out[i] ^= L[i];
            }
            out
        };
        let F = |K: &[u8], X: &[u8], domain_separator: u8| {
            let G0 = G(K, X, domain_separator);
            let G1 = G(K, X, domain_separator + 1);

            let mut out = [0u8; 16];
            for i in 0..16 {
                out[i] = G0[i] ^ G1[i];
            }
            out
        };
        let KD = |K: &[u8], X: &[u8]| (F(K, X, 0), F(K, X, 1));
        let (L, X) = KD(key, R);

        // P_star is P whitened with X.
        let mut P_star = [0u8; 7];
        for i in 0..P_star.len() {
            P_star[i] = P[i] ^ X[i];
        }

        Self {
            aead: Aes128Gcm::new(&L.into()),
            nonce_prefix: P_star.into(),
        }
    }

    /// Computes derived nonce as nonce_prefix || position || last_block_flag
    fn derived_nonce(&self, position: u32, last_block: bool) -> aead::Nonce<Aes128Gcm> {
        let mut out: aead::Nonce<Aes128Gcm> = Default::default(); // 96 bits
        out[0..7].copy_from_slice(&self.nonce_prefix);
        out[7..11].copy_from_slice(&position.to_le_bytes());
        out[11] = last_block as u8;
        out
    }
}

#[cfg(test)]
mod tests {
    #![cfg(feature = "alloc")]
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;
    #[test]
    fn basic_enc_dec() {
        let x = Aes128GcmSE3Xor::new(&Default::default(), &Default::default());
        let mut encryptor = x.clone().encryptor();
        let mut decryptor = x.decryptor();

        let mut msg1 = Vec::new();
        msg1.extend_from_slice(b"123");
        let ad1 = b"ad123";
        let mut buf1 = msg1.clone();
        encryptor.encrypt_next_in_place(ad1, &mut buf1).unwrap();
        decryptor.decrypt_next_in_place(ad1, &mut buf1).unwrap();
        assert_eq!(msg1, buf1);

        let mut msg2 = Vec::new();
        msg2.extend_from_slice(b"456");
        let ad2 = b"ad456";
        let mut buf2 = msg2.clone();
        encryptor.encrypt_last_in_place(ad2, &mut buf2).unwrap();
        decryptor.decrypt_last_in_place(ad2, &mut buf2).unwrap();
        assert_eq!(msg2, buf2);
    }
}
