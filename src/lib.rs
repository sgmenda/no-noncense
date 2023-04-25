#![doc = include_str!("../README.md")]
#![no_std]
#![deny(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod aes_gcm_se3_hmac;
pub mod aes_gcm_se3_xor;
