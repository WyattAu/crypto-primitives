//! crypto-primitives — pure-Rust, std-only cryptographic primitives.
//!
//! Extracted from the cryptopals crate where every layer was validated
//! against primary sources: FIPS-197 (AES-128), NIST SP 800-38A (CBC),
//! FIPS 180-4 (SHA-1), plus cross-checks against Python's cryptography
//! library. The AES and SHA-1 layers were promoted verbatim; the codecs
//! and padding were re-verified against the same vectors on promotion.
//!
//! Design notes:
//! - `sha1::Sha1` exposes internal state (`state()`, `from_state()`) and
//!   glue padding — deliberately, so length-extension against naive
//!   key-prefix MACs is constructible by callers (the Set 2 lesson).
//! - No allocation in the block primitives; bulk helpers return `Vec`.

pub mod aes;
pub mod base64;
pub mod hex;
pub mod padding;
pub mod sha1;
pub mod xor;
