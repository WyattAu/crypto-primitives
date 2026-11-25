# crypto-primitives

Pure-Rust, std-only cryptographic primitives extracted from the
[cryptopals](https://github.com/WyattAu/cryptopals) crate, where every
layer was validated against primary sources (FIPS-197, NIST SP
800-38A, FIPS 180-4) and cross-checked against Python's `cryptography`
library.

## Contents

| Module | What | Validation |
|---|---|---|
| `aes` | AES-128 ECB (block + bulk) and CBC decrypt | FIPS-197 App. C.1 vector, SP 800-38A F.2.5 |
| `sha1` | SHA-1 with **exposed internal state** + glue padding | FIPS 180-4 examples |
| `padding` | PKCS#7 pad/unpad with malformation detection | RFC 5652 §6.3 |
| `hex` | hex encode/decode | roundtrip property |
| `base64` | RFC 4648 encode/decode (URL-safe tolerated on input) | RFC 4648 vectors + roundtrip |
| `xor` | XOR combination | self-inverse property |

## Design note: why SHA-1 exposes its state

`Sha1::state()` / `Sha1::from_state()` / `Sha1::glue_padding()` exist
deliberately: they make length-extension against naive `SHA1(key ||
msg)` MACs *constructible by callers*. That exposure is the lesson of
cryptopals Set 2 — the API demonstrates the vulnerability it exists to
teach. Do not use this crate's MAC-less construction for real
authentication (use HMAC).

## Provenance

Promoted 2026-11-25 from `cryptopals` (AES + SHA-1 verbatim; codecs
re-verified). The promotion test suite caught one latent bug in the
carried-over base64 decoder (padding count ignored — `decode(encode(x))`
did not round-trip for 1–2 byte inputs), fixed here first.

MIT OR Apache-2.0.
