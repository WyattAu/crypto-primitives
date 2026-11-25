//! Base64 (RFC 4648 standard alphabet; the decoder also tolerates the
//! URL-safe `-`/`_` alphabet and strips newlines, matching the inputs
//! the cryptopals challenges feed it).

pub fn base64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| -> Option<u32> {
        T.iter().position(|&t| t == c).map(|p| p as u32)
            .or_else(|| match c { b'=' => None, _ => {
                // url-safe alphabet tolerated
                match c { b'-' => Some(62), b'_' => Some(63), _ => None }
            }})
    };
    let mut out = Vec::new();
    let clean: Vec<u8> = s.bytes().filter(|b| *b != b'\n' && *b != b'\r').collect();
    for c in clean.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0usize;
        for (i, &ch) in c.iter().enumerate() {
            match val(ch) {
                Some(v) => n |= v << (18 - 6 * i),
                None => pad += 1,
            }
        }
        if c.len() < 2 {
            break;
        }
        // output length from data chars actually present: (L - pad) * 6 / 8
        // — the decoder previously ignored `pad` and always emitted 3
        // bytes per full chunk, so decode(encode(x)) did not round-trip
        // for 1- and 2-byte inputs (caught by the promotion test suite)
        let bytes = (c.len() - pad) * 6 / 8;
        if bytes >= 1 {
            out.push((n >> 16) as u8);
        }
        if bytes >= 2 {
            out.push((n >> 8) as u8);
        }
        if bytes >= 3 {
            out.push(n as u8);
        }
    }
    out
}
