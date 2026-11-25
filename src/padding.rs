//! PKCS#7 padding (RFC 5652 §6.3): every padded block carries `pad`
//! copies of the byte `pad`, where `1 <= pad <= block`.

pub fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad = (block - data.len() % block) as u8;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(pad).take(pad as usize));
    out
}

/// Returns `None` on any padding malformation (zero length byte, pad
/// larger than block or buffer, or inconsistent pad bytes).
pub fn pkcs7_unpad(data: &[u8], block: usize) -> Option<&[u8]> {
    let pad = *data.last()?;
    if pad == 0 || pad as usize > block || pad as usize > data.len() {
        return None;
    }
    if data[data.len() - pad as usize..].iter().any(|&b| b != pad) {
        return None;
    }
    Some(&data[..data.len() - pad as usize])
}
