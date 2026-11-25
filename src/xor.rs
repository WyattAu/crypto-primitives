//! XOR combination (the repeating-key and fixed-key cases share one
//! zip; length mismatch truncates to the shorter operand).

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}
