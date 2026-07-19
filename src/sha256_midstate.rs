//! Minimal SHA-256 implementation that can resume from BouncyCastle's serialized state.
//!
//! RSK stores "compressed" coinbase transactions that consist of a SHA-256 midstate
//! (40 bytes) plus unhashed tail bytes. The midstate is BouncyCastle's
//! `SHA256Digest.getEncodedState()` trimmed to 40 bytes: `[byteCount(8), H1(4), ..., H8(4)]`.
//!
//! This module reconstructs the SHA-256 internal state from that midstate, processes
//! the remaining tail, and produces the coinbase hash needed for Merkle proof verification.
//!
//! Reference: FIPS PUB 180-4

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 state that can be initialized from a BouncyCastle midstate and then
/// used to process additional data and finalize.
pub struct Sha256State {
    h: [u32; 8],
    /// Partial word buffer (up to 3 bytes carried over between `update` calls).
    buf: [u8; 4],
    buf_len: usize,
    /// Total bytes processed so far (from the midstate's byteCount field).
    byte_count: u64,
    /// Message schedule buffer for the current 64-byte block.
    x: [u32; 16],
    x_off: usize,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// Create a new SHA-256 state initialized to the standard IV.
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            buf: [0u8; 4],
            buf_len: 0,
            byte_count: 0,
            x: [0u32; 16],
            x_off: 0,
        }
    }

    /// Reconstruct from a BouncyCastle 40-byte encoded state.
    ///
    /// Format: `[byteCount:8][H1:4][H2:4][...][H8:4]` — all big-endian.
    #[must_use]
    pub fn from_bouncyastle_midstate(state: &[u8; 40]) -> Self {
        let byte_count = u64::from_be_bytes(
            state[0..8]
                .try_into()
                .expect("midstate slice is always 8 bytes"),
        );
        let mut h = [0u32; 8];
        for i in 0..8 {
            h[i] = u32::from_be_bytes(
                state[8 + i * 4..12 + i * 4]
                    .try_into()
                    .expect("midstate slice is always 4 bytes"),
            );
        }
        Self {
            h,
            buf: [0u8; 4],
            buf_len: 0,
            byte_count,
            x: [0u32; 16],
            x_off: 0,
        }
    }

    /// Feed data into the hash.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        let len = data.len();

        // Fill the partial word buffer first.
        if self.buf_len > 0 {
            while offset < len && self.buf_len < 4 {
                self.buf[self.buf_len] = data[offset];
                self.buf_len += 1;
                offset += 1;
            }
            if self.buf_len == 4 {
                let word = u32::from_be_bytes(self.buf);
                self.x[self.x_off] = word;
                self.x_off += 1;
                if self.x_off == 16 {
                    self.process_block();
                }
                self.buf_len = 0;
            }
        }

        // Process complete 4-byte words.
        let limit = len.saturating_sub(3);
        while offset < limit {
            let word = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            self.x[self.x_off] = word;
            self.x_off += 1;
            if self.x_off == 16 {
                self.process_block();
            }
            offset += 4;
        }

        // Buffer remaining bytes.
        while offset < len {
            self.buf[self.buf_len] = data[offset];
            self.buf_len += 1;
            offset += 1;
        }

        self.byte_count += len as u64;
    }

    /// Finalize and return the 32-byte SHA-256 digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.byte_count * 8;

        // Padding: append 0x80, then zeros until xBufOff (buf_len) is 0.
        self.update_partial(&[0x80]);
        while self.buf_len != 0 {
            self.update_partial(&[0]);
        }

        // If xOff > 14, the length words won't fit in the current block.
        if self.x_off > 14 {
            self.process_block();
        }

        // Append bit length as big-endian 64-bit integer.
        self.x[14] = (bit_length >> 32) as u32;
        self.x[15] = bit_length as u32;
        self.process_block();

        // Produce the digest.
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }

    /// Internal: feed data one byte at a time, processing full words.
    /// Used only during finalization to handle the padding.
    fn update_partial(&mut self, data: &[u8]) {
        for &byte in data {
            self.buf[self.buf_len] = byte;
            self.buf_len += 1;
            if self.buf_len == 4 {
                let word = u32::from_be_bytes(self.buf);
                self.x[self.x_off] = word;
                self.x_off += 1;
                if self.x_off == 16 {
                    self.process_block();
                }
                self.buf_len = 0;
            }
        }
        self.byte_count += data.len() as u64;
    }

    /// Process one 64-byte block through the SHA-256 compression function.
    fn process_block(&mut self) {
        // Extend 16 words into 64 words in a local array.
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(&self.x);

        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);

        self.x_off = 0;
        self.x = [0u32; 16];
    }
}

/// Compute `SHA-256d(data)` — the double SHA-256 hash commonly used in Bitcoin.
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// Single SHA-256 hash.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = Sha256State::new();
    state.update(data);
    state.finalize()
}

/// Compute the Bitcoin transaction hash (txid) from a compressed coinbase.
///
/// The compressed coinbase is `[byteCount:8][H1-H8:32][tail...]` where the
/// midstate represents SHA-256 state after processing `byteCount` bytes, and
/// `tail` is the remaining unhashed data.
///
/// Returns the double-SHA-256 hash in **natural byte order** (SHA-256 output
/// order, MSB first — same as the merkle root in the Bitcoin header).
pub fn coinbase_hash_from_compressed(compressed: &[u8]) -> Result<[u8; 32], &'static str> {
    if compressed.len() < 40 {
        return Err("compressed coinbase too short (< 40 bytes)");
    }

    let mut midstate = [0u8; 40];
    midstate.copy_from_slice(&compressed[..40]);
    let tail = &compressed[40..];

    let mut state = Sha256State::from_bouncyastle_midstate(&midstate);
    state.update(tail);
    let first_hash = state.finalize();

    // Double hash — return in natural SHA-256 output order (no reversal).
    // This matches Bitcoin Core: SHA256_Final writes to m_data directly,
    // and Hash(left, right) concatenates raw m_data without reversal.
    Ok(sha256(&first_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_sha256_state_consistency() {
        // The compressed midstate format only works at 64-byte block boundaries
        // (xBufOff=0, xOff=0, X[]=zeros).
        // Hash 64 bytes of data in one shot vs. split at 64-byte boundary.
        let mut data = vec![0u8; 128];
        for i in 0..128 {
            data[i] = (i * 37 + 7) as u8;
        }
        let full_hash = sha256(&data);

        // Hash first 64 bytes, extract midstate.
        let mut state = Sha256State::new();
        state.update(&data[..64]);

        // Build the 40-byte midstate (byteCount + H1-H8).
        let mut encoded = [0u8; 40];
        encoded[0..8].copy_from_slice(&state.byte_count.to_be_bytes());
        for i in 0..8 {
            encoded[8 + i * 4..12 + i * 4].copy_from_slice(&state.h[i].to_be_bytes());
        }

        // Reconstruct and hash the remaining 64 bytes.
        let mut state2 = Sha256State::from_bouncyastle_midstate(&encoded);
        state2.update(&data[64..]);
        let reconstructed_hash = state2.finalize();

        assert_eq!(full_hash, reconstructed_hash);
    }

    #[test]
    fn test_sha256_midstate_roundtrip() {
        // Hash data, extract midstate at 64-byte block boundary, verify consistency.
        let mut data = vec![0u8; 192];
        for i in 0..192 {
            data[i] = (i * 13 + 42) as u8;
        }
        let full_hash = sha256(&data);

        // Midstate at offset 64 (after 1 block).
        let mut s = Sha256State::new();
        s.update(&data[..64]);
        let mut encoded = [0u8; 40];
        encoded[0..8].copy_from_slice(&s.byte_count.to_be_bytes());
        for i in 0..8 {
            encoded[8 + i * 4..12 + i * 4].copy_from_slice(&s.h[i].to_be_bytes());
        }

        let mut s2 = Sha256State::from_bouncyastle_midstate(&encoded);
        s2.update(&data[64..]);
        assert_eq!(full_hash, s2.finalize());

        // Midstate at offset 128 (after 2 blocks).
        let mut s = Sha256State::new();
        s.update(&data[..128]);
        let mut encoded = [0u8; 40];
        encoded[0..8].copy_from_slice(&s.byte_count.to_be_bytes());
        for i in 0..8 {
            encoded[8 + i * 4..12 + i * 4].copy_from_slice(&s.h[i].to_be_bytes());
        }

        let mut s2 = Sha256State::from_bouncyastle_midstate(&encoded);
        s2.update(&data[128..]);
        assert_eq!(full_hash, s2.finalize());
    }

    #[test]
    fn test_sha256d() {
        // SHA-256d("hello") = SHA-256(SHA-256("hello"))
        let first = sha256(b"hello");
        let expected = sha256(&first);
        assert_eq!(sha256d(b"hello"), expected);
    }

    #[test]
    fn test_sha256_midstate_zero_bytes() {
        // Midstate after processing zero bytes should match fresh state.
        let mut encoded = [0u8; 40];
        encoded[0..8].copy_from_slice(&0u64.to_be_bytes()); // byteCount = 0
        for i in 0..8 {
            encoded[8 + i * 4..12 + i * 4].copy_from_slice(&H_INIT[i].to_be_bytes());
        }

        let mut state = Sha256State::from_bouncyastle_midstate(&encoded);
        state.update(b"test");
        let hash1 = state.finalize();

        let hash2 = sha256(b"test");
        assert_eq!(hash1, hash2);
    }
}
