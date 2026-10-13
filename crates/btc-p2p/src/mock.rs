//! An in-memory peer stream for offline tests: `input` is pre-encoded frames
//! the fake "peer" sends us, `output` captures everything we send back. Reads
//! come out in small chunks on purpose, to exercise the codec's exact-read
//! behaviour against partial deliveries.

use std::io::{Read, Write};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::RawNetworkMessage;

pub struct MockPeer {
    input: Vec<u8>,
    pos: usize,
    output: Vec<u8>,
}

impl MockPeer {
    /// Script the peer's side of the conversation.
    pub fn scripted(frames: Vec<RawNetworkMessage>) -> Self {
        let mut input = Vec::new();
        for frame in frames {
            frame
                .consensus_encode(&mut input)
                .expect("encoding to vec is infallible");
        }
        Self {
            input,
            pos: 0,
            output: Vec::new(),
        }
    }

    /// Decode the frames we wrote back, in order.
    pub fn sent(&self) -> Vec<RawNetworkMessage> {
        let mut out = Vec::new();
        let mut rest: &[u8] = &self.output;
        while !rest.is_empty() {
            out.push(RawNetworkMessage::consensus_decode(&mut rest).expect("mock frame decodes"));
        }
        out
    }
}

impl Read for MockPeer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.input.len() - self.pos;
        if remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "mock input exhausted",
            ));
        }
        let n = buf.len().min(remaining).min(7);
        buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for MockPeer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
