//! Framed Bitcoin P2P messages over a byte stream.
//!
//! `bitcoin`'s [`RawNetworkMessage`] owns the entire wire envelope — magic,
//! command, payload length and the double-SHA256 checksum — so the codec is
//! just exact reads and writes around it: reading consumes exactly one frame,
//! writing emits exactly one. Anything that would read past a frame is the
//! caller's error, which is why [`read_message`] never does a plain
//! `read_to_end`.

use std::io::{Read, Write};

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::RawNetworkMessage;

use crate::error::Error;

/// The largest message we will read. Bitcoin caps message payloads at 4 MiB;
/// this allows a bit more and rejects anything larger before allocating for it.
const MAX_MESSAGE_SIZE: u64 = 5_000_000;

/// Read one framed message. Consumes exactly the frame: no bytes beyond it.
pub fn read_message<R: Read>(reader: &mut R) -> Result<RawNetworkMessage, Error> {
    let mut framed = reader.take(MAX_MESSAGE_SIZE);
    Ok(RawNetworkMessage::consensus_decode(&mut framed)?)
}

/// Read one framed message and reject it if it is not for `magic`.
pub fn read_message_for<R: Read>(reader: &mut R, magic: Magic) -> Result<RawNetworkMessage, Error> {
    let msg = read_message(reader)?;
    if msg.magic() != &magic {
        return Err(Error::Protocol(format!(
            "unexpected network magic {} (want {})",
            msg.magic(),
            magic
        )));
    }
    Ok(msg)
}

/// Write one framed message.
pub fn write_message<W: Write>(writer: &mut W, msg: &RawNetworkMessage) -> Result<(), Error> {
    let mut frame = Vec::new();
    // Encoding into a `Vec` cannot fail (writes to memory are infallible);
    // the error is mapped anyway so the signature stays honest.
    msg.consensus_encode(&mut frame)
        .map_err(|e| Error::Protocol(format!("encode message: {e}")))?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::block::BlockHash;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const MAGIC: Magic = Magic::BITCOIN;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn frames_round_trip_exactly() -> Result<(), Error> {
        let genesis = genesis_block(Network::Bitcoin);
        let peer = addr(8333);
        let payloads = vec![
            NetworkMessage::Verack,
            NetworkMessage::Ping(42),
            NetworkMessage::WtxidRelay,
            NetworkMessage::Version(VersionMessage::new(
                ServiceFlags::NETWORK,
                1_600_000_000,
                Address::new(&peer, ServiceFlags::NONE),
                Address::new(&peer, ServiceFlags::NONE),
                7,
                "/mock:1/".to_string(),
                0,
            )),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(
                vec![genesis.header.block_hash()],
                BlockHash::all_zeros(),
            )),
        ];
        for payload in payloads {
            let original = RawNetworkMessage::new(MAGIC, payload);
            let mut bytes = Vec::new();
            original
                .consensus_encode(&mut bytes)
                .expect("vec is infallible");
            let decoded = read_message(&mut bytes.as_slice())?;
            assert_eq!(decoded, original);
        }
        Ok(())
    }

    #[test]
    fn reading_stops_at_the_frame_boundary() -> Result<(), Error> {
        // Two frames in a row; reading the first must leave the second whole.
        let first = RawNetworkMessage::new(MAGIC, NetworkMessage::Ping(1));
        let second = RawNetworkMessage::new(MAGIC, NetworkMessage::Pong(2));
        let mut bytes = Vec::new();
        first
            .consensus_encode(&mut bytes)
            .expect("vec is infallible");
        second
            .consensus_encode(&mut bytes)
            .expect("vec is infallible");
        let mut rest = bytes.as_slice();
        let got_first = read_message(&mut rest)?;
        assert_eq!(got_first, first);
        let got_second = read_message(&mut rest)?;
        assert_eq!(got_second, second);
        Ok(())
    }

    #[test]
    fn wrong_magic_is_rejected() -> Result<(), Error> {
        let other = RawNetworkMessage::new(Magic::REGTEST, NetworkMessage::Verack);
        let mut bytes = Vec::new();
        other
            .consensus_encode(&mut bytes)
            .expect("vec is infallible");
        let err = read_message_for(&mut bytes.as_slice(), MAGIC).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        Ok(())
    }
}
