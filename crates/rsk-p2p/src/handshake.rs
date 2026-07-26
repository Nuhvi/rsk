use aes::cipher::{KeyIvInit, StreamCipher};
use alloy_primitives::B512;
use alloy_rlp::Encodable;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use ethereum_types::H128;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Digest;
use sha3::Keccak256;

use crate::{
    ecies::Ecies,
    error::{Error, Result},
    hash_mac::HashMac,
    messages::{Capability, Disconnect, Hello, Ping, Pong, Status},
    secret::{Aes128Ctr64BE, Secrets},
};

const PROTOCOL_VERSION: usize = 5;
const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];

pub struct Handshake {
    pub ecies: Ecies,
    pub secrets: Option<Secrets>,
}

impl Handshake {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        Handshake {
            ecies: Ecies::new(private_key, remote_public_key),
            secrets: None,
        }
    }

    pub fn auth(&mut self) -> BytesMut {
        let signature = self.signature();

        let full_pub_key = self.ecies.public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = rlp::RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.ecies.nonce.as_bytes());
        stream.append(&PROTOCOL_VERSION);

        let auth_body = Bytes::from(stream.out());

        let mut buf = BytesMut::default();
        let _encrypted_len = self.encrypt(auth_body, &mut buf);

        self.ecies.auth = Some(Bytes::copy_from_slice(&buf[..]));

        buf
    }

    fn signature(&self) -> [u8; 65] {
        let msg = self.ecies.shared_key ^ self.ecies.nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(msg.as_bytes()).unwrap(),
                &self.ecies.private_ephemeral_key,
            )
            .serialize_compact();

        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        signature
    }

    pub fn encrypt(&self, data_in: Bytes, data_out: &mut BytesMut) -> Result<usize> {
        self.ecies.encrypt(data_in, data_out)
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8]> {
        self.ecies.decrypt(data_in)
    }

    pub fn derive_secrets(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = rlp::Rlp::new(ack_body);

        let recipient_ephemeral_pubk_raw: Vec<_> = rlp.val_at(0)?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        let recipient_ephemeral_pubk =
            PublicKey::from_slice(&buf).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        let recipient_nonce_raw: Vec<_> = rlp.val_at(1)?;
        let recipient_nonce = ethereum_types::H256::from_slice(&recipient_nonce_raw);

        let _ack_vsn: usize = rlp.val_at(2)?;

        let ephemeral_key = ethereum_types::H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &recipient_ephemeral_pubk,
                &self.ecies.private_ephemeral_key,
            )[..32],
        );

        let keccak_nonce = create_hash(&[recipient_nonce.as_ref(), self.ecies.nonce.as_ref()]);
        let shared_secret = create_hash(&[ephemeral_key.as_ref(), keccak_nonce.as_ref()]);
        let aes_secret = create_hash(&[ephemeral_key.as_ref(), shared_secret.as_ref()]);
        let mac_secret = create_hash(&[ephemeral_key.as_ref(), aes_secret.as_ref()]);

        let mut egress_mac = HashMac::new(mac_secret);
        egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
        egress_mac.update(self.ecies.auth.as_ref().unwrap());

        let mut ingress_mac = HashMac::new(mac_secret);
        ingress_mac.update((mac_secret ^ self.ecies.nonce).as_bytes());
        ingress_mac.update(self.ecies.auth_response.as_ref().unwrap());

        let iv = H128::default();

        self.secrets = Some(Secrets {
            egress_mac,
            ingress_mac,
            ingress_aes: Aes128Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
            egress_aes: Aes128Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
        });

        Ok(())
    }

    pub fn status_msg(&mut self, status: &Status) -> BytesMut {
        let mut encoded_status = BytesMut::default();
        Status::ID.encode(&mut encoded_status);
        status.encode(&mut encoded_status);
        self.write_frame(&encoded_status)
    }

    pub fn ping_msg(&mut self) -> BytesMut {
        let mut encoded_ping = BytesMut::default();
        Ping::ID.encode(&mut encoded_ping);
        // Ping is an empty list (RLP encoding of empty list is 0xc0)
        encoded_ping.extend_from_slice(&[0xc0]);
        self.write_frame(&encoded_ping)
    }

    pub fn pong_msg(&mut self) -> BytesMut {
        let mut encoded_pong = BytesMut::default();
        Pong::ID.encode(&mut encoded_pong);
        // Pong is an empty list (RLP encoding of empty list is 0xc0)
        encoded_pong.extend_from_slice(&[0xc0]);
        self.write_frame(&encoded_pong)
    }

    pub fn hello_msg(&mut self) -> BytesMut {
        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "RSK-P2P/0.1.0".to_string(),
            capabilities: vec![Capability {
                version: 66,
                name: "eth".to_string(),
            }],
            port: 0,
            id: *B512::from_slice(&self.ecies.public_key.serialize_uncompressed()[1..]),
        };

        let mut encoded_hello = BytesMut::default();
        Hello::ID.encode(&mut encoded_hello);
        hello.encode(&mut encoded_hello);

        self.write_frame(&encoded_hello)
    }

    pub fn disconnect_msg(&mut self, reason: usize) -> BytesMut {
        let disc = Disconnect { reason };

        let mut encoded_disc = BytesMut::default();
        Disconnect::ID.encode(&mut encoded_disc);
        disc.encode(&mut encoded_disc);

        self.write_frame(&encoded_disc)
    }

    pub fn get_block_headers_msg(
        &mut self,
        request_id: u64,
        block_number: u64,
        limit: u64,
    ) -> BytesMut {
        use crate::messages::{BlockHeadersQuery, GetBlockHeaders};

        let query = BlockHeadersQuery {
            block: alloy_rlp::encode(block_number).to_vec(),
            skip: 0,
            limit,
            reverse: false,
        };

        let msg = GetBlockHeaders { request_id, query };

        let mut encoded = BytesMut::default();
        GetBlockHeaders::ID.encode(&mut encoded);
        msg.encode(&mut encoded);

        self.write_frame(&encoded)
    }

    pub fn get_block_bodies_msg(&mut self, hashes: Vec<ethereum_types::H256>) -> BytesMut {
        let mut encoded = BytesMut::default();
        0x05u8.encode(&mut encoded);
        for hash in &hashes {
            encoded.extend_from_slice(hash.as_bytes());
        }

        self.write_frame(&encoded)
    }

    fn write_frame(&mut self, data: &[u8]) -> BytesMut {
        let mut buf = [0; 8];
        let n_bytes = 3;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);

        let mut header_buf = [0_u8; 16];
        header_buf[..3].copy_from_slice(&buf[..3]);
        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        let secrets = self.secrets.as_mut().unwrap();
        secrets.egress_aes.apply_keystream(&mut header_buf);
        secrets.egress_mac.compute_header(&header_buf);

        let mac = secrets.egress_mac.digest();

        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(&mac[..16]);

        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        secrets.egress_aes.apply_keystream(encrypted);
        secrets.egress_mac.compute_frame(encrypted);
        let mac = secrets.egress_mac.digest();

        out.extend_from_slice(&mac[..16]);

        out
    }

    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<(Vec<u8>, usize)> {
        if buf.len() < 32 {
            return Err(Error::InvalidInput("Too short".to_string()));
        }

        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac_bytes) = header_bytes.split_at_mut(16);

        let secrets = self.secrets.as_mut().unwrap();

        secrets.ingress_mac.compute_header(header);
        let expected_mac = secrets.ingress_mac.digest();
        if mac_bytes != &expected_mac[..16] {
            return Err(Error::InvalidMac);
        }

        secrets.ingress_aes.apply_keystream(header);

        let mut frame_size = BigEndian::read_uint(header, 3) + 16;
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let frame_len = frame.len();
        let (frame_data, frame_mac_bytes) = frame.split_at_mut(frame_len - 16);

        secrets.ingress_mac.compute_frame(frame_data);
        let expected_frame_mac = secrets.ingress_mac.digest();

        if frame_mac_bytes != &expected_frame_mac[..16] {
            return Err(Error::InvalidMac);
        }

        secrets.ingress_aes.apply_keystream(frame_data);

        let total_bytes_used = 32 + frame_size as usize;

        Ok((frame_data.to_owned(), total_bytes_used))
    }
}

fn create_hash(inputs: &[&[u8]]) -> ethereum_types::H256 {
    let mut hasher = Keccak256::new();
    for input in inputs {
        hasher.update(input);
    }
    ethereum_types::H256::from_slice(&hasher.finalize())
}
