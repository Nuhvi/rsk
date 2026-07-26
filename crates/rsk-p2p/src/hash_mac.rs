use ethereum_types::{H128, H256};
use sha2::Digest;
use sha3::Keccak256;

pub struct HashMac {
    mac: H256,
    secret: H256,
}

impl HashMac {
    pub fn new(secret: H256) -> Self {
        Self {
            mac: H256::zero(),
            secret,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(data);
        self.mac = H256::from_slice(&hasher.finalize());
    }

    pub fn compute_header(&mut self, header: &[u8]) {
        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(header);
        self.mac = H256::from_slice(&hasher.finalize());
    }

    pub fn compute_frame(&mut self, frame_data: &[u8]) {
        let mut pad_frame = frame_data.to_vec();
        if pad_frame.len() % 16 != 0 {
            pad_frame.resize((pad_frame.len() / 16 + 1) * 16, 0);
        }

        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(&pad_frame);
        self.mac = H256::from_slice(&hasher.finalize());
    }

    pub fn digest_header(&self) -> H128 {
        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(self.secret.as_bytes());
        let result = H256::from_slice(&hasher.finalize());
        H128::from_slice(&result[..16])
    }

    pub fn digest_frame(&self) -> H128 {
        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(self.secret.as_bytes());
        let result = H256::from_slice(&hasher.finalize());
        H128::from_slice(&result[..16])
    }

    pub fn digest(&self) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.mac.as_bytes());
        hasher.update(self.secret.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
}
