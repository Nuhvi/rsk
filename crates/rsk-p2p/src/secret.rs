use ethereum_types::H128;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

pub struct Secrets {
    pub ingress_aes: Aes128Ctr64BE,
    pub egress_aes: Aes128Ctr64BE,
    pub ingress_mac: super::hash_mac::HashMac,
    pub egress_mac: super::hash_mac::HashMac,
}

pub type Aes128Iv = H128;
pub type Aes128Key = H128;
