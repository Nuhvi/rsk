// Validation rules
//
// 1. Block header timestamp rules
// 2. Proof of Work rules
// 3. Uncle rules

use crate::block_header::RskBlockHeader;

pub mod pow;
pub mod timestamp_rule;
pub mod uncle_rule;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    FutureTimestamp,
    /// Bitcoin PoW hash does not meet RSK difficulty target
    InsufficientWork,
}

impl RskBlockHeader {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_timestamp()?;
        self.validate_proof_of_work()?;

        Ok(())
    }
}
