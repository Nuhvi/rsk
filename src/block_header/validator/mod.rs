// Validation rules
//
// 1. Block header timestamp rules

use crate::block_header::RskBlockHeader;

pub mod pow;
pub mod timestamp_rule;

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
