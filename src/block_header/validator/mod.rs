// Validation rules
//
// 1. Block header timestamp rules

use crate::block_header::RskBlockHeader;

pub mod timestamp_rule;

#[derive(Debug)]
pub enum ValidationError {
    FutureTimestamp,
}

impl RskBlockHeader {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_timestamp()?;

        Ok(())
    }
}
