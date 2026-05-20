//! Timestamp rules
//!
//! Reference: <https://github.com/rsksmart/rskj/blob/6a4c9a24/rskj-core/src/main/java/co/rsk/validators/BlockTimeStampValidationRule.java>
//!
//! 1. Check timestamp is not too far in the future.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{BlockHeader, constants::DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS};

impl BlockHeader {
    pub fn validate_timestamp(&self) -> Result<(), ValidationError> {
        if self.timestamp > now() + DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS {
            // 15-second allowed drift
            return Err(ValidationError::FutureTimestamp);
        }

        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_secs()
}

#[derive(Debug)]
pub enum ValidationError {
    FutureTimestamp,
}

#[cfg(test)]
mod tests {

    use num_bigint::BigUint;

    use super::*;
    use crate::BlockHeader;

    #[test]
    fn test_future_timestamp() {
        let header = BlockHeader {
            hash: "".to_string(),
            parent_hash: "".to_string(),
            difficulty: BigUint::from(0_u32),
            number: 0,
            timestamp: now() + (DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS * 2),
        };

        assert!(matches!(
            header.validate_timestamp(),
            Err(ValidationError::FutureTimestamp)
        ));
    }
}
