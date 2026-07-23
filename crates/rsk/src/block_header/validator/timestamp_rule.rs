//! Timestamp rules
//!
//! Reference: <https://github.com/rsksmart/rskj/blob/6a4c9a24/rskj-core/src/main/java/co/rsk/validators/BlockTimeStampValidationRule.java>
//!
//! 1. Check timestamp is not too far in the future.

use crate::block_header::{RskBlockHeader, validator::ValidationError};

pub const DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS: u64 = 5 * 60;

impl RskBlockHeader {
    pub fn validate_timestamp(&self) -> Result<(), ValidationError> {
        if self.timestamp > now() + DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS {
            // 15-second allowed drift
            return Err(ValidationError::FutureTimestamp);
        }

        Ok(())
    }
}

fn now() -> u64 {
    #[cfg(not(target_os = "zkvm"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_secs()
    }
    #[cfg(target_os = "zkvm")]
    {
        // No wall‑clock time available – return a placeholder,
        // making this FutureTimestamp validation a noop.
        0_u64
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_future_timestamp() {
        let header = RskBlockHeader {
            timestamp: now() + (DEFAULT_MAX_TIMESTAMPS_DIFF_IN_SECS * 2),
            ..Default::default()
        };

        assert!(matches!(
            header.validate_timestamp(),
            Err(ValidationError::FutureTimestamp)
        ));
    }
}
