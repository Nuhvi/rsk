// Validation rules
//
// 1. Block header timestamp rules
// 2. Proof of Work rules
// 3. Uncle rules

pub mod pow;
pub mod timestamp_rule;
pub mod uncle_rule;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    FutureTimestamp,
    /// Bitcoin PoW hash does not meet RSK difficulty target
    InsufficientWork,
}
