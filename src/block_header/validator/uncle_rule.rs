use crate::block_header::RskBlockHeader;

impl RskBlockHeader {
    pub fn validate_is_uncle_of(&self, trunk_block: &RskBlockHeader) -> Result<(), &'static str> {
        if self.number != trunk_block.number {
            return Err("Uncle's block number does not match trunk block number");
        }

        if self.parent != trunk_block.parent {
            return Err("Uncle's parent does not match trunk block's parent");
        }

        if self.difficulty != trunk_block.difficulty {
            return Err("Uncle's difficulty does not match trunk block's difficulty");
        }

        Ok(())
    }
}
