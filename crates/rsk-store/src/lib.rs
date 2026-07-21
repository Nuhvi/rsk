pub mod error;
pub mod store;

pub use error::StoreError;
pub use store::{
    MergeMiningData, Store, decode_rsk_header, header_work,
};

/// Tracks the cumulative work of the last N Bitcoin blocks.
pub struct DifficultyTracker {
    window_size: usize,
    ring_buffer: std::collections::VecDeque<primitive_types::U256>,
    cumulative: primitive_types::U256,
}

impl DifficultyTracker {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            ring_buffer: std::collections::VecDeque::with_capacity(window_size),
            cumulative: primitive_types::U256::zero(),
        }
    }

    pub fn add_block(&mut self, work: primitive_types::U256) {
        if self.ring_buffer.len() >= self.window_size {
            if let Some(oldest) = self.ring_buffer.pop_front() {
                self.cumulative = self.cumulative.saturating_sub(oldest);
            }
        }
        self.ring_buffer.push_back(work);
        self.cumulative = self.cumulative.checked_add(work).unwrap_or(self.cumulative);
    }

    #[must_use]
    pub fn cumulative_work(&self) -> primitive_types::U256 {
        self.cumulative
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ring_buffer.len()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.ring_buffer.len() >= self.window_size
    }

    /// Rebuild from stored headers starting at `tip_height`.
    pub fn rebuild_from_chain(
        &mut self,
        store: &Store,
        tip_height: u64,
    ) -> Result<(), StoreError> {
        self.ring_buffer.clear();
        self.cumulative = primitive_types::U256::zero();

        let start = tip_height.saturating_sub(self.window_size as u64 - 1);
        for height in start..=tip_height {
            if let Some(header) = store.btc_get_header_at_height(height)? {
                let work = header_work(&header);
                self.add_block(work);
            }
        }
        Ok(())
    }
}
