//! Configuration options for the System Context Engine and GC subsystem.

/// Configuration parameters governing retention, GC triggers, and capacity limits.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Time-To-Live in milliseconds for terminated entities (default: 10 minutes = 600,000 ms).
    pub retention_ttl_ms: i64,
    /// Maximum capacity of total retained process instances before forced LRU/capacity GC (default: 50,000).
    pub max_process_capacity: usize,
    /// Maximum capacity of interaction records in the ring buffer (default: 100,000).
    pub max_interaction_capacity: usize,
    /// Interval in milliseconds between background GC sweeps (default: 5,000 ms).
    pub gc_interval_ms: u64,
    /// Whether to preserve parent ancestry chains by converting expired parents into lightweight tombstones.
    pub enable_tombstones: bool,
}

impl Default for ContextConfig {
    /// Returns default production configuration values.
    ///
    /// # Returns
    ///
    /// A [`ContextConfig`] with 10-minute TTL, 50k process limit, and 5-second GC interval.
    fn default() -> Self {
        Self {
            retention_ttl_ms: 10 * 60 * 1000, // 10 minutes
            max_process_capacity: 50_000,
            max_interaction_capacity: 100_000,
            gc_interval_ms: 5_000,
            enable_tombstones: true,
        }
    }
}

impl ContextConfig {
    /// Creates a fast configuration with short TTL and aggressive intervals for testing.
    ///
    /// # Returns
    ///
    /// A [`ContextConfig`] configured with 100ms TTL and 20ms GC frequency.
    pub fn for_test() -> Self {
        Self {
            retention_ttl_ms: 100, // 100ms
            max_process_capacity: 10,
            max_interaction_capacity: 50,
            gc_interval_ms: 20,
            enable_tombstones: true,
        }
    }
}
