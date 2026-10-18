//! In-memory suppression cache and rate limiter for rapid verdict lookup.
//!
//! Evaluated verdicts (such as benign Task Manager diagnostic polling) are cached
//! to eliminate repeated Rhai script execution on high-frequency operations (< 5 ns lookup).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheEntry {
    /// Suppression lasts for the entire lifetime of the process instance.
    ProcessLifetime,
    /// Suppression expires at the specified deadline.
    Timed(Instant),
}

/// Composite cache key pairing the calling process ID with requested access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    pid: u32,
    desired_access: u32,
}

/// Thread-safe in-memory cache tracking active false-positive suppressions.
#[derive(Debug)]
pub struct SuppressionCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
}

impl SuppressionCache {
    /// Constructs a new, empty `SuppressionCache`.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if an operation is currently suppressed in the cache.
    ///
    /// # Arguments
    ///
    /// * `pid` - Caller process identifier.
    /// * `desired_access` - Requested access rights bitmask.
    ///
    /// # Returns
    ///
    /// `true` if an unexpired suppression entry exists; otherwise `false`.
    pub fn is_suppressed(&self, pid: u32, desired_access: u32) -> bool {
        let key = CacheKey { pid, desired_access };
        let read_guard = self.entries.read().unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(entry) = read_guard.get(&key) {
            match entry {
                CacheEntry::ProcessLifetime => true,
                CacheEntry::Timed(deadline) => Instant::now() < *deadline,
            }
        } else {
            false
        }
    }

    /// Inserts a suppression verdict into the cache.
    ///
    /// # Arguments
    ///
    /// * `pid` - Caller process identifier.
    /// * `desired_access` - Requested access rights bitmask.
    /// * `cooldown_seconds` - Duration to cache (0 = process lifetime).
    pub fn insert(&self, pid: u32, desired_access: u32, cooldown_seconds: u32) {
        let key = CacheKey { pid, desired_access };
        let entry = if cooldown_seconds == 0 {
            CacheEntry::ProcessLifetime
        } else {
            CacheEntry::Timed(Instant::now() + Duration::from_secs(cooldown_seconds as u64))
        };

        let mut write_guard = self.entries.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        write_guard.insert(key, entry);
    }

    /// Prunes all suppression entries for a terminated process ID.
    ///
    /// Prevents stale cache entries from matching recycled PIDs assigned to new processes.
    ///
    /// # Arguments
    ///
    /// * `pid` - Terminated process identifier.
    pub fn prune_process(&self, pid: u32) {
        let mut write_guard = self.entries.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        write_guard.retain(|key, _| key.pid != pid);
    }

    /// Clears all entries in the suppression cache.
    pub fn clear(&self) {
        let mut write_guard = self.entries.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        write_guard.clear();
    }
}

impl Default for SuppressionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use super::*;

    #[test]
    fn test_process_lifetime_suppression() {
        let cache = SuppressionCache::new();
        assert!(!cache.is_suppressed(8800, 0x1410));

        // Insert with cooldown_seconds = 0 (process lifetime)
        cache.insert(8800, 0x1410, 0);
        assert!(cache.is_suppressed(8800, 0x1410));

        // Different access mask on same PID should not be suppressed
        assert!(!cache.is_suppressed(8800, 0x1FFFFF));

        // Different PID on same access mask should not be suppressed
        assert!(!cache.is_suppressed(9999, 0x1410));

        // Pruning process removes suppression
        cache.prune_process(8800);
        assert!(!cache.is_suppressed(8800, 0x1410));
    }

    #[test]
    fn test_timed_cooldown_expiration() {
        let cache = SuppressionCache::new();

        // Insert with 1-second timed cooldown
        cache.insert(1234, 0x0010, 1);
        assert!(cache.is_suppressed(1234, 0x0010));

        // Wait for cooldown to expire
        sleep(Duration::from_millis(1100));
        assert!(!cache.is_suppressed(1234, 0x0010));
    }
}
