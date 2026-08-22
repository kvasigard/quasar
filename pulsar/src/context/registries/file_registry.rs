//! Concurrent normalized filesystem file registry.

use std::sync::Arc;
use dashmap::DashMap;

use crate::context::identity::FileKey;
use crate::context::models::file::FileContext;

/// Normalizes Windows file paths (strips NT prefixes like `\??\`, `\\?\`, and normalizes `\Device\HarddiskVolumeX\`).
///
/// # Arguments
///
/// * `path` - The raw file path string from telemetry.
///
/// # Returns
///
/// A normalized lowercase Windows path string with standard backslashes.
pub fn normalize_file_path(path: &str) -> String {
    let cleaned = path
        .strip_prefix(r"\??\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(path);

    cleaned.replace('/', "\\").to_lowercase()
}

/// Concurrent registry mapping normalized file paths and active kernel FileObjects to `FileContext` entities.
pub struct FileRegistry {
    /// Maps normalized path string to synthetic FileKey.
    path_to_key: DashMap<String, FileKey>,
    /// Global file arena mapping `FileKey` to `Arc<FileContext>`.
    files: DashMap<FileKey, Arc<FileContext>>,
    /// Active kernel FileObject pointer to FileKey mapping.
    file_objects: DashMap<u64, FileKey>,
}

impl FileRegistry {
    /// Creates a new empty `FileRegistry`.
    ///
    /// # Returns
    ///
    /// An empty [`FileRegistry`].
    pub fn new() -> Self {
        Self {
            path_to_key: DashMap::new(),
            files: DashMap::new(),
            file_objects: DashMap::new(),
        }
    }

    /// Gets an existing file context by path, or creates a new one if not yet tracked.
    ///
    /// # Arguments
    ///
    /// * `raw_path` - The raw file path to resolve.
    /// * `timestamp` - Current observation timestamp.
    ///
    /// # Returns
    ///
    /// A tuple containing the shared [`Arc<FileContext>`] reference and a `bool` indicating
    /// whether this file was newly created (`true`) or already existed (`false`).
    pub fn get_or_create(&self, raw_path: &str, timestamp: i64) -> (Arc<FileContext>, bool) {
        let normalized = normalize_file_path(raw_path);

        if let Some(key_ref) = self.path_to_key.get(&normalized)
            && let Some(file_ref) = self.files.get(key_ref.value())
        {
            file_ref.touch(timestamp);
            return (Arc::clone(file_ref.value()), false);
        }

        let key = FileKey::new();
        let file_ctx = Arc::new(FileContext::new(key, normalized.clone(), timestamp));

        self.files.insert(key, Arc::clone(&file_ctx));
        self.path_to_key.insert(normalized, key);

        (file_ctx, true)
    }

    /// Associates an active kernel `FileObject` pointer with a synthetic `FileKey`.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Numerical value of the kernel `FileObject` pointer.
    /// * `file_key` - Synthetic file key to associate.
    pub fn map_file_object(&self, file_object: u64, file_key: FileKey) {
        if file_object != 0 {
            self.file_objects.insert(file_object, file_key);
        }
    }

    /// Resolves the synthetic `FileKey` associated with an active kernel `FileObject`.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Kernel `FileObject` pointer.
    ///
    /// # Returns
    ///
    /// `Some(FileKey)` if mapped, otherwise `None`.
    #[inline]
    pub fn get_key_by_file_object(&self, file_object: u64) -> Option<FileKey> {
        self.file_objects.get(&file_object).map(|entry| *entry.value())
    }

    /// Resolves the [`FileContext`] associated with an active kernel `FileObject`.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Kernel `FileObject` pointer.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if mapped and tracked, otherwise `None`.
    #[inline]
    pub fn get_by_file_object(&self, file_object: u64) -> Option<Arc<FileContext>> {
        let key = self.get_key_by_file_object(file_object)?;
        self.get_by_key(key)
    }

    /// Unmaps a kernel `FileObject` pointer upon file close or cleanup.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Kernel `FileObject` pointer to unmap.
    ///
    /// # Returns
    ///
    /// The previously mapped `Some(FileKey)` if found.
    pub fn unmap_file_object(&self, file_object: u64) -> Option<FileKey> {
        self.file_objects.remove(&file_object).map(|(_, k)| k)
    }

    /// Returns the number of active mapped kernel FileObjects.
    #[inline]
    pub fn active_file_object_count(&self) -> usize {
        self.file_objects.len()
    }

    /// Looks up a file context by its synthetic FileKey.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic [`FileKey`].
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    #[inline]
    pub fn get_by_key(&self, key: FileKey) -> Option<Arc<FileContext>> {
        self.files.get(&key).map(|entry| Arc::clone(entry.value()))
    }

    /// Looks up a file context by path if already tracked.
    ///
    /// # Arguments
    ///
    /// * `raw_path` - The path to search.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    pub fn get_by_path(&self, raw_path: &str) -> Option<Arc<FileContext>> {
        let normalized = normalize_file_path(raw_path);
        let key_ref = self.path_to_key.get(&normalized)?;
        self.get_by_key(*key_ref.value())
    }

    /// Returns the total count of tracked files.
    ///
    /// # Returns
    ///
    /// Number of distinct files tracked in memory.
    #[inline]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Checks if the file registry is empty.
    ///
    /// # Returns
    ///
    /// `true` if zero files are currently tracked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Total count alias for backwards compatibility.
    ///
    /// # Returns
    ///
    /// Number of distinct files tracked in memory.
    #[inline]
    pub fn total_count(&self) -> usize {
        self.len()
    }
}

impl Default for FileRegistry {
    fn default() -> Self {
        Self::new()
    }
}
