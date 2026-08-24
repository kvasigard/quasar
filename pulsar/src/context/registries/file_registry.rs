//! Concurrent normalized filesystem file registry.

use std::sync::{Arc, OnceLock};
use dashmap::DashMap;
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

use crate::context::identity::FileKey;
use crate::context::models::file::FileContext;

/// Cached map of NT device paths to standard DOS drive letters (e.g. `\device\harddiskvolume3` -> `c:`).
fn dos_device_map() -> &'static Vec<(String, String)> {
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map = Vec::new();
        let mut buffer = [0u16; 512];
        for drive_letter in b'A'..=b'Z' {
            let drive_str = format!("{}:", drive_letter as char);
            let wide_drive: Vec<u16> = drive_str.encode_utf16().chain(std::iter::once(0)).collect();
            let len = unsafe {
                QueryDosDeviceW(wide_drive.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
            };
            if len > 0 {
                let nt_device = String::from_utf16_lossy(&buffer[..len as usize])
                    .trim_matches('\0')
                    .to_lowercase();
                map.push((nt_device, drive_str.to_lowercase()));
            }
        }
        map
    })
}

/// Normalizes Windows file paths:
/// 1. Strips NT namespace prefixes (`\??\`, `\\?\`).
/// 2. Converts NT kernel device paths (`\Device\HarddiskVolumeX\...`) to standard Win32 drive paths (`C:\...`).
/// 3. Normalizes forward slashes to standard Windows backslashes and lowercases for uniform indexing.
///
/// # Arguments
///
/// * `path` - The raw file path string from telemetry.
///
/// # Returns
///
/// A normalized lowercase Windows path string with standard backslashes accessible via Win32 APIs.
pub fn normalize_file_path(path: &str) -> String {
    let mut cleaned = path
        .strip_prefix(r"\??\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(path)
        .replace('/', "\\");

    let lower = cleaned.to_lowercase();
    if lower.starts_with(r"\device\harddiskvolume") {
        for (nt_device, drive_letter) in dos_device_map() {
            if lower.starts_with(nt_device) {
                cleaned = format!("{}{}", drive_letter, &cleaned[nt_device.len()..]);
                return cleaned.to_lowercase();
            }
        }
        // Fallback for unmapped volumes: use Win32 global root device prefix
        cleaned = format!(r"\\?\GLOBALROOT{}", cleaned);
    }

    cleaned.to_lowercase()
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

        match self.path_to_key.entry(normalized.clone()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let key = *occupied.get();
                if let Some(file_ref) = self.files.get(&key) {
                    file_ref.touch(timestamp);
                    (Arc::clone(file_ref.value()), false)
                } else {
                    let file_ctx = Arc::new(FileContext::new(key, normalized, timestamp));
                    self.files.insert(key, Arc::clone(&file_ctx));
                    (file_ctx, true)
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let key = FileKey::new();
                let file_ctx = Arc::new(FileContext::new(key, normalized, timestamp));
                self.files.insert(key, Arc::clone(&file_ctx));
                vacant.insert(key);
                (file_ctx, true)
            }
        }
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
    pub fn resolve_file_object(&self, file_object: u64) -> Option<FileKey> {
        self.file_objects.get(&file_object).map(|r| *r.value())
    }

    /// Resolves the synthetic `FileKey` associated with an active kernel `FileObject` (alias).
    pub fn get_key_by_file_object(&self, file_object: u64) -> Option<FileKey> {
        self.resolve_file_object(file_object)
    }

    /// Resolves the `FileContext` associated with an active kernel `FileObject`.
    pub fn get_by_file_object(&self, file_object: u64) -> Option<Arc<FileContext>> {
        let key = self.get_key_by_file_object(file_object)?;
        self.get_by_key(key)
    }

    /// Returns the number of currently active mapped kernel FileObjects.
    pub fn active_file_object_count(&self) -> usize {
        self.file_objects.len()
    }

    /// Removes a `FileObject` mapping upon cleanup or closure.
    pub fn unmap_file_object(&self, file_object: u64) -> Option<FileKey> {
        self.file_objects.remove(&file_object).map(|(_, k)| k)
    }

    /// Looks up a tracked file entity by its normalized path string.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to search.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    pub fn get_by_path(&self, path: &str) -> Option<Arc<FileContext>> {
        let normalized = normalize_file_path(path);
        let key = *self.path_to_key.get(&normalized)?;
        self.files.get(&key).map(|r| Arc::clone(r.value()))
    }

    /// Looks up a tracked file entity by its synthetic `FileKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The `FileKey` to look up.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    pub fn get_by_key(&self, key: FileKey) -> Option<Arc<FileContext>> {
        self.files.get(&key).map(|r| Arc::clone(r.value()))
    }

    /// Returns a list of all currently tracked files.
    ///
    /// # Returns
    ///
    /// A vector of shared [`Arc<FileContext>`] references.
    pub fn all_files(&self) -> Vec<Arc<FileContext>> {
        self.files.iter().map(|r| Arc::clone(r.value())).collect()
    }

    /// Returns the total number of tracked unique file entities.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Returns `true` if no files are tracked.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

impl Default for FileRegistry {
    fn default() -> Self {
        Self::new()
    }
}
