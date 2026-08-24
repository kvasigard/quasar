use std::sync::Arc;
use crate::context::FileKey;

/// Immutable metadata describing an executable binary or dynamic-link library (DLL) image on disk.
///
/// Shared across all processes via [`Arc<ModuleInfo>`] to eliminate duplicate heap allocations
/// and memory redundancy for identical binaries (such as system DLLs mapped via ASLR).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleInfo {
    /// Module filename or full image path.
    pub image_name: Arc<str>,
    /// Size of the mapped image in bytes.
    pub image_size: u64,
    /// Synthetic storage key for the backing file on disk, if resolved.
    pub file_key: Option<FileKey>,
    /// Checksum extracted from the PE header.
    pub checksum: u32,
    /// Preferred default base address from the PE header.
    pub default_base: u64,
    /// Indicates whether this module resides in a recognized Windows system directory.
    pub is_system: bool,
}

impl ModuleInfo {
    /// Windows system directory subpaths used for system binary classification.
    const SYSTEM_PATH_PATTERNS: [&'static str; 5] = [
        r"\windows\system32\",
        r"\windows\syswow64\",
        r"\windows\winsxs\",
        r"\systemroot\system32\",
        r"\??\c:\windows\system32\",
    ];

    /// Instantiates a new [`ModuleInfo`], automatically evaluating whether the path points to a Windows system binary.
    #[inline]
    pub fn new(
        image_name: impl Into<Arc<str>>,
        image_size: u64,
        file_key: Option<FileKey>,
        checksum: u32,
        default_base: u64,
    ) -> Self {
        let image_name: Arc<str> = image_name.into();
        let is_system = Self::is_system_path(&image_name);

        Self {
            image_name,
            image_size,
            file_key,
            checksum,
            default_base,
            is_system,
        }
    }

    /// Evaluates whether a given filesystem path matches known Windows system directory signatures.
    #[must_use]
    pub fn is_system_path(path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        lower.contains(r"\system32\")
            || lower.contains(r"\syswow64\")
            || lower.contains(r"\winsxs\")
            || lower.contains(r"\systemroot\")
            || lower.ends_with("ntdll.dll")
            || lower.ends_with("win32u.dll")
            || lower.ends_with("kernel32.dll")
            || lower.ends_with("kernelbase.dll")
            || lower.ends_with("user32.dll")
            || Self::SYSTEM_PATH_PATTERNS
                .iter()
                .any(|pattern| lower.contains(pattern) || lower.starts_with(pattern))
    }
}

/// Lightweight per-process metadata representing an executable binary or DLL mapped into virtual memory.
///
/// Contains process-specific mapping attributes (such as `base_address` and `load_time`) and
/// references shared static metadata via `Arc<ModuleInfo>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoadedModule {
    /// Virtual base address where the image was mapped in this process.
    pub base_address: u64,
    /// Timestamp when the module was loaded (Windows `FILETIME` 100ns intervals).
    pub load_time: i64,
    /// Indicates whether this module lacks a physical backing file on disk (e.g., reflective DLL injection).
    pub is_unbacked: bool,
    /// Shared pointer to immutable module metadata.
    pub info: Arc<ModuleInfo>,
}

impl PartialOrd for LoadedModule {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LoadedModule {
    /// Orders modules primarily by their `base_address` to support binary search operations in sorted collections.
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.base_address.cmp(&other.base_address)
    }
}

impl LoadedModule {
    /// Instantiates a new [`LoadedModule`] with its own shared [`ModuleInfo`].
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_address: u64,
        image_size: u64,
        image_name: impl Into<Arc<str>>,
        file_key: Option<FileKey>,
        load_time: i64,
        checksum: u32,
        default_base: u64,
        is_unbacked: bool,
    ) -> Self {
        let info = Arc::new(ModuleInfo::new(
            image_name,
            image_size,
            file_key,
            checksum,
            default_base,
        ));

        Self {
            base_address,
            load_time,
            is_unbacked,
            info,
        }
    }

    /// Instantiates a [`LoadedModule`] using an existing pre-cached [`Arc<ModuleInfo>`].
    #[inline]
    pub fn with_info(
        base_address: u64,
        load_time: i64,
        is_unbacked: bool,
        info: Arc<ModuleInfo>,
    ) -> Self {
        Self {
            base_address,
            load_time,
            is_unbacked,
            info,
        }
    }

    /// Evaluates whether a given filesystem path matches known Windows system directory signatures.
    #[must_use]
    #[inline]
    pub fn is_system_path(path: &str) -> bool {
        ModuleInfo::is_system_path(path)
    }

    /// Module filename or full image path.
    #[inline]
    pub fn image_name(&self) -> &str {
        &self.info.image_name
    }

    /// Size of the mapped image in bytes.
    #[inline]
    pub fn image_size(&self) -> u64 {
        self.info.image_size
    }

    /// Synthetic storage key for the backing file on disk, if resolved.
    #[inline]
    pub fn file_key(&self) -> Option<FileKey> {
        self.info.file_key
    }

    /// Checksum extracted from the PE header.
    #[inline]
    pub fn checksum(&self) -> u32 {
        self.info.checksum
    }

    /// Preferred default base address from the PE header.
    #[inline]
    pub fn default_base(&self) -> u64 {
        self.info.default_base
    }

    /// Indicates whether this module resides in a recognized Windows system directory.
    #[inline]
    pub fn is_system(&self) -> bool {
        self.info.is_system
    }

    /// Checks whether the specified virtual address falls within the mapped bounds of this module.
    ///
    /// Operates over the half-open interval `[base_address, base_address + image_size)`.
    /// Uses saturating arithmetic to prevent address space overflow wrapping on corrupted headers.
    ///
    /// # Arguments
    ///
    /// * `addr` - The 64-bit virtual memory address to test.
    #[must_use]
    #[inline]
    pub fn contains_address(&self, addr: u64) -> bool {
        let end_address = self.base_address.saturating_add(self.info.image_size);
        (self.base_address..end_address).contains(&addr)
    }

    /// Computes the end virtual address of this module's mapped range.
    #[must_use]
    #[inline]
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.info.image_size)
    }

    /// Determines whether the module has been relocated from its preferred PE default base address.
    #[must_use]
    #[inline]
    pub fn is_relocated(&self) -> bool {
        self.info.default_base != 0 && self.base_address != self.info.default_base
    }
}
