use crate::context::FileKey;

/// Metadata representing an executable binary or dynamic-link library (DLL) mapped into virtual memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoadedModule {
    /// Virtual base address where the image was mapped in memory.
    pub base_address: u64,
    /// Size of the mapped image in bytes.
    pub image_size: u64,
    /// Module filename or full image path.
    pub image_name: String,
    /// Synthetic storage key for the backing file on disk, if resolved.
    pub file_key: Option<FileKey>,
    /// Timestamp when the module was loaded (Windows `FILETIME` 100ns intervals).
    pub load_time: i64,
    /// Checksum extracted from the PE header.
    pub checksum: u32,
    /// Preferred default base address from the PE header.
    pub default_base: u64,
    /// Indicates whether this module lacks a physical backing file on disk (e.g., reflective DLL injection).
    pub is_unbacked: bool,
    /// Indicates whether this module resides in a recognized Windows system directory.
    pub is_system: bool,
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
    /// Windows system directory subpaths used for system binary classification.
    const SYSTEM_PATH_PATTERNS: [&'static str; 5] = [
        r"\windows\system32\",
        r"\windows\syswow64\",
        r"\windows\winsxs\",
        r"\systemroot\system32\",
        r"\??\c:\windows\system32\",
    ];

    /// Instantiates a new [`LoadedModule`], automatically evaluating whether the path points to a Windows system binary.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_address: u64,
        image_size: u64,
        image_name: impl Into<String>,
        file_key: Option<FileKey>,
        load_time: i64,
        checksum: u32,
        default_base: u64,
        is_unbacked: bool,
    ) -> Self {
        let image_name = image_name.into();
        let is_system = Self::is_system_path(&image_name);

        Self {
            base_address,
            image_size,
            image_name,
            file_key,
            load_time,
            checksum,
            default_base,
            is_unbacked,
            is_system,
        }
    }

    /// Evaluates whether a given filesystem path matches known Windows system directory signatures.
    ///
    /// The check normalizes the input path to lowercase ASCII and matches against NT, DOS,
    /// and standard subsystem path variations.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path or module name to evaluate.
    #[must_use]
    pub fn is_system_path(path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        Self::SYSTEM_PATH_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern) || lower.starts_with(pattern))
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
        let end_address = self.base_address.saturating_add(self.image_size);
        (self.base_address..end_address).contains(&addr)
    }

    /// Computes the end virtual address of this module's mapped range.
    #[must_use]
    #[inline]
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.image_size)
    }

    /// Determines whether the module has been relocated from its preferred PE default base address.
    #[must_use]
    #[inline]
    pub fn is_relocated(&self) -> bool {
        self.default_base != 0 && self.base_address != self.default_base
    }
}
