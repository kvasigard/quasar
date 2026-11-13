//! Domain entity representing a backing binary file on disk (`_CONTROL_AREA` / `_FILE_OBJECT`).
//!
//! When a process starts or maps a DLL via `ImageLoad`, Pulsar creates a shared [`BinaryImage`]
//! (`Arc<BinaryImage>`) immediately on the hot telemetry path with an empty [`OnceLock`] for its
//! heavy metadata. A background worker subsequently opens the file once, extracts its physical
//! [`FileId`] and [`FileRevision`], verifies its cryptographic [`SeSigningLevel`], parses its
//! [`PeMetadata`], and populates the `OnceLock` so all processes referencing that binary
//! gain lock-free access to the enriched metadata.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use crate::enrichment::{
    pe::{PeMetadata, TrackedExport},
    signature::SeSigningLevel,
};

/// Hardware volume and file index uniquely identifying a physical file on disk (`_FILE_OBJECT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Volume serial number reported by `GetFileInformationByHandle`.
    volume_serial: u32,
    /// 64-bit NTFS/ReFS file index (`(nFileIndexHigh << 32) | nFileIndexLow`).
    file_index: u64,
}

impl FileId {
    /// Creates a new [`FileId`] from a volume serial number and 64-bit file index.
    #[inline]
    pub const fn new(volume_serial: u32, file_index: u64) -> Self {
        Self {
            volume_serial,
            file_index,
        }
    }

    /// Returns the volume serial number.
    #[inline]
    pub const fn volume_serial(&self) -> u32 {
        self.volume_serial
    }

    /// Returns the 64-bit file index on the volume.
    #[inline]
    pub const fn file_index(&self) -> u64 {
        self.file_index
    }
}

/// Content state fingerprint used to detect in-place binary modifications or tampering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileRevision {
    /// File size in bytes.
    size: u64,
    /// 64-bit `FILETIME` timestamp of the last write to the file.
    last_write_time: u64,
}

impl FileRevision {
    /// Creates a new [`FileRevision`] from a file size and last-write timestamp.
    #[inline]
    pub const fn new(size: u64, last_write_time: u64) -> Self {
        Self {
            size,
            last_write_time,
        }
    }

    /// Returns the file size in bytes at the moment of inspection.
    #[inline]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the 64-bit `FILETIME` last-write timestamp.
    #[inline]
    pub const fn last_write_time(&self) -> u64 {
        self.last_write_time
    }
}

/// Heavy static metadata computed once off-thread by the background enrichment worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryMetadata {
    /// Physical hardware identity resolved from the open file handle.
    id: Option<FileId>,
    /// Modification revision at the moment of inspection.
    revision: Option<FileRevision>,
    /// Cryptographic Code Integrity signing tier.
    signing_level: SeSigningLevel,
    /// Parsed PE headers and tracked loader export RVAs (`None` if not a valid PE).
    pe_metadata: Option<PeMetadata>,
}

impl BinaryMetadata {
    /// Constructs a new [`BinaryMetadata`] record from completed background analysis results.
    pub fn new(
        id: Option<FileId>,
        revision: Option<FileRevision>,
        signing_level: SeSigningLevel,
        pe_metadata: Option<PeMetadata>,
    ) -> Self {
        Self {
            id,
            revision,
            signing_level,
            pe_metadata,
        }
    }

    /// Returns the physical hardware [`FileId`] if resolved.
    #[inline]
    pub const fn id(&self) -> Option<FileId> {
        self.id
    }

    /// Returns the [`FileRevision`] at the moment of inspection if resolved.
    #[inline]
    pub const fn revision(&self) -> Option<FileRevision> {
        self.revision
    }

    /// Returns the cryptographic [`SeSigningLevel`].
    #[inline]
    pub const fn signing_level(&self) -> SeSigningLevel {
        self.signing_level
    }

    /// Returns a reference to the parsed [`PeMetadata`] if the file is a valid PE.
    #[inline]
    pub const fn pe_metadata(&self) -> Option<&PeMetadata> {
        self.pe_metadata.as_ref()
    }
}

impl Default for BinaryMetadata {
    fn default() -> Self {
        BinaryMetadata {
            id: None,
            revision: None,
            signing_level: SeSigningLevel::Unchecked,
            pe_metadata: None,
        }
    }
}

/// Global representation of a backing binary image on disk (`_CONTROL_AREA`).
///
/// Created on-demand on the telemetry hot path and enriched asynchronously by `ImageCatalog`.
/// Fields are encapsulated to guarantee that `path` and `file_name` remain immutable and
/// `metadata` transitions once from unanalyzed (`None`) to analyzed (`Some`) via [`Self::set_metadata`].
#[derive(Debug)]
pub struct BinaryImage {
    /// Normalized Win32 filesystem path (e.g. `C:\Windows\System32\ntdll.dll`).
    path: Box<Path>,
    /// Short filename extracted from `path` (e.g. `ntdll.dll`).
    file_name: Box<str>,
    /// Lock-free cell populated once by the background enrichment worker.
    metadata: OnceLock<Arc<BinaryMetadata>>,
}

impl BinaryImage {
    /// Constructs a new unanalyzed `BinaryImage` ready to be queued for background enrichment.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path to the binary on disk.
    ///
    /// # Return values
    ///
    /// * `Self` - A new [`BinaryImage`] whose `metadata` is uninitialized (`None`).
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned().into_boxed_str())
            .unwrap_or_else(|| "".into());

        BinaryImage {
            path: Box::from(path),
            file_name,
            metadata: OnceLock::new(),
        }
    }

    /// Returns a borrowed slice of the binary's full filesystem path.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the short filename (e.g. `"ntdll.dll"`) of the binary.
    #[inline]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Populates the binary's metadata once the background worker completes analysis.
    ///
    /// # Arguments
    ///
    /// * `metadata` - Shared [`BinaryMetadata`] computed by the enrichment worker.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Metadata was successfully stored in the [`OnceLock`].
    /// * `Err(Arc<BinaryMetadata>)` - Metadata was already initialized on this [`BinaryImage`].
    pub fn set_metadata(&self, metadata: Arc<BinaryMetadata>) -> Result<(), Arc<BinaryMetadata>> {
        self.metadata.set(metadata)
    }

    /// Returns a reference to the completed [`BinaryMetadata`], or `None` if still pending.
    #[inline]
    pub fn metadata(&self) -> Option<&BinaryMetadata> {
        self.metadata.get().map(Arc::as_ref)
    }

    /// Returns the verified [`SeSigningLevel`], defaulting to [`SeSigningLevel::Unchecked`]
    /// if background analysis is still in flight.
    #[inline]
    pub fn signing_level(&self) -> SeSigningLevel {
        self.metadata()
            .map_or(SeSigningLevel::Unchecked, |m| m.signing_level)
    }

    /// Returns the parsed [`PeMetadata`] if analysis is complete and the file is a valid PE.
    #[inline]
    pub fn pe(&self) -> Option<&PeMetadata> {
        self.metadata().and_then(|m| m.pe_metadata.as_ref())
    }

    /// Looks up the direct executable RVA for a [`TrackedExport`] if available.
    #[inline]
    pub fn export_rva(&self, export: TrackedExport) -> Option<u32> {
        self.pe()?.export_rva(export)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::pe::{ExportTarget, PeArchitecture};
    use std::collections::HashMap;

    #[test]
    fn test_binary_image_pending_defaults_and_once_lock_transition() {
        let img = BinaryImage::new("C:\\Windows\\System32\\kernel32.dll");

        // 1. Before enrichment completes (Pending state)
        assert_eq!(img.path(), Path::new("C:\\Windows\\System32\\kernel32.dll"));
        assert_eq!(img.file_name(), "kernel32.dll");
        assert!(img.metadata().is_none());
        assert!(img.pe().is_none());
        assert_eq!(img.signing_level(), SeSigningLevel::Unchecked);
        assert_eq!(img.export_rva(TrackedExport::LoadLibraryW), None);

        // 2. Populate metadata from background worker
        let mut exports = HashMap::new();
        exports.insert(TrackedExport::LoadLibraryW, ExportTarget::CodeRva(0x1F480));

        let meta = Arc::new(BinaryMetadata::new(
            Some(FileId::new(0x1234_5678, 0x0001_0000_0000_0042)),
            Some(FileRevision::new(780_000, 133_500_000_000_000_000)),
            SeSigningLevel::Windows,
            Some(PeMetadata::new(
                PeArchitecture::X64,
                true,
                0xC0000,
                0x1010,
                0xABCD,
                0x6500_0000,
                exports,
            )),
        ));

        assert!(img.set_metadata(Arc::clone(&meta)).is_ok());

        // 3. After enrichment completes (Analyzed state)
        assert_eq!(img.signing_level(), SeSigningLevel::Windows);
        assert_eq!(img.export_rva(TrackedExport::LoadLibraryW), Some(0x1F480));
        assert_eq!(img.export_rva(TrackedExport::LdrLoadDll), None);

        // 4. Attempting to overwrite already-set metadata must be rejected by OnceLock
        let duplicate = Arc::new(BinaryMetadata::default());
        assert!(img.set_metadata(duplicate).is_err());
    }
}
