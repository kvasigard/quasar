//! Windows Binary Signature Verifier
//!
//! A thread-safe binary signature verifier using the Windows `WTGetSignatureInfo` API.
//! The verifier must detect embedded Authenticode signatures, detached Windows Catalog (`.cat`)
//! signatures, and identify native Windows OS binaries
//!
//! # Documentation & References
//!
//! - **WTGetSignatureInfo (Wine / MinGW definitions & implementation):**
//!   - Wine `wintrust.h` header definition: <https://github.com/wine-mirror/wine/blob/master/include/wintrust.h>
//!   - System Informer / Process Hacker implementation: <https://github.com/winsiderss/systeminformer/blob/master/phlib/verify.c>
//!   - Wine implementation: <https://gitlab.winehq.org/wine/wine/-/blob/master/dlls/wintrust/wintrust_main.c>
//!
//! - **WinVerifyTrust & WINTRUST_DATA:**
//!   - `WinVerifyTrust` function: <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust>
//!   - `WINTRUST_DATA` structure: <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data>
//!   - Example PE verification: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file>
//!
//! - **File Handling & Cryptography:**
//!   - `CreateFileW`: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew>
//!   - `GetFileInformationByHandle`: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle>
//!   - `CertFreeCertificateContext`: <https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext>
//!   - Authenticode PE Specification: <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>
//!

use std::{
    collections::HashMap,
    fmt,
    fs::OpenOptions,
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle},
    },
    path::Path,
    sync::RwLock,
};

use log::{debug, trace, warn};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle,
};

/// Represents the 16 Windows Code Integrity (`ci.dll`) signing levels (`SE_SIGNING_LEVEL`).
///
/// In the Windows Kernel, each active process (`EPROCESS.SignatureLevel`) and binary section
/// (`EPROCESS.SectionSignatureLevel`) is stamped with one of these values. Protected Process
/// Light (PPL) and Windows Defender Application Control (WDAC) use this numerical hierarchy
/// to restrict process access and prevent lower-trust code from tampering with higher-trust binaries.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeSigningLevel {
    /// `0x00` (0): The file has not yet been inspected or verification was skipped/aborted.
    Unchecked = 0x00,
    /// `0x01` (1): Inspected and explicitly verified to contain no valid digital signature.
    Unsigned = 0x01,
    /// `0x02` (2): Signed by an Enterprise-specific certificate (e.g. internal PKI / WDAC enterprise policy).
    Enterprise = 0x02,
    /// `0x03` (3): Test-signed binary or developer-mode certificate (e.g. Windows TestSigning mode).
    Developer = 0x03,
    /// `0x04` (4): Standard third-party Authenticode signature chaining to a public trusted root CA.
    Authenticode = 0x04,
    /// `0x05` (5): Reserved custom policy level (Custom 2).
    Custom2 = 0x05,
    /// `0x06` (6): Microsoft Store / Universal Windows Platform (UWP / AppX) signed application.
    Store = 0x06,
    /// `0x07` (7): Antimalware vendor signature (used for Early Launch Anti-Malware / ELAM and PPL AV drivers).
    Antimalware = 0x07,
    /// `0x08` (8): General Microsoft-signed binary not part of the base OS (e.g. Sysinternals, VS Code, Teams).
    Microsoft = 0x08,
    /// `0x09` (9): Reserved custom policy level (Custom 4).
    Custom4 = 0x09,
    /// `0x0A` (10): Reserved custom policy level (Custom 5).
    Custom5 = 0x0A,
    /// `0x0B` (11): Dynamic code generation authorization (used by JIT compilers, e.g. web browsers like Edge).
    DynamicCodegen = 0x0B,
    /// `0x0C` (12): Core Windows operating system binary (e.g. `taskmgr.exe`, `kernel32.dll`, standard drivers).
    Windows = 0x0C,
    /// `0x0D` (13): Reserved custom policy level (Custom 7).
    Custom7 = 0x0D,
    /// `0x0E` (14): Windows Trusted Computing Base (TCB) — the highest kernel privilege tier (e.g. `smss.exe`, `ntoskrnl.exe`).
    WindowsTcb = 0x0E,
    /// `0x0F` (15): Highest reserved custom policy level (Custom 6).
    Custom6 = 0x0F,
}

impl SeSigningLevel {
    /// Evaluates whether the signing level meets the minimum cryptographic trust threshold.
    ///
    /// Excludes `Unchecked`, `Unsigned`, `Enterprise`, and `Developer` (test-signed) levels so
    /// that only binaries chaining to a recognized public root CA or Microsoft root are trusted
    /// by default.
    ///
    /// # Arguments
    ///
    /// * `self` - The [`SeSigningLevel`] verdict to evaluate.
    ///
    /// # Return values
    ///
    /// * `true` - The signing level is [`SeSigningLevel::Authenticode`] (`0x04`) or higher.
    /// * `false` - The binary is unsigned, unchecked, or signed with a non-production/test certificate.
    #[inline]
    pub const fn is_trusted(self) -> bool {
        (self as u8) >= (Self::Authenticode as u8)
    }

    /// Determines whether the signing level corresponds to a genuine Microsoft Windows OS binary.
    ///
    /// Identifies core system components and Trusted Computing Base (TCB) binaries that chain to
    /// the Microsoft Root Authority and carry the Windows System Component EKU.
    ///
    /// # Arguments
    ///
    /// * `self` - The [`SeSigningLevel`] verdict to evaluate.
    ///
    /// # Return values
    ///
    /// * `true` - The signing level is [`SeSigningLevel::Windows`] (`0x0C`) or [`SeSigningLevel::WindowsTcb`] (`0x0E`).
    /// * `false` - The binary is third-party signed, unsigned, or non-OS Microsoft software.    #[inline]
    pub const fn is_os_binary(self) -> bool {
        matches!(self, Self::Windows | Self::WindowsTcb)
    }
}

impl TryFrom<u8> for SeSigningLevel {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Unchecked),
            0x01 => Ok(Self::Unsigned),
            0x02 => Ok(Self::Enterprise),
            0x03 => Ok(Self::Developer),
            0x04 => Ok(Self::Authenticode),
            0x05 => Ok(Self::Custom2),
            0x06 => Ok(Self::Store),
            0x07 => Ok(Self::Antimalware),
            0x08 => Ok(Self::Microsoft),
            0x09 => Ok(Self::Custom4),
            0x0A => Ok(Self::Custom5),
            0x0B => Ok(Self::DynamicCodegen),
            0x0C => Ok(Self::Windows),
            0x0D => Ok(Self::Custom7),
            0x0E => Ok(Self::WindowsTcb),
            0x0F => Ok(Self::Custom6),
            other => Err(other),
        }
    }
}

/// Detailed failure modes that prevent the verifier from reaching a cryptographic verdict.
///
/// Separating operational failures (like missing files or locked handles) from cryptographic
/// verdicts allows callers to decide whether to retry, log an operational alert, or treat the
/// file as untrusted.
#[derive(Debug)]
pub enum VerifierError {
    /// `wintrust.dll` or the `WTGetSignatureInfo` export could not be resolved on the host OS.
    ApiUnavailable,
    /// Failed to open the target file or query its handle metadata.
    /// Wraps `std::io::Error`, which natively captures and formats Win32 `GetLastError` codes
    /// and rejects invalid paths (such as paths containing interior NUL bytes).
    Io(io::Error),
    /// `WTGetSignatureInfo` returned a failing (negative) `HRESULT`.
    WinTrust(i32),
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiUnavailable => write!(f, "WTGetSignatureInfo unavailable in wintrust.dll"),
            Self::Io(err) => write!(f, "I/O error during signature verification: {err}"),
            Self::WinTrust(hr) => write!(
                f,
                "WTGetSignatureInfo failed (HRESULT: 0x{:08X})",
                *hr as u32
            ),
        }
    }
}

impl std::error::Error for VerifierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for VerifierError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Uniquely identifies a physical file on a storage volume regardless of path casing
/// (`cmd.exe` vs `CMD.EXE`), symlinks, hardlinks, etc.
///
/// Using this 16-byte `Copy` struct as the `HashMap` key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    volume_serial: u32,
    file_index: u64,
}

/// Fingerprint of a file's content state used to detect in-place modifications.
///
/// If a cached `FileId` is opened again, we compare its current `FileRevision` (extracted directly
/// from the open handle) against the cached revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileRevision {
    size: u64,
    last_write_time: u64,
}

/// Associates a cached cryptographic verdict with the exact file revision that produced it.
#[derive(Debug, Clone, Copy)]
struct CachedVerdict {
    revision: FileRevision,
    level: SeSigningLevel,
}

/// Thread-safe Windows binary signature verifier backed by `WTGetSignatureInfo` and an
/// anti-poisoning hardware-identity cache.
pub struct BinarySignatureVerifier {
    /// Upper bound on cached file verdicts to prevent unbounded memory growth in long-running services.
    max_cache_entries: usize,
    /// Concurrent read-heavy cache mapping physical `FileId`s to their stamped verification verdict.
    /// `RwLock` allows multiple worker threads to hit the cache simultaneously without contention.
    signature_cache: RwLock<HashMap<FileId, CachedVerdict>>,
}

impl BinarySignatureVerifier {
    /// Initializes a new thread-safe binary signature verifier with a bounded anti-poisoning cache.
    ///
    /// Eagerly resolves the `WTGetSignatureInfo` export from `wintrust.dll` on first invocation
    /// and pre-allocates the internal `RwLock`-protected hash map to avoid re-allocations during
    /// initial verification bursts.
    ///
    /// # Arguments
    ///
    /// * `max_cache_entries` - Maximum number of unique physical files (`FileId`) to retain in the
    ///   cache before evicting existing entries. Passing `0` disables caching entirely.
    ///
    /// # Return values
    ///
    /// * `Self` - An initialized [`BinarySignatureVerifier`] ready for concurrent verification requests.
    pub fn new(max_cache_entries: usize) -> Self {
        // Eagerly resolve the FFI symbol on startup so missing DLL issues are logged immediately.
        if ffi::wt_get_signature_info().is_some() {
            debug!(
                "Initialized BinarySignatureVerifier (max_cache_entries = {})",
                max_cache_entries
            );
        }

        Self {
            max_cache_entries,
            signature_cache: RwLock::new(HashMap::with_capacity(max_cache_entries)),
        }
    }

    /// Verifies the digital signature of a binary file on disk, degrading safely on operational errors.
    ///
    /// Designed for hot paths (such as process-creation telemetry callbacks) where missing files,
    /// sharing violations, or WinTrust engine errors should immediately fall back to an untrusted
    /// [`SeSigningLevel::Unchecked`] verdict rather than propagating an error.
    ///
    /// # Arguments
    ///
    /// * `path` - File system path to the target binary to inspect.
    ///
    /// # Return values
    ///
    /// * `SeSigningLevel::Windows` - Binary is validly signed (embedded or catalog) and verified as a core Windows OS component.
    /// * `SeSigningLevel::Authenticode` - Binary carries a valid, trusted third-party or non-OS Microsoft signature.
    /// * `SeSigningLevel::Unsigned` - File was opened and inspected, but has no signature, a tampered hash, or an untrusted root.
    /// * `SeSigningLevel::Unchecked` - Verification could not be performed due to an I/O error, invalid path, or unavailable API.
    pub fn verify<P: AsRef<Path>>(&self, path: P) -> SeSigningLevel {
        let path = path.as_ref();
        self.try_verify(path).unwrap_or_else(|err| {
            warn!(
                "Verification could not complete for '{}': {err}. Defaulting to Unchecked.",
                path.display()
            );
            SeSigningLevel::Unchecked
        })
    }

    /// Performs diagnostic cryptographic signature verification of a target binary file.
    ///
    /// Opens the file handle with permissive sharing flags (`FILE_SHARE_READ | WRITE | DELETE`)
    /// prior to querying its hardware file identity (`VolumeSerial`, `FileIndex`) and modification
    /// revision (`Size`, `LastWriteTime`) to prevent TOCTOU path-swapping and cache-poisoning attacks.
    ///
    /// # Arguments
    ///
    /// * `path` - File system path to the target binary to inspect.
    ///
    /// # Return values
    ///
    /// * `Ok(SeSigningLevel)` - Cryptographic inspection completed (or matched a valid cache entry) and produced a signing level verdict.
    /// * `Err(VerifierError::ApiUnavailable)` - `wintrust.dll` or `WTGetSignatureInfo` could not be resolved on the host OS.
    /// * `Err(VerifierError::Io)` - Target file could not be opened, path contained interior NUL bytes, or `GetFileInformationByHandle` failed.
    /// * `Err(VerifierError::WinTrust)` - `WTGetSignatureInfo` failed with a negative `HRESULT` status code.
    pub fn try_verify<P: AsRef<Path>>(&self, path: P) -> Result<SeSigningLevel, VerifierError> {
        let path = path.as_ref();
        trace!("Starting signature verification for '{}'", path.display());

        // Open the file *before* checking the cache so we inspect the handle's true identity,
        // preventing TOCTOU path-swapping attacks.
        //
        // Rust's `OpenOptions` automatically converts the path to UTF-16, rejects interior NUL
        // bytes, invokes `CreateFileW`, and wraps the handle in `std::fs::File` (which guarantees
        // `CloseHandle` on drop). Permissive share flags (`READ | WRITE | DELETE`) are critical
        // to avoid sharing violations when inspecting actively running executables or DLLs.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)?;

        // Query the volume/file index and size/timestamp directly from the open kernel handle.
        let (file_id, current_rev) = query_handle_identity(file.as_raw_handle() as _)?;

        if let Some(cached_level) = self.lookup_cache(file_id, current_rev, path) {
            return Ok(cached_level);
        }

        // Delegate the cryptographic check to our isolated FFI boundary.
        // Passing `file.as_handle()` (`BorrowedHandle<'_>`) proves to the compiler that the file
        // handle stays open for the entire duration of the WinTrust call.
        let report = ffi::verify_open_file(path, file.as_handle())?;

        let level = match (report.is_trusted(), report.is_os_binary) {
            (true, true) => SeSigningLevel::Windows,
            (true, false) => SeSigningLevel::Authenticode,
            // The file was successfully inspected by WinTrust, but its signature is missing,
            // tampered with (invalid hash), or chains to an untrusted/revoked root.
            (false, _) => SeSigningLevel::Unsigned,
        };

        debug!(
            "Verified '{}' (vol={:08X}, idx={:016X}): level={level:?}, state={:?}, kind={:?}, is_os_binary={}",
            path.display(),
            file_id.volume_serial,
            file_id.file_index,
            report.state,
            report.kind,
            report.is_os_binary
        );

        self.insert_cache(file_id, current_rev, level);
        Ok(level)
    }

    /// Looks up the physical `FileId` in the cache and validates that its `FileRevision`
    /// matches the currently open handle.
    fn lookup_cache(
        &self,
        id: FileId,
        current_rev: FileRevision,
        path: &Path,
    ) -> Option<SeSigningLevel> {
        if self.max_cache_entries == 0 {
            return None;
        }

        // Recover gracefully if another thread panicked while holding the lock.
        let cache = self
            .signature_cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(entry) = cache.get(&id) {
            if entry.revision == current_rev {
                trace!("Cache HIT for '{}' -> {:?}", path.display(), entry.level);
                return Some(entry.level);
            } else {
                debug!(
                    "Cache INVALIDATED for '{}': file revision changed (old={:?}, new={:?})",
                    path.display(),
                    entry.revision,
                    current_rev
                );
            }
        } else {
            trace!("Cache MISS for '{}'", path.display());
        }

        None
    }

    /// Stores the verification verdict under the file's physical `FileId`, evicting an entry
    /// if the cache has reached its configured capacity.
    fn insert_cache(&self, id: FileId, revision: FileRevision, level: SeSigningLevel) {
        if self.max_cache_entries == 0 {
            return;
        }

        let mut cache = self
            .signature_cache
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Enforce capacity bound before inserting a brand-new key.
        if cache.len() >= self.max_cache_entries && !cache.contains_key(&id) {
            if let Some(&evicted_id) = cache.keys().next() {
                debug!(
                    "Cache full ({} entries); evicting {:?}",
                    self.max_cache_entries, evicted_id
                );
                cache.remove(&evicted_id);
            }
        }

        cache.insert(id, CachedVerdict { revision, level });
    }
}

/// Extracts the physical [`FileId`] and [`FileRevision`] directly from an open Win32 file handle.
fn query_handle_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<(FileId, FileRevision)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let id = FileId {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64),
    };
    let rev = FileRevision {
        size: ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64),
        last_write_time: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | (info.ftLastWriteTime.dwLowDateTime as u64),
    };

    Ok((id, rev))
}

/// Encapsulates all `unsafe` WinTrust data structures, dynamic symbol resolution, and
/// RAII resource cleanup behind a safe internal API (`verify_open_file`).
pub mod ffi {
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, BorrowedHandle},
            raw::HANDLE,
        },
        path::Path,
        ptr,
        sync::OnceLock,
    };

    use log::{error, warn};
    use windows_sys::{
        Win32::{
            Foundation::GetLastError,
            Security::{
                Cryptography::{CERT_CONTEXT, CertFreeCertificateContext},
                WinTrust::{
                    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WTD_CHOICE_FILE,
                    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_UI_NONE, WinVerifyTrust,
                },
            },
            System::LibraryLoader::{GetProcAddress, LoadLibraryW},
        },
        w,
    };

    use super::VerifierError;

    // Flags for WTGetSignatureInfo
    /// Check embedded PE Authenticode signatures.
    pub const SIF_AUTHENTICODE_SIGNED: u32 = 0x0001;
    /// Check external Windows catalog (`.cat`) files.
    pub const SIF_CATALOG_SIGNED: u32 = 0x0002;
    /// Enables populating `SIGNATURE_INFO::is_os_binary`.
    pub const SIF_CHECK_OS_BINARY: u32 = 0x0008;
    /// Fast local check (avoids blocking on network CRL/OCSP requests).
    pub const SIF_BASE_VERIFICATION: u32 = 0x0100;

    /// Cryptographically valid signature.
    pub const SIGNATURE_STATE_VALID: i32 = 5;
    /// Fully trusted against the Windows root store.
    pub const SIGNATURE_STATE_TRUSTED: i32 = 6;

    /// Structure representing the extracted signature details from a file or catalog.
    ///
    /// Reference: <https://github.com/winsiderss/systeminformer/blob/master/phlib/include/verifyp.h>
    #[repr(C)]
    pub struct SIGNATURE_INFO {
        /// [IN] Size of this structure in bytes: must be set to `size_of::<SIGNATURE_INFO>() as u32`
        /// before calling `WTGetSignatureInfo`, or the function returns `E_INVALIDARG` (`0x80070057`).
        pub cb_size: u32,
        /// [OUT] Cryptographic status of the signature:
        /// - `0` = `SIGNATURE_STATE_UNSIGNED` (File has no signature)
        /// - `1` = `SIGNATURE_STATE_SIGNED`   (Signature block exists but unverified)
        /// - `2` = `SIGNATURE_STATE_INVALID`  (Hash mismatch, corrupt, or tampered file)
        /// - `3` = `SIGNATURE_STATE_UNTRUSTED` (Valid hash, but cert is untrusted/revoked)
        /// - `5` = `SIGNATURE_STATE_VALID`    (Cryptographically valid signature)
        /// - `6` = `SIGNATURE_STATE_TRUSTED`  (Fully trusted against root store)
        pub signature_state: i32,
        /// [OUT] The mechanism used to sign the file:
        /// - `1` = `SIT_AUTHENTICODE` (Embedded signature inside the PE header)
        /// - `2` = `SIT_CATALOG`      (Detached signature in `%SystemRoot%\System32\CatRoot`)
        pub signature_t: i32,
        /// [OUT] Bitmask indicating which signature metadata fields were populated by the engine.
        pub signature_info_availability: u32,
        /// [OUT] Bitmask indicating general publisher/certificate info availability.
        pub info_availability: u32,
        /// [IN/OUT, Optional] Pointer to a caller-provided UTF-16 buffer to receive the
        /// program/display name (from `SpcSpOpusInfo`). Set to null if not querying.
        pub display_name: *mut u16,
        /// [IN/OUT, Optional] Length (in `wchar_t`) of `display_name` buffer. Set to 0 if null.
        pub display_name_len: u32,
        /// [IN/OUT, Optional] Pointer to a caller-provided UTF-16 buffer to receive the
        /// certificate Subject / Publisher name. Set to null if not querying.
        pub publisher_name: *mut u16,
        /// [IN/OUT, Optional] Length (in `wchar_t`) of `publisher_name` buffer. Set to 0 if null.
        pub publisher_name_len: u32,
        /// [IN/OUT, Optional] Pointer to a caller-provided UTF-16 buffer to receive the
        /// publisher's information URL. Set to null if not querying.
        pub more_info_url: *mut u16,
        /// [IN/OUT, Optional] Length (in `wchar_t`) of `more_info_url` buffer. Set to 0 if null.
        pub more_info_url_len: u32,
        /// [IN/OUT, Optional] Pointer to a caller-provided byte buffer to receive the
        /// calculated cryptographic hash of the file. Set to null if not querying.
        pub hash_value: *mut u8,
        /// [IN/OUT, Optional] Length in bytes of the `hash_value` buffer. Set to 0 if null.
        pub hash_value_len: u32,
        /// [OUT] Boolean flag (`1` or `0`):
        /// - `1` (true)  = The binary is an authentic Microsoft Windows OS component
        ///                 (chains to the Microsoft Root and contains the Windows OS EKU).
        /// - `0` (false) = Third-party signed, unsigned, or non-OS Microsoft software.
        pub is_os_binary: i32,
    }

    /// Function signature for `WTGetSignatureInfo` from `wintrust.dll`.
    pub type FnWTGetSignatureInfo = unsafe extern "system" fn(
        // [in, optional] Null-terminated UTF-16 path to the file on disk.
        psz_file: *const u16,
        // [in, optional] Handle to an open file (must have at least GENERIC_READ).
        // Recommended to pass an explicit handle with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        // to avoid sharing conflicts with running processes.
        h_file: HANDLE,
        // [in] Flags controlling what checks WTGetSignatureInfo performs:
        // - 0x0001 (SIF_AUTHENTICODE_SIGNED): Check embedded PE signatures.
        // - 0x0002 (SIF_CATALOG_SIGNED):      Check external Windows catalog (.cat) files.
        // - 0x0008 (SIF_CHECK_OS_BINARY):     Enables populating `sig_info.is_os_binary`.
        // - 0x0100 (SIF_BASE_VERIFICATION):   Fast local check (no network CRL/OCSP blocking).
        sig_info_flags: u32,
        // [in, out] Pointer to the caller-allocated SIGNATURE_INFO struct.
        // MUST have `sig_info.cb_size` initialized prior to calling.
        sig_info: *mut SIGNATURE_INFO,
        // [out] Receives a pointer to the leaf signing certificate context (PCCERT_CONTEXT).
        // If non-null on return, you MUST release it via `CertFreeCertificateContext`.
        cert_context: *mut *mut c_void,
        // [out] Receives an internal WinVerifyTrust state handle (`hWVTStateData`).
        // If non-null on return, you MUST release it via `WinVerifyTrust` with `WTD_STATEACTION_CLOSE`.
        wvt_state_data: *mut HANDLE,
    ) -> i32; // Returns HRESULT (0 / S_OK on success, negative value on failure)

    /// Dynamically resolves the `WTGetSignatureInfo` function pointer from `wintrust.dll`.
    ///
    /// Caches the resolved symbol inside a process-wide `OnceLock` so subsequent calls return
    /// immediately without incrementing the module reference count via repeated `LoadLibraryW` calls.
    ///
    /// # Return values
    ///
    /// * `Some(FnWTGetSignatureInfo)` - Successfully loaded `wintrust.dll` and located the `WTGetSignatureInfo` export.
    /// * `None` - `LoadLibraryW` or `GetProcAddress` failed on the current operating system.
    pub fn wt_get_signature_info() -> Option<FnWTGetSignatureInfo> {
        static WT_GET_SIG_INFO: OnceLock<Option<FnWTGetSignatureInfo>> = OnceLock::new();

        *WT_GET_SIG_INFO.get_or_init(|| unsafe {
            let module = LoadLibraryW(w!("wintrust.dll"));
            if module.is_null() {
                error!(
                    "LoadLibraryW(\"wintrust.dll\") failed with Win32 error 0x{:08X}",
                    GetLastError()
                );
                return None;
            }
            let proc = GetProcAddress(module, c"WTGetSignatureInfo".as_ptr().cast());
            if proc.is_none() {
                error!("GetProcAddress(\"WTGetSignatureInfo\") failed in wintrust.dll");
            }
            proc.map(|addr| std::mem::transmute::<_, FnWTGetSignatureInfo>(addr))
        })
    }

    /// Safe representation of `SIGNATURE_INFO::signature_state`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignatureState {
        Unsigned,
        SignedUnverified,
        Invalid,
        Untrusted,
        Valid,
        Trusted,
        Unknown(i32),
    }

    impl From<i32> for SignatureState {
        fn from(raw: i32) -> Self {
            match raw {
                0 => Self::Unsigned,
                1 => Self::SignedUnverified,
                2 => Self::Invalid,
                3 => Self::Untrusted,
                SIGNATURE_STATE_VALID => Self::Valid,
                SIGNATURE_STATE_TRUSTED => Self::Trusted,
                other => Self::Unknown(other),
            }
        }
    }

    /// Safe representation of `SIGNATURE_INFO::signature_t`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignatureKind {
        None,
        Authenticode,
        Catalog,
        Unknown(i32),
    }

    impl From<i32> for SignatureKind {
        fn from(raw: i32) -> Self {
            match raw {
                0 => Self::None,
                1 => Self::Authenticode,
                2 => Self::Catalog,
                other => Self::Unknown(other),
            }
        }
    }

    /// High-level, safe summary of `SIGNATURE_INFO` after all Win32 handles/contexts are freed.
    #[derive(Debug, Clone, Copy)]
    pub struct SignatureReport {
        pub state: SignatureState,
        pub kind: SignatureKind,
        pub is_os_binary: bool,
    }

    impl SignatureReport {
        /// Checks whether the WinTrust signature state represents a cryptographically valid and trusted signature.
        ///
        /// # Arguments
        ///
        /// * `&self` - The extracted [`SignatureReport`] to inspect.
        ///
        /// # Return values
        ///
        /// * `true` - `self.state` is either [`SignatureState::Valid`] (`5`) or [`SignatureState::Trusted`] (`6`).
        /// * `false` - The file is unsigned, has a hash mismatch, or chains to an untrusted/revoked certificate.
        #[inline]
        pub fn is_trusted(&self) -> bool {
            matches!(self.state, SignatureState::Valid | SignatureState::Trusted)
        }
    }

    /// Calls `WTGetSignatureInfo` on a borrowed file handle and guarantees RAII cleanup
    /// of returned `CERT_CONTEXT` and `hWVTStateData` resources before returning.
    pub(super) fn verify_open_file(
        path: &Path,
        handle: BorrowedHandle<'_>,
    ) -> Result<SignatureReport, VerifierError> {
        let wtget_signature_info = wt_get_signature_info().ok_or(VerifierError::ApiUnavailable)?;

        let wpath: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Combine flags to inspect both embedded Authenticode and detached Catalog signatures
        // locally without blocking on network revocation servers.
        let flags = SIF_AUTHENTICODE_SIGNED
            | SIF_CATALOG_SIGNED
            | SIF_CHECK_OS_BINARY
            | SIF_BASE_VERIFICATION;

        let mut sig_info: SIGNATURE_INFO = unsafe { std::mem::zeroed() };
        sig_info.cb_size = std::mem::size_of::<SIGNATURE_INFO>() as u32;

        // Guard out-parameters (`cert_ctx` and `wvt_state`) so Win32 cryptographic contexts
        // are always released as soon as this scope exits, even on error or panic.
        let mut guard = WinTrustContextGuard::default();

        let status = unsafe {
            wtget_signature_info(
                wpath.as_ptr(),
                handle.as_raw_handle(),
                flags,
                &mut sig_info,
                &mut guard.cert_ctx,
                &mut guard.wvt_state,
            )
        };

        if status < 0 {
            warn!(
                "WTGetSignatureInfo failed for '{}' with HRESULT 0x{:08X}",
                path.display(),
                status as u32
            );
            return Err(VerifierError::WinTrust(status));
        }

        Ok(SignatureReport {
            state: SignatureState::from(sig_info.signature_state),
            kind: SignatureKind::from(sig_info.signature_t),
            is_os_binary: sig_info.is_os_binary != 0,
        })
    }

    /// RAII guard for the cryptographic state handles populated by `WTGetSignatureInfo`.
    ///
    /// `WTGetSignatureInfo` allocates both an internal `WinVerifyTrust` state machine (`hWVTStateData`)
    /// and a leaf `CERT_CONTEXT`. Failing to close both leaks significant heap memory in long-running
    /// security services.
    struct WinTrustContextGuard {
        cert_ctx: *mut c_void,
        wvt_state: HANDLE,
    }

    impl Default for WinTrustContextGuard {
        fn default() -> Self {
            Self {
                cert_ctx: ptr::null_mut(),
                wvt_state: ptr::null_mut(),
            }
        }
    }

    impl Drop for WinTrustContextGuard {
        fn drop(&mut self) {
            // Release WinVerifyTrust state data to prevent memory leaks.
            if !self.wvt_state.is_null() {
                unsafe {
                    let mut wtd: WINTRUST_DATA = std::mem::zeroed();
                    wtd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
                    wtd.dwUIChoice = WTD_UI_NONE;
                    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    wtd.dwUnionChoice = WTD_CHOICE_FILE;
                    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                    wtd.hWVTStateData = self.wvt_state;

                    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    let _ = WinVerifyTrust(
                        ptr::null_mut(),
                        &mut action,
                        (&raw mut wtd).cast::<c_void>(),
                    );
                }
            }

            // Release the certificate context if populated.
            if !self.cert_ctx.is_null() {
                unsafe {
                    let _ = CertFreeCertificateContext(self.cert_ctx.cast::<CERT_CONTEXT>());
                }
            }
        }
    }
}

// ============================================================================
// Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    #[test]
    fn test_non_existent_file() {
        let verifier = BinarySignatureVerifier::new(32);
        let path = Path::new("C:\\Windows\\System32\\non_existent_file_xyz_123.exe");

        let level = verifier.verify(path);
        assert_eq!(
            level,
            SeSigningLevel::Unchecked,
            "Missing file cannot be opened and must return Unchecked"
        );
        assert!(!level.is_trusted(), "Missing file must not be trusted");
        assert!(
            !level.is_os_binary(),
            "Missing file must not be an OS binary"
        );

        // Diagnostic API should surface the underlying I/O error.
        assert!(matches!(
            verifier.try_verify(path),
            Err(VerifierError::Io(_))
        ));
    }

    #[test]
    fn test_interior_nul_path_rejected() {
        let verifier = BinarySignatureVerifier::new(32);
        let bad_path = Path::new("C:\\Windows\\System32\\cmd.exe\0evil.exe");

        let res = verifier.try_verify(bad_path);
        assert!(
            matches!(res, Err(VerifierError::Io(_))),
            "Paths with interior NUL bytes must be rejected by OpenOptions before reaching Win32 FFI"
        );
    }

    #[test]
    fn test_unsigned_dummy_file() {
        let verifier = BinarySignatureVerifier::new(32);
        let temp_dir = std::env::temp_dir();
        let dummy_path = temp_dir.join("signature_test_dummy_unsigned.exe");

        let mut file = std::fs::File::create(&dummy_path).expect("Failed to create dummy file");
        file.write_all(b"MZ\x90\x00\x03\x00\x00\x00InvalidSignaturePayloadData")
            .expect("Write dummy");
        drop(file);

        let level = verifier.verify(&dummy_path);
        let _ = std::fs::remove_file(&dummy_path);

        assert_eq!(
            level,
            SeSigningLevel::Unsigned,
            "Inspected file without a valid signature should be classified as Unsigned"
        );
        assert!(
            !level.is_trusted(),
            "Unsigned dummy file must not be trusted"
        );
        assert!(
            !level.is_os_binary(),
            "Unsigned dummy file must not be an OS binary"
        );
    }

    #[test]
    fn test_windows_core_binary() {
        let verifier = BinarySignatureVerifier::new(32);

        // Standard Windows binaries (usually catalog-signed or embedded OS signed)
        let candidates = [
            "C:\\Windows\\System32\\taskmgr.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\notepad.exe",
        ];

        let mut verified = false;
        for path_str in candidates {
            let path = Path::new(path_str);
            if path.exists() {
                let level = verifier.verify(path);
                assert!(level.is_trusted(), "Expected {path_str} to be trusted");
                assert!(
                    level.is_os_binary(),
                    "Expected {path_str} to be recognized as a genuine Windows OS binary"
                );
                verified = true;
                break;
            }
        }
        assert!(
            verified,
            "At least one candidate Windows system binary must exist to run this test"
        );
    }

    #[test]
    fn test_cache_hit_and_case_insensitive_deduplication() {
        let verifier = BinarySignatureVerifier::new(32);
        let lower_path = Path::new("c:\\windows\\system32\\cmd.exe");
        let upper_path = Path::new("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");

        if lower_path.exists() {
            let res1 = verifier.verify(lower_path);
            let res2 = verifier.verify(upper_path);
            assert_eq!(
                res1, res2,
                "Repeated verification must return identical cached result"
            );

            // Because the cache is keyed by hardware `FileId` rather than `PathBuf`,
            // verifying two differently-cased paths to the same file produces only 1 entry.
            let cache = verifier.signature_cache.read().unwrap();
            assert_eq!(
                cache.len(),
                1,
                "Differently-cased paths to the same physical file must share a single cache entry"
            );
        }
    }

    #[test]
    fn test_cache_invalidation_on_modification() {
        let verifier = BinarySignatureVerifier::new(32);
        let source_signed = Path::new("C:\\Windows\\System32\\cmd.exe");
        if !source_signed.exists() {
            return;
        }

        let temp_dir = std::env::temp_dir();
        let target_path = temp_dir.join("signature_test_invalidation.exe");

        // 1. Copy a known signed binary so the initial cached verdict is `Windows` (trusted).
        std::fs::copy(source_signed, &target_path).expect("Copy signed binary");
        let first = verifier.verify(&target_path);
        assert!(
            first.is_trusted(),
            "Unmodified copy of signed system binary must initially be trusted"
        );

        // 2. Modify file size & timestamp by appending an untrusted payload, breaking the hash.
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(&target_path)
                .expect("Open target");
            file.write_all(b"\nAppended payload to mutate size, timestamp, and cryptographic hash")
                .expect("Write append");
        }

        // 3. Verifier must detect the FileRevision change rather than serving the stale trusted cache.
        let second = verifier.verify(&target_path);
        let _ = std::fs::remove_file(&target_path);

        assert!(
            !second.is_trusted(),
            "Tampered binary must trigger a cache invalidation and lose trust"
        );
        assert_eq!(second, SeSigningLevel::Unsigned);
    }

    #[test]
    fn test_cache_capacity_bound_respected() {
        let max_entries = 2;
        let verifier = BinarySignatureVerifier::new(max_entries);
        let temp_dir = std::env::temp_dir();

        let mut paths = Vec::new();
        for i in 0..4 {
            let p = temp_dir.join(format!("sig_cache_bound_test_{i}.exe"));
            std::fs::write(&p, format!("dummy content {i}")).expect("Write temp file");
            let _ = verifier.verify(&p);
            paths.push(p);
        }

        for p in &paths {
            let _ = std::fs::remove_file(p);
        }

        let cache = verifier.signature_cache.read().unwrap();
        assert!(
            cache.len() <= max_entries,
            "Cache size ({}) must never exceed configured max_cache_entries ({})",
            cache.len(),
            max_entries
        );
    }

    #[test]
    fn test_thread_safety_concurrent_verification() {
        let verifier = Arc::new(BinarySignatureVerifier::new(64));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let v = Arc::clone(&verifier);
            handles.push(std::thread::spawn(move || {
                let path = Path::new("C:\\Windows\\System32\\cmd.exe");
                if path.exists() {
                    let level = v.verify(path);
                    assert!(level.is_trusted());
                }
            }));
        }

        for h in handles {
            h.join().expect("Worker thread panicked");
        }
    }
}
