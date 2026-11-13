//! Windows Binary Signature Verifier
//!
//! A stateless, thread-safe binary signature verifier using the Windows `WTGetSignatureInfo` API.
//! The verifier detects embedded Authenticode signatures, detached Windows Catalog (`.cat`)
//! signatures, and identifies native Windows OS binaries.
//!
//! Caching of verification verdicts is intentionally delegated to [`ImageCatalog`](crate::state)
//! inside [`SystemState`](crate::state::SystemState), allowing a single open [`std::fs::File`]
//! handle to be inspected once for hardware identity ([`FileId`], [`FileRevision`]), cryptographic
//! signature ([`SeSigningLevel`]), and static PE metadata ([`PeMetadata`](crate::enrichment::pe::PeMetadata)).
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

use std::{
    fmt,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle},
    },
    path::Path,
};

use crate::model::entities::binary::{FileId, FileRevision};
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
    /// * `false` - The binary is third-party signed, unsigned, or non-OS Microsoft software.
    #[inline]
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

/// Stateless, thread-safe Windows binary signature verifier backed by `WTGetSignatureInfo`.
///
/// Can inspect either an already-open [`std::fs::File`] handle (via [`Self::verify_open_file`] /
/// [`Self::try_verify_open_file`]) or open a filesystem path directly (via [`Self::verify`] /
/// [`Self::try_verify`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct BinarySignatureVerifier;

impl BinarySignatureVerifier {
    /// Initializes a new stateless binary signature verifier.
    ///
    /// Eagerly resolves the `WTGetSignatureInfo` export from `wintrust.dll` on first invocation
    /// so missing DLL issues are logged immediately during startup.
    ///
    /// # Return values
    ///
    /// * `Self` - An initialized [`BinarySignatureVerifier`] ready for concurrent verification requests.
    pub fn new() -> Self {
        if ffi::wt_get_signature_info().is_some() {
            debug!("Initialized stateless BinarySignatureVerifier");
        }
        Self
    }

    /// Verifies the digital signature of an already-open [`std::fs::File`] handle, degrading
    /// safely to [`SeSigningLevel::Unchecked`] on operational errors.
    ///
    /// Designed for background enrichment workers that open a file handle once to extract
    /// `(FileId, FileRevision)`, verify its WinTrust signature, and parse its PE headers
    /// without reopening the file on disk.
    ///
    /// # Arguments
    ///
    /// * `path` - File system path associated with `file` (used by `WTGetSignatureInfo` for catalog lookup and logging).
    /// * `file` - Reference to the open [`std::fs::File`] handle with read access.
    ///
    /// # Return values
    ///
    /// * `SeSigningLevel::Windows` - Binary is validly signed (embedded or catalog) and verified as a core Windows OS component.
    /// * `SeSigningLevel::Authenticode` - Binary carries a valid, trusted third-party or non-OS Microsoft signature.
    /// * `SeSigningLevel::Unsigned` - File was inspected, but has no signature, a tampered hash, or an untrusted root.
    /// * `SeSigningLevel::Unchecked` - Verification could not complete due to an I/O error, invalid path, or unavailable API.
    pub fn verify_open_file(&self, path: &Path, file: &File) -> SeSigningLevel {
        self.try_verify_open_file(path, file).unwrap_or_else(|err| {
            warn!(
                "Verification could not complete for '{}': {err}. Defaulting to Unchecked.",
                path.display()
            );
            SeSigningLevel::Unchecked
        })
    }

    /// Performs diagnostic cryptographic signature verification on an already-open [`std::fs::File`] handle.
    ///
    /// Delegates directly to `WTGetSignatureInfo` using the borrowed Win32 handle from `file`,
    /// guaranteeing that the same physical kernel file object is inspected without TOCTOU path re-resolution.
    ///
    /// # Arguments
    ///
    /// * `path` - File system path associated with `file`.
    /// * `file` - Reference to the open [`std::fs::File`] handle with read access.
    ///
    /// # Return values
    ///
    /// * `Ok(SeSigningLevel)` - Cryptographic inspection completed and produced a signing level verdict.
    /// * `Err(VerifierError::ApiUnavailable)` - `wintrust.dll` or `WTGetSignatureInfo` could not be resolved on the host OS.
    /// * `Err(VerifierError::Io)` - `path` contained interior NUL bytes.
    /// * `Err(VerifierError::WinTrust)` - `WTGetSignatureInfo` failed with a negative `HRESULT` status code.
    pub fn try_verify_open_file(
        &self,
        path: &Path,
        file: &File,
    ) -> Result<SeSigningLevel, VerifierError> {
        trace!("Starting signature verification for '{}'", path.display());

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
            "Verified '{}': level={level:?}, state={:?}, kind={:?}, is_os_binary={}",
            path.display(),
            report.state,
            report.kind,
            report.is_os_binary
        );

        Ok(level)
    }

    /// Verifies the digital signature of a binary file on disk by path, degrading safely on operational errors.
    ///
    /// Opens the file with permissive sharing flags (`FILE_SHARE_READ | WRITE | DELETE`) and
    /// delegates to [`Self::verify_open_file`].
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

    /// Opens a target binary file by path and performs diagnostic cryptographic signature verification.
    ///
    /// Opens the file handle with permissive sharing flags (`FILE_SHARE_READ | WRITE | DELETE`)
    /// to avoid sharing violations when inspecting actively running executables or DLLs, then
    /// delegates to [`Self::try_verify_open_file`].
    ///
    /// # Arguments
    ///
    /// * `path` - File system path to the target binary to inspect.
    ///
    /// # Return values
    ///
    /// * `Ok(SeSigningLevel)` - Cryptographic inspection completed and produced a signing level verdict.
    /// * `Err(VerifierError::ApiUnavailable)` - `wintrust.dll` or `WTGetSignatureInfo` could not be resolved on the host OS.
    /// * `Err(VerifierError::Io)` - Target file could not be opened or path contained interior NUL bytes.
    /// * `Err(VerifierError::WinTrust)` - `WTGetSignatureInfo` failed with a negative `HRESULT` status code.
    pub fn try_verify<P: AsRef<Path>>(&self, path: P) -> Result<SeSigningLevel, VerifierError> {
        let path = path.as_ref();

        // Rust's `OpenOptions` automatically converts the path to UTF-16, rejects interior NUL
        // bytes, invokes `CreateFileW`, and wraps the handle in `std::fs::File` (which guarantees
        // `CloseHandle` on drop). Permissive share flags (`READ | WRITE | DELETE`) are critical
        // to avoid sharing violations when inspecting actively running executables or DLLs.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)?;

        self.try_verify_open_file(path, &file)
    }
}

/// Extracts the physical [`FileId`] (`VolumeSerialNumber` + `FileIndex`) and [`FileRevision`]
/// (`FileSize` + `LastWriteTime`) directly from an open [`std::fs::File`] via `GetFileInformationByHandle`.
///
/// Used by the background enrichment worker to uniquely identify physical files across
/// differently-cased paths, hardlinks, or symlinks, and to detect in-place file modifications.
///
/// # Arguments
///
/// * `file` - Reference to an open [`std::fs::File`] handle.
///
/// # Return values
///
/// * `Ok((FileId, FileRevision))` - Hardware identity and modification fingerprint of the open file.
/// * `Err(io::Error)` - `GetFileInformationByHandle` failed; contains the underlying Win32 OS error.
pub fn query_file_identity(file: &File) -> io::Result<(FileId, FileRevision)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let id = FileId::new(
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64),
    );
    let rev = FileRevision::new(
        ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64),
        ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | (info.ftLastWriteTime.dwLowDateTime as u64),
    );

    Ok((id, rev))
}

/// Encapsulates all `unsafe` WinTrust data structures, dynamic symbol resolution, and
/// RAII resource cleanup behind a safe internal API (`verify_open_file`).
pub mod ffi {
    use std::{
        ffi::c_void,
        io,
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
        /// [OUT] `SIGNATURE_INFO_VALUE` enum (`0` = `SIV_FALSE`, `1` = `SIV_TRUE`, `2` = `SIV_UNKNOWN`):
        /// - `1` (`SIV_TRUE`) = The binary is an authentic Microsoft Windows OS component
        ///                      (chains to the Microsoft Root and contains the Windows OS EKU).
        /// - `0` / `2`        = Third-party signed, unsigned, or non-OS Microsoft software.
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

        let wide_chars: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide_chars.contains(&0) {
            return Err(VerifierError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file path contains an interior NUL byte",
            )));
        }
        let mut wpath = wide_chars;
        wpath.push(0);

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

        // Note: In Wine/Windows wintrust.h, `SIGNATURE_INFO::is_os_binary` is a `SIGNATURE_INFO_VALUE`
        // (`0` = SIV_FALSE, `1` = SIV_TRUE, `2` = SIV_UNKNOWN). Only `1` (`SIV_TRUE`) indicates a
        // verified Windows OS binary; however, when running inside restricted sandboxes where
        // CatRoot catalog lookups return SIV_FALSE/SIV_UNKNOWN for embedded certs, we check `== 1`.
        Ok(SignatureReport {
            state: SignatureState::from(sig_info.signature_state),
            kind: SignatureKind::from(sig_info.signature_t),
            is_os_binary: sig_info.is_os_binary == 1,
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
        let verifier = BinarySignatureVerifier::new();
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
        let verifier = BinarySignatureVerifier::new();
        let bad_path = Path::new("C:\\Windows\\System32\\cmd.exe\0evil.exe");

        let res = verifier.try_verify(bad_path);
        assert!(
            matches!(res, Err(VerifierError::Io(_))),
            "Paths with interior NUL bytes must be rejected before reaching Win32 FFI"
        );
    }

    #[test]
    fn test_unsigned_dummy_file() {
        let verifier = BinarySignatureVerifier::new();
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
    fn test_windows_core_binary_and_open_file_verification() {
        let verifier = BinarySignatureVerifier::new();

        // Standard Windows binaries (embedded OS signed or catalog signed)
        let candidates = [
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\System32\\cmd.exe",
        ];

        let mut verified = false;
        for path_str in candidates {
            let path = Path::new(path_str);
            if path.exists() {
                let file = OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(path)
                    .expect("Open system binary");

                let level_from_handle = verifier.verify_open_file(path, &file);
                let level_from_path = verifier.verify(path);

                assert_eq!(
                    level_from_handle, level_from_path,
                    "Verifying via open &File and via &Path must yield the exact same SeSigningLevel"
                );
                assert!(
                    level_from_handle.is_trusted(),
                    "Expected {path_str} to be cryptographically trusted, got {level_from_handle:?}"
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
    fn test_query_file_identity_case_insensitive_and_revision_tracking() {
        let lower_path = Path::new("c:\\windows\\system32\\cmd.exe");
        let upper_path = Path::new("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");

        if lower_path.exists() {
            let f1 = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(lower_path)
                .unwrap();
            let f2 = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(upper_path)
                .unwrap();

            let (id1, rev1) = query_file_identity(&f1).expect("Query f1 identity");
            let (id2, rev2) = query_file_identity(&f2).expect("Query f2 identity");

            assert_eq!(
                id1, id2,
                "Differently-cased paths to the same physical file must resolve to identical FileId"
            );
            assert_eq!(
                rev1, rev2,
                "Unmodified file handles must resolve to identical FileRevision"
            );
        }
    }

    #[test]
    fn test_tampered_binary_loses_trust_and_changes_revision() {
        let verifier = BinarySignatureVerifier::new();
        let source_signed = Path::new("C:\\Windows\\System32\\cmd.exe");
        if !source_signed.exists() {
            return;
        }

        let temp_dir = std::env::temp_dir();
        let target_path = temp_dir.join("signature_test_tamper.exe");

        // 1. Copy a known signed binary so the initial verdict is trusted.
        std::fs::copy(source_signed, &target_path).expect("Copy signed binary");
        let (id_before, rev_before, level_before) = {
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&target_path)
                .unwrap();
            let (id, rev) = query_file_identity(&file).unwrap();
            let lvl = verifier.verify_open_file(&target_path, &file);
            (id, rev, lvl)
        };
        assert!(level_before.is_trusted());

        // 2. Modify file size & content by appending an untrusted payload, breaking the hash.
        {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(&target_path)
                .expect("Open target");
            file.write_all(b"\nAppended payload to mutate size and cryptographic hash")
                .expect("Write append");
        }

        // 3. Re-inspect open handle: FileId stays the same, FileRevision changes, and trust is lost.
        let (id_after, rev_after, level_after) = {
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&target_path)
                .unwrap();
            let (id, rev) = query_file_identity(&file).unwrap();
            let lvl = verifier.verify_open_file(&target_path, &file);
            (id, rev, lvl)
        };
        let _ = std::fs::remove_file(&target_path);

        assert_eq!(id_before, id_after, "In-place modification keeps the same physical FileId");
        assert_ne!(rev_before, rev_after, "Appending bytes must change FileRevision");
        assert!(!level_after.is_trusted(), "Tampered binary must lose trust");
        assert_eq!(level_after, SeSigningLevel::Unsigned);
    }

    #[test]
    fn test_thread_safety_concurrent_verification() {
        let verifier = Arc::new(BinarySignatureVerifier::new());
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
