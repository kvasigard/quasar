use core::ffi::CStr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};
use wdk_sys::{
    HANDLE, NTSTATUS, PEPROCESS, PUNICODE_STRING,
    ntddk::{
        IoGetCurrentProcess, MmGetSystemRoutineAddress, PsGetCurrentProcessId, PsGetProcessId,
        SeLocateProcessImageName,
    },
};

use crate::foundation::string::init_unicode_string;

// PsGetProcessImageFileName and PsGetProcessSessionId are exported by ntoskrnl.exe, but not exposed in wdk-sys headers.
unsafe extern "system" {
    pub fn PsGetProcessImageFileName(Process: PEPROCESS) -> *const i8;
    pub fn PsGetProcessSessionId(Process: PEPROCESS) -> u32;
}

/// Strongly-typed Windows Code Integrity process signing level taxonomy.
///
/// Encapsulates the cryptographic verification status and policy under which
/// the process executable image was signed and verified by the kernel loader.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SeSigningLevel(pub u8);

impl SeSigningLevel {
    /// Image has not been evaluated by Code Integrity.
    pub(crate) const UNCHECKED: Self = Self(0x00);
    /// Image is unsigned or has an invalid/corrupted signature.
    pub(crate) const UNSIGNED: Self = Self(0x01);
    /// Signed by an Enterprise policy certificate.
    pub(crate) const ENTERPRISE: Self = Self(0x02);
    /// Signed with a test/developer certificate (test-signing enabled).
    pub(crate) const DEVELOPER: Self = Self(0x03);
    /// Standard commercial Authenticode signature (third-party software).
    pub(crate) const AUTHENTICODE: Self = Self(0x04);
    /// Signed by the Windows Store / Universal Windows Platform policy.
    pub(crate) const STORE: Self = Self(0x05);
    /// Signed by an anticheat vendor recognized by the kernel.
    pub(crate) const ANTICHEAT: Self = Self(0x07);
    /// Signed by Microsoft Production PCA (standard Microsoft application).
    pub(crate) const MICROSOFT: Self = Self(0x08);
    /// Core Windows operating system component (signed by Windows PCA).
    pub(crate) const WINDOWS: Self = Self(0x0C);
    /// Microsoft-approved Antimalware component (ELAM / PPL-Antimalware).
    pub(crate) const ANTIMALWARE: Self = Self(0x0E);
    /// Windows Trusted Computing Base (highest OS tier, e.g. kernel, smss, lsass).
    pub(crate) const WINDOWS_TCB: Self = Self(0x10);

    /// Checks whether the binary has a trusted Microsoft or Windows operating system signature.
    ///
    /// # Return values
    ///
    /// * `true` - Signed by Microsoft Production PCA, Windows PCA, or Antimalware PCA.
    /// * `false` - Unsigned, test-signed, or third-party Authenticode.
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn is_microsoft_or_higher(self) -> bool {
        self.0 >= Self::MICROSOFT.0
    }
}

type FnPsGetProcessSignatureLevel = unsafe extern "system" fn(PEPROCESS) -> u8;

const SENTINEL_UNAVAILABLE: *mut () = 1 as *mut ();
static PS_GET_PROCESS_SIGNATURE_LEVEL: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

fn resolve_ps_get_process_signature_level() -> Option<FnPsGetProcessSignatureLevel> {
    let routine_ptr = PS_GET_PROCESS_SIGNATURE_LEVEL.load(Ordering::Acquire);

    if routine_ptr == SENTINEL_UNAVAILABLE {
        return None;
    }

    if !routine_ptr.is_null() {
        return unsafe { Some(core::mem::transmute(routine_ptr)) };
    }

    let mut routine_name = unsafe {
        init_unicode_string(windows_sys::w!("PsGetProcessSignatureLevel"))
    };
    let resolved = unsafe { MmGetSystemRoutineAddress(&mut routine_name) };

    if resolved.is_null() {
        PS_GET_PROCESS_SIGNATURE_LEVEL.store(SENTINEL_UNAVAILABLE, Ordering::Release);
        None
    } else {
        PS_GET_PROCESS_SIGNATURE_LEVEL.store(resolved as *mut (), Ordering::Release);
        unsafe { Some(core::mem::transmute(resolved)) }
    }
}

/// Protection type indicating whether a process is Protected (PP) or ProtectedLight (PPL).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PsProtectedType {
    /// Unprotected process.
    None = 0,
    /// Protected Process Light (PPL).
    ProtectedLight = 1,
    /// Full Protected Process (PP).
    Protected = 2,
}

/// Signer classification identifying the authority that authorized process protection.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PsProtectedSigner {
    /// Unprotected or unrecognized signer.
    None = 0,
    /// Authenticode signer.
    Authenticode = 1,
    /// Dynamic Code Generation signer.
    CodeGen = 2,
    /// Antimalware / Early Launch Antimalware (ELAM) signer.
    Antimalware = 3,
    /// Local Security Authority (LSA) signer.
    Lsa = 4,
    /// Windows core operating system signer.
    Windows = 5,
    /// Windows Trusted Computing Base (WinTcb) signer.
    WinTcb = 6,
    /// Windows System component signer.
    WinSystem = 7,
    /// App package signer.
    App = 8,
}

/// Strongly-typed wrapper around the Windows kernel `PS_PROTECTION` byte.
///
/// Encapsulates the protection type, audit mode, and signer tier enforced by the kernel executive.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PsProtection(pub u8);

impl PsProtection {
    /// Unprotected process (`0x00`).
    pub(crate) const NONE: Self = Self(0);

    /// Extracts the protection type (Bits 0..2).
    ///
    /// # Return values
    ///
    /// * `PsProtectedType` - Protection classification (None, ProtectedLight, or Protected).
    #[inline(always)]
    pub(crate) fn protection_type(self) -> PsProtectedType {
        match self.0 & 0x07 {
            1 => PsProtectedType::ProtectedLight,
            2 => PsProtectedType::Protected,
            _ => PsProtectedType::None,
        }
    }

    /// Checks if the process is running in Audit mode (Bit 3).
    ///
    /// # Return values
    ///
    /// * `true` - Operating in audit mode (violations logged rather than blocked).
    /// * `false` - Normal enforcement mode.
    #[inline(always)]
    pub(crate) fn is_audit(self) -> bool {
        (self.0 & 0x08) != 0
    }

    /// Extracts the signer tier (Bits 4..7).
    ///
    /// # Return values
    ///
    /// * `PsProtectedSigner` - Signer authority classification (e.g. Lsa, Windows, WinTcb, Antimalware).
    #[inline(always)]
    pub(crate) fn signer(self) -> PsProtectedSigner {
        match (self.0 >> 4) & 0x0F {
            1 => PsProtectedSigner::Authenticode,
            2 => PsProtectedSigner::CodeGen,
            3 => PsProtectedSigner::Antimalware,
            4 => PsProtectedSigner::Lsa,
            5 => PsProtectedSigner::Windows,
            6 => PsProtectedSigner::WinTcb,
            7 => PsProtectedSigner::WinSystem,
            8 => PsProtectedSigner::App,
            _ => PsProtectedSigner::None,
        }
    }

    /// Checks whether the process has any active protection (PP or PPL).
    ///
    /// # Return values
    ///
    /// * `true` - Process is running with ProtectedLight (PPL) or Protected (PP).
    /// * `false` - Process is unprotected.
    #[inline(always)]
    pub(crate) fn is_protected(self) -> bool {
        (self.0 & 0x07) != 0
    }
}

type FnPsGetProcessProtection = unsafe extern "system" fn(PEPROCESS) -> u8;

static PS_GET_PROCESS_PROTECTION: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

fn resolve_ps_get_process_protection() -> Option<FnPsGetProcessProtection> {
    let routine_ptr = PS_GET_PROCESS_PROTECTION.load(Ordering::Acquire);

    if routine_ptr == SENTINEL_UNAVAILABLE {
        return None;
    }

    if !routine_ptr.is_null() {
        return unsafe { Some(core::mem::transmute(routine_ptr)) };
    }

    let mut routine_name = unsafe {
        init_unicode_string(windows_sys::w!("PsGetProcessProtection"))
    };
    let resolved = unsafe { MmGetSystemRoutineAddress(&mut routine_name) };

    if resolved.is_null() {
        PS_GET_PROCESS_PROTECTION.store(SENTINEL_UNAVAILABLE, Ordering::Release);
        None
    } else {
        PS_GET_PROCESS_PROTECTION.store(resolved as *mut (), Ordering::Release);
        unsafe { Some(core::mem::transmute(resolved)) }
    }
}

/// A zero-cost, non-owning handle to an active Windows EPROCESS.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Eprocess {
    raw: NonNull<wdk_sys::_EPROCESS>,
}

impl Eprocess {
    /// Creates a wrapper from a raw `PEPROCESS` pointer.
    ///
    /// Validates that the supplied pointer is non-null before constructing the wrapper.
    ///
    /// # Safety
    /// The caller must ensure `ptr` is non-null and points to an object that
    /// remains valid for the duration of the wrapper's usage.
    ///
    /// # Arguments
    ///
    /// * `ptr` - Raw kernel `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `Some(Self)` - Valid non-null process wrapper.
    /// * `None` - Supplied pointer was null.
    #[inline]
    pub(crate) unsafe fn from_raw(ptr: PEPROCESS) -> Option<Self> {
        NonNull::new(ptr as *mut wdk_sys::_EPROCESS).map(|raw| Self { raw })
    }

    /// Returns the `Eprocess` for the current execution context (the caller).
    ///
    /// Retrieves the current process pointer using `IoGetCurrentProcess`.
    ///
    /// # Return values
    ///
    /// * `Self` - Non-null process wrapper for the calling thread's process.
    #[inline]
    pub(crate) fn current() -> Self {
        let ptr = unsafe { IoGetCurrentProcess() };
        // SAFETY: IoGetCurrentProcess() is guaranteed never to return NULL.
        unsafe {
            Self {
                raw: NonNull::new_unchecked(ptr as *mut _),
            }
        }
    }

    /// Returns the PID for this process instance.
    ///
    /// Invokes `PsGetProcessId` on the wrapped process object.
    ///
    /// # Return values
    ///
    /// * `usize` - Numerical Process ID.
    #[inline]
    pub(crate) fn pid(&self) -> usize {
        let handle: HANDLE = unsafe { PsGetProcessId(self.as_raw()) };
        handle as usize
    }

    /// Returns the PID of the current execution context.
    ///
    /// Invokes `PsGetCurrentProcessId`.
    ///
    /// # Return values
    ///
    /// * `usize` - Current executing Process ID.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn current_pid() -> usize {
        let handle: HANDLE = unsafe { PsGetCurrentProcessId() };
        handle as usize
    }

    /// Returns the Terminal Services / Remote Desktop Session ID for this process.
    ///
    /// Invokes `PsGetProcessSessionId`. Core system services like LSASS always reside in Session 0.
    ///
    /// # Return values
    ///
    /// * `u32` - Session ID (e.g. `0` for system session).
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn session_id(&self) -> u32 {
        unsafe { PsGetProcessSessionId(self.as_raw()) }
    }

    /// Returns the Code Integrity signature level of this process.
    ///
    /// Dynamically resolves and invokes `PsGetProcessSignatureLevel` exported by `ntoskrnl.exe`.
    /// If the export is unresolvable or the image is unsigned, returns `SeSigningLevel::UNSIGNED`.
    ///
    /// # Return values
    ///
    /// * `SeSigningLevel` - Authenticode signing level classification.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn signature_level(&self) -> SeSigningLevel {
        if let Some(func) = resolve_ps_get_process_signature_level() {
            let level = unsafe { func(self.as_raw()) };
            SeSigningLevel(level)
        } else {
            SeSigningLevel::UNSIGNED
        }
    }

    /// Returns the Mandatory Integrity Level of this process's primary token.
    ///
    /// Safely references the primary token via `TokenGuard` and queries `TokenIntegrityLevel`.
    /// Returns `IntegrityLevel::UNTRUSTED` if token resolution fails.
    ///
    /// # Return values
    ///
    /// * `IntegrityLevel` - Mandatory integrity tier classification (e.g. Low, Medium, High, System).
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn integrity_level(&self) -> super::token::IntegrityLevel {
        super::token::TokenGuard::from_process(self.as_raw())
            .map(|token| token.integrity_level())
            .unwrap_or(super::token::IntegrityLevel::UNTRUSTED)
    }

    /// Returns the Process Protection Level (PPL / PP) of this process.
    ///
    /// Dynamically resolves and invokes `PsGetProcessProtection` exported by `ntoskrnl.exe`.
    /// If the export is unresolvable or lookup fails, returns `PsProtection::NONE`.
    ///
    /// # Return values
    ///
    /// * `PsProtection` - Encapsulated process protection type, audit status, and signer tier.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn protection(&self) -> PsProtection {
        if let Some(func) = resolve_ps_get_process_protection() {
            let byte = unsafe { func(self.as_raw()) };
            PsProtection(byte)
        } else {
            PsProtection::NONE
        }
    }

    /// Returns the 15-character truncated short image name (e.g., "lsass.exe").
    ///
    /// Reads from `EPROCESS::ImageFileName` which is limited to 15 characters plus null terminator.
    ///
    /// # Return values
    ///
    /// * `&CStr` - Null-terminated ASCII image file name slice.
    #[inline]
    pub(crate) fn short_name(&self) -> &CStr {
        unsafe {
            let name_ptr = PsGetProcessImageFileName(self.as_raw());
            if name_ptr.is_null() {
                c""
            } else {
                CStr::from_ptr(name_ptr)
            }
        }
    }

    /// Retrieves the full NT path of the process executable (e.g. `\Device\HarddiskVolume3\...`).
    ///
    /// Queries `SeLocateProcessImageName` to resolve the full NT image path.
    /// The caller must free the resulting `UNICODE_STRING` buffer using `ExFreePool`.
    ///
    /// # Return values
    ///
    /// * `Ok(*mut wdk_sys::_UNICODE_STRING)` - Allocated unicode string containing full image path.
    /// * `Err(NTSTATUS)` - Query failed or image path unresolvable.
    #[allow(dead_code)]
    pub(crate) fn full_image_path(&self) -> Result<*mut wdk_sys::_UNICODE_STRING, NTSTATUS> {
        let mut unicode_str_ptr: PUNICODE_STRING = core::ptr::null_mut();
        let status = unsafe {
            SeLocateProcessImageName(self.as_raw(), &mut unicode_str_ptr as *mut PUNICODE_STRING)
        };

        if status >= 0 && !unicode_str_ptr.is_null() {
            Ok(unicode_str_ptr)
        } else {
            Err(status)
        }
    }

    /// Returns the raw `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `PEPROCESS` - Underlying raw kernel process pointer.
    #[inline]
    pub(crate) fn as_raw(&self) -> PEPROCESS {
        self.raw.as_ptr() as PEPROCESS
    }
}
