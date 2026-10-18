//! Process security token inspection and RAII lifecycle wrappers.

use wdk_sys::ntddk::{ObfDereferenceObject, PsReferencePrimaryToken, SeQueryInformationToken};

/// Strongly-typed Windows Mandatory Integrity Control (MIC) privilege tier.
///
/// Represents the sub-authority Relative Identifier (RID) of the mandatory label
/// Security Identifier (`S-1-16-XXXX`) assigned to a process security token.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct IntegrityLevel(pub u32);

#[allow(dead_code)]
impl IntegrityLevel {
    /// Anonymous session or deeply restricted sandbox (`S-1-16-0x0000`).
    pub(crate) const UNTRUSTED: Self = Self(0x0000);
    /// Low-integrity sandbox (e.g. Edge/Chrome renderer, Office Protected View; `S-1-16-0x1000`).
    pub(crate) const LOW: Self = Self(0x1000);
    /// Standard non-elevated desktop user (`S-1-16-0x2000`).
    pub(crate) const MEDIUM: Self = Self(0x2000);
    /// Intermediate Medium-Plus integrity (e.g. isolated processes; `S-1-16-0x2100`).
    pub(crate) const MEDIUM_PLUS: Self = Self(0x2100);
    /// Elevated administrator context with UAC elevation (`S-1-16-0x3000`).
    pub(crate) const HIGH: Self = Self(0x3000);
    /// Operating system core service context (`NT AUTHORITY\SYSTEM`; `S-1-16-0x4000`).
    pub(crate) const SYSTEM: Self = Self(0x4000);
    /// Protected operating system process token (`S-1-16-0x5000`).
    pub(crate) const PROTECTED: Self = Self(0x5000);

    /// Checks whether the token has `SYSTEM` integrity or higher.
    ///
    /// # Return values
    ///
    /// * `true` - Token integrity RID is greater than or equal to `0x4000`.
    /// * `false` - Token integrity RID is lower than `SYSTEM`.
    #[inline(always)]
    pub(crate) fn is_system_or_higher(self) -> bool {
        self.0 >= Self::SYSTEM.0
    }

    /// Checks whether the token has elevated `HIGH` (Administrator) integrity or higher.
    ///
    /// # Return values
    ///
    /// * `true` - Token integrity RID is greater than or equal to `0x3000`.
    /// * `false` - Standard non-elevated user or sandbox.
    #[inline(always)]
    pub(crate) fn is_elevated_or_higher(self) -> bool {
        self.0 >= Self::HIGH.0
    }

    /// Checks whether the token is at or below standard user `MEDIUM` integrity.
    ///
    /// # Return values
    ///
    /// * `true` - Standard user, sandbox, or untrusted token (`<= 0x2000`).
    /// * `false` - Elevated administrator or SYSTEM token.
    #[inline(always)]
    pub(crate) fn is_medium_or_lower(self) -> bool {
        self.0 <= Self::MEDIUM.0
    }
}

/// An RAII guard ensuring proper reference counting for an executive token object.
///
/// Automatically invokes `ObfDereferenceObject` when dropped to prevent kernel memory leaks.
pub(crate) struct TokenGuard(*mut core::ffi::c_void);

impl TokenGuard {
    /// References the primary token of the specified process.
    ///
    /// Acquires an executive object reference via `PsReferencePrimaryToken` at `<= APC_LEVEL`.
    ///
    /// # Arguments
    ///
    /// * `process` - Valid `Eprocess` wrapper.
    ///
    /// # Return values
    ///
    /// * `Some(Self)` - Valid non-null token guard wrapping the referenced token.
    /// * `None` - Process token unresolvable, NULL, or IRQL > `APC_LEVEL`.
    pub(crate) fn from_process(process: &super::eprocess::Eprocess) -> Option<Self> {
        if crate::foundation::irql::ensure_max_irql(wdk_sys::APC_LEVEL as u8).is_err() {
            return None;
        }
        let token = unsafe { PsReferencePrimaryToken(process.as_raw()) };
        if token.is_null() {
            None
        } else {
            Some(Self(token))
        }
    }

    /// Returns the raw pointer to the underlying kernel token object.
    ///
    /// # Return values
    ///
    /// * `*mut core::ffi::c_void` - Raw token object pointer.
    #[inline(always)]
    pub(crate) fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0
    }

    /// Queries the Mandatory Integrity Level of this token.
    ///
    /// Invokes `SeQueryInformationToken` with `TokenIntegrityLevel`.
    ///
    /// Note: The kernel routine `SeQueryInformationToken` for `TokenIntegrityLevel` writes the
    /// mandatory label sub-authority RID directly into `*TokenInformation` as a pointer-sized
    /// value (`PVOID`, 8 bytes on x64) without allocating pool memory. Passing a pointer-sized
    /// `PVOID` variable prevents 8-byte stack smash corruption on 64-bit targets.
    ///
    /// # Return values
    ///
    /// * `IntegrityLevel` - Mandatory integrity tier classification (e.g. Low, Medium, High, System).
    pub(crate) fn integrity_level(&self) -> IntegrityLevel {
        if crate::foundation::irql::ensure_max_irql(wdk_sys::APC_LEVEL as u8).is_err() {
            return IntegrityLevel::UNTRUSTED;
        }

        let mut info_ptr: wdk_sys::PVOID = core::ptr::null_mut();
        let status = unsafe {
            SeQueryInformationToken(
                self.as_ptr(),
                wdk_sys::_TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
                &raw mut info_ptr,
            )
        };

        if !wdk::nt_success(status) {
            return IntegrityLevel::UNTRUSTED;
        }

        IntegrityLevel(info_ptr as usize as u32)
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe { ObfDereferenceObject(self.0) };
    }
}
