//! Process security token inspection and RAII lifecycle wrappers.

use wdk_sys::{
    TOKEN_MANDATORY_LABEL,
    ntddk::{
        ObfDereferenceObject, PsReferencePrimaryToken, RtlSubAuthorityCountSid, RtlSubAuthoritySid,
        SeQueryInformationToken,
    },
};

use super::pool::PoolGuard;

/// Strongly-typed Windows Mandatory Integrity Control (MIC) privilege tier.
///
/// Represents the sub-authority Relative Identifier (RID) of the mandatory label
/// Security Identifier (`S-1-16-XXXX`) assigned to a process security token.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct IntegrityLevel(pub u32);

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
    /// Acquires an executive object reference via `PsReferencePrimaryToken`.
    ///
    /// # Arguments
    ///
    /// * `process` - Raw kernel `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `Some(Self)` - Valid non-null token guard wrapping the referenced token.
    /// * `None` - Process token unresolvable or NULL.
    pub(crate) fn from_process(process: wdk_sys::PEPROCESS) -> Option<Self> {
        let token = unsafe { PsReferencePrimaryToken(process) };
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
    /// Invokes `SeQueryInformationToken` with `TokenIntegrityLevel`, parses the returned
    /// mandatory label SID, and safely deallocates the paged pool buffer using `PoolGuard`.
    ///
    /// # Return values
    ///
    /// * `IntegrityLevel` - Mandatory integrity tier classification (e.g. Low, Medium, High, System).
    pub(crate) fn integrity_level(&self) -> IntegrityLevel {
        let mut info_ptr: wdk_sys::PVOID = core::ptr::null_mut();
        let status = unsafe {
            SeQueryInformationToken(
                self.as_ptr(),
                wdk_sys::_TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
                &mut info_ptr,
            )
        };

        if status < 0 || info_ptr.is_null() {
            return IntegrityLevel::UNTRUSTED;
        }

        // SAFETY: SeQueryInformationToken allocates memory from paged pool on success.
        // PoolGuard guarantees that ExFreePool is invoked upon drop.
        let pool_guard =
            match unsafe { PoolGuard::<TOKEN_MANDATORY_LABEL>::from_raw(info_ptr as *mut _) } {
                Some(guard) => guard,
                None => return IntegrityLevel::UNTRUSTED,
            };

        let sid = pool_guard.Label.Sid;
        if sid.is_null() {
            return IntegrityLevel::UNTRUSTED;
        }

        let sub_authority_count = unsafe { *RtlSubAuthorityCountSid(sid) };
        if sub_authority_count == 0 {
            return IntegrityLevel::UNTRUSTED;
        }

        let rid = unsafe { *RtlSubAuthoritySid(sid, (sub_authority_count - 1) as u32) };
        IntegrityLevel(rid)
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        unsafe { ObfDereferenceObject(self.0) };
    }
}
