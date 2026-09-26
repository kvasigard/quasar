//! Models and definitions for Object Manager callback targets and operations.

use wdk_sys::{
    ExDesktopObjectType, OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE,
    POBJECT_TYPE, PVOID, PsProcessType, PsThreadType,
};

/// Default filter altitude for antivirus and monitoring drivers.
pub const DEFAULT_ALTITUDE: *const u16 = windows_sys::w!("320013");

/// Supported kernel object types for callback registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackType {
    /// Process object callback (`PsProcessType`).
    ///
    /// Intercepts handle operations against process objects, such as `OpenProcess`.
    /// The target object in operation information is a `PEPROCESS`. Use this callback
    /// to protect target processes from termination, memory dumping, or code injection
    /// by stripping permissions such as `PROCESS_TERMINATE`, `PROCESS_VM_READ`, and
    /// `PROCESS_VM_WRITE`.
    ///
    /// Do not restrict access to critical operating system binaries such as csrss.exe
    /// or services.exe. Also check the `KernelHandle` flag before modifying masks, as
    /// kernel-mode callers should generally remain unrestricted to avoid system instability.
    Process,

    /// Thread object callback (`PsThreadType`).
    ///
    /// Intercepts handle operations against thread objects, such as `OpenThread`.
    /// The target object in operation information is a `PETHREAD`. Use this callback
    /// to block remote thread creation and thread hijacking by stripping permissions
    /// such as `THREAD_SET_CONTEXT`, `THREAD_SUSPEND_RESUME`, and `THREAD_TERMINATE`.
    ///
    /// To identify the parent process owning the target thread, resolve the process
    /// pointer using `IoThreadToProcess`.
    Thread,

    /// Desktop object callback (`ExDesktopObjectType`).
    ///
    /// Intercepts operations targeting desktop objects under the Win32k subsystem.
    /// This callback is typically used in sandboxing and isolation engines to prevent
    /// desktop switching, screen scraping, and cross-desktop window message injection.
    ///
    /// Because the desktop subsystem is closely tied to user session stability, avoid
    /// altering desktop masks unless strictly enforcing isolated display boundaries.
    DesktopHandle,
}

impl CallbackType {
    /// Resolves the raw pointer to the kernel exported object type.
    ///
    /// # Safety
    ///
    /// Kernel object types are global exports initialized by NTOSKRNL during startup.
    pub unsafe fn as_raw_object_type(self) -> *mut POBJECT_TYPE {
        // SAFETY: The kernel initializes these globals before driver entry.
        unsafe {
            match self {
                Self::Process => PsProcessType,
                Self::Thread => PsThreadType,
                Self::DesktopHandle => ExDesktopObjectType,
            }
        }
    }
}

/// Operation mask specifying handle creation, handle duplication, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Intercepts handle creation requests such as `OpenProcess` or `OpenThread`.
    Create,

    /// Intercepts handle duplication requests such as `DuplicateHandle`.
    Duplicate,

    /// Intercepts both handle creation and handle duplication.
    ///
    /// This option is strongly recommended for security drivers so that callers cannot
    /// bypass pre-operation restrictions by duplicating an existing unrestricted handle.
    All,
}

impl OperationType {
    /// Returns the corresponding WDK bitmask value.
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Create => OB_OPERATION_HANDLE_CREATE,
            Self::Duplicate => OB_OPERATION_HANDLE_DUPLICATE,
            Self::All => OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        }
    }
}

/// Pre-operation callback routine invoked by the Windows Object Manager.
///
/// Runs at `PASSIVE_LEVEL` in the context of the thread attempting to open or duplicate
/// the handle. You may inspect the target object and strip unwanted access masks from
/// `DesiredAccess` to protect processes or threads.
///
/// Never grant permissions beyond what the caller requested. Avoid calling APIs that open
/// handles inside this routine to prevent infinite callback recursion. If `KernelHandle`
/// is non-zero, the request originated from the kernel and should generally remain
/// unrestricted to avoid system instability. Always return `OB_PREOP_SUCCESS`.
pub type PreOperationCallbackFn = unsafe extern "system" fn(
    registration_context: PVOID,
    operation_information: wdk_sys::POB_PRE_OPERATION_INFORMATION,
) -> wdk_sys::OB_PREOP_CALLBACK_STATUS;

/// Post-operation callback routine invoked after the handle has been created or duplicated.
///
/// Runs at `PASSIVE_LEVEL` after the Object Manager has generated the handle. Post-operation
/// callbacks cannot modify access masks or fail the operation, making them suitable for
/// auditing, telemetry, and logging.
///
/// Always check the `ReturnStatus` field inside the operation information structure before
/// inspecting granted access rights, as the handle creation may have failed.
pub type PostOperationCallbackFn = unsafe extern "system" fn(
    registration_context: PVOID,
    operation_information: wdk_sys::POB_POST_OPERATION_INFORMATION,
);

/// Defines an individual object callback hook.
pub struct Callback {
    pub kind: CallbackType,
    pub operation: OperationType,
    pub pre_operation: Option<PreOperationCallbackFn>,
    pub post_operation: Option<PostOperationCallbackFn>,
}

impl Callback {
    /// Creates a new callback configuration.
    ///
    /// At least one callback function should be provided. Supplying both allows synchronous
    /// access restriction before creation and telemetry logging after the handle is generated.
    pub const fn new(
        kind: CallbackType,
        operation: OperationType,
        pre_operation: Option<PreOperationCallbackFn>,
        post_operation: Option<PostOperationCallbackFn>,
    ) -> Self {
        Self {
            kind,
            operation,
            pre_operation,
            post_operation,
        }
    }
}
