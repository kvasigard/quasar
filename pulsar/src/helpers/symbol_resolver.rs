//! Synchronous Windows DbgHelp symbol resolution wrapper.

use std::collections::HashMap;
use std::ffi::CStr;
use std::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGEHLP_MODULE64, SYMBOL_INFO, SYMOPT_DEFERRED_LOADS, SYMOPT_UNDNAME, SymCleanup, SymFromAddr,
    SymGetModuleInfo64, SymInitialize, SymSetOptions,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// A synchronous Symbol Resolver using the Windows DbgHelp API.
///
/// Wraps per-process `SymInitialize` sessions and resolves memory addresses to module/symbol names.
pub struct SymbolResolver {
    /// Cache of process handles initialized with DbgHelp.
    /// Key: Process ID. Value: HANDLE cast to isize (to safely implement Send/Sync).
    process_handles: HashMap<u32, isize>,
}

/// Represents a resolved memory address with module and symbol information.
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    /// The name of the binary module (e.g. `ntdll.dll`, `kernel32.dll`).
    pub module_name: String,
    /// The decoded function/symbol name if available.
    pub symbol_name: Option<String>,
}

impl Default for SymbolResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolResolver {
    /// Creates a new `SymbolResolver` and initializes DbgHelp options with deferred loading and name undecoration.
    ///
    /// # Returns
    ///
    /// An initialized `SymbolResolver` instance.
    pub fn new() -> Self {
        unsafe {
            // Defer loading symbols until they are actually requested, and undecorate C++ names.
            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        }
        Self {
            process_handles: HashMap::new(),
        }
    }

    /// Resolves a memory address to a module and symbol name for a specific Process ID.
    ///
    /// # Arguments
    ///
    /// * `pid` - The target Process ID.
    /// * `address` - The instruction pointer / virtual memory address to resolve.
    ///
    /// # Returns
    ///
    /// `Some(ResolvedSymbol)` if the address could be queried against DbgHelp module info, or `None`.
    pub fn resolve_address(&mut self, pid: u32, address: u64) -> Option<ResolvedSymbol> {
        let h_process = self.get_or_init_process(pid)?;

        unsafe {
            // Try to get the Module Information (e.g. "ntdll")
            let mut module_info: IMAGEHLP_MODULE64 = zeroed();
            module_info.SizeOfStruct = size_of::<IMAGEHLP_MODULE64>() as u32;

            let module_name = if SymGetModuleInfo64(h_process, address, &mut module_info) != 0 {
                CStr::from_ptr(module_info.ModuleName.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            } else {
                "UnknownModule".to_string()
            };

            // Try to get the specific Symbol Name (e.g. "NtReadVirtualMemory")
            // SYMBOL_INFO has a variable length trailing string, so we must allocate a buffer.
            const MAX_SYM_NAME: usize = 1024;
            let mut buffer = vec![0u8; size_of::<SYMBOL_INFO>() + MAX_SYM_NAME];
            let sym_info = buffer.as_mut_ptr() as *mut SYMBOL_INFO;

            (*sym_info).SizeOfStruct = size_of::<SYMBOL_INFO>() as u32;
            (*sym_info).MaxNameLen = MAX_SYM_NAME as u32;

            let mut displacement: u64 = 0;
            let symbol_name = if SymFromAddr(h_process, address, &mut displacement, sym_info) != 0 {
                Some(
                    CStr::from_ptr((*sym_info).Name.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                None
            };

            Some(ResolvedSymbol {
                module_name,
                symbol_name,
            })
        }
    }

    /// Retrieves a cached DbgHelp session for a PID, or initializes a new process handle session.
    ///
    /// # Arguments
    ///
    /// * `pid` - The target Process ID.
    ///
    /// # Returns
    ///
    /// An open `HANDLE` if permissions allow, or `None` if process is inaccessible or terminated.
    fn get_or_init_process(&mut self, pid: u32) -> Option<HANDLE> {
        if let Some(&h_process) = self.process_handles.get(&pid) {
            return Some(h_process as HANDLE);
        }

        unsafe {
            // Open the target process to read its memory and enumerate modules
            let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if h_process.is_null() {
                return None; // Process might have died or we lack permissions (Access Denied)
            }

            // Initialize the symbol handler for this process.
            // fInvadeProcess = TRUE forces DbgHelp to load all modules currently in the process.
            if SymInitialize(h_process, std::ptr::null(), 1) == 0 {
                CloseHandle(h_process);
                return None;
            }

            self.process_handles.insert(pid, h_process as isize);
            Some(h_process)
        }
    }
}

/// Cleans up all cached DbgHelp process sessions and OS handles upon drop.
impl Drop for SymbolResolver {
    fn drop(&mut self) {
        unsafe {
            for &handle_val in self.process_handles.values() {
                let h_process = handle_val as HANDLE;
                SymCleanup(h_process);
                CloseHandle(h_process);
            }
        }
    }
}

// SAFETY: DbgHelp is single-threaded. By implementing Send/Sync, thread safety
// is guaranteed by wrapping this struct inside an Arc<Mutex<SymbolResolver>>.
unsafe impl Send for SymbolResolver {}
unsafe impl Sync for SymbolResolver {}
