//! Entity domain models and definitions.

pub mod file;
pub mod handle;
pub mod interaction;
pub mod module;
pub mod network;
pub mod process;
pub mod thread;
pub mod token;

pub use file::{
    FileAccessRecord, FileContext, FileFormatInfo, FileOperationKind, PeExport, PeExportDirectory,
    PeInfo, PeSection,
};
pub use handle::{HandleObject, HandleTarget};
pub use interaction::{
    ConfidenceLevel, ExecutionTrigger, HandleDupDetails, InjectionDetails, InjectionTechnique,
    InteractionKind, InteractionRecord, MemoryTamperingDetails, TokenImpersonationDetails,
};
pub use module::{LoadedModule, ModuleInfo};
pub use network::{NetworkConnection, SocketProtocol};
pub use process::ProcessContext;
pub use thread::{ThreadContext, ThreadExecutionState};
pub use token::{IntegrityLevel, PrivilegeState, TokenContext};
