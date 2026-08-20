//! Entity domain models and definitions.

pub mod file;
pub mod handle;
pub mod interaction;
pub mod network;
pub mod process;
pub mod thread;
pub mod token;

pub use file::{FileAccessRecord, FileContext, FileOperationKind};
pub use handle::{HandleObject, HandleTarget};
pub use interaction::{
    ConfidenceLevel, ExecutionTrigger, HandleDupDetails, InjectionDetails, InjectionTechnique,
    InteractionKind, InteractionRecord, MemoryTamperingDetails, TokenImpersonationDetails,
};
pub use network::{NetworkConnection, SocketProtocol};
pub use process::{LoadedModule, ProcessContext};
pub use thread::{ThreadContext, ThreadExecutionState};
pub use token::{IntegrityLevel, PrivilegeState, TokenContext};
