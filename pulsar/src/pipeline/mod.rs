//! The event routing backbone and telemetry pipeline of the EDR.

pub mod dispatcher;
pub mod event;
pub mod ingress;

pub use dispatcher::{DispatcherHandle, EventDispatcher, Subscriber};
pub use event::{
    CorrelatedSyscallEvent, Event, ImageLoadEvent, ImageUnloadEvent, ProcessExitEvent,
    ProcessStartEvent, SyscallEvent,
};
pub use ingress::IngressParser;
