//! The event routing backbone of the EDR.

pub mod call_stack_correlator;
pub mod dispatcher;
pub mod etw_schemas;
pub mod event;

pub use call_stack_correlator::CallStackCorrelator;
pub use dispatcher::{EventDispatcher, EventListener};
pub use event::Event;


