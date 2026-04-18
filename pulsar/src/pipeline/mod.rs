//! The event routing backbone of the EDR.

pub mod dispatcher;
pub mod event;

// Expose only the types that other modules need to interact with.
// The internal implementation details remain private to the `pipeline` module.
pub use dispatcher::{EventDispatcher, Subscriber};
pub use event::Event;
