//! The event routing backbone of the EDR.

pub mod dispatcher;
pub mod etw_schemas;
pub mod event;

pub use dispatcher::{EventDispatcher, Subscriber};
pub use event::Event;
