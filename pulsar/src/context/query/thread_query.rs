//! Fluent thread query interface and inspection wrapper.

use std::sync::Arc;

use crate::context::SystemContext;
use crate::context::identity::{ProcessKey, ThreadKey};
use crate::context::models::thread::ThreadContext;
use crate::context::models::token::TokenContext;
use crate::context::query::process_query::ProcessRef;

/// Ergonomic, fluent query wrapper around an `Arc<ThreadContext>` snapshot.
#[derive(Clone)]
pub struct ThreadRef<'a> {
    pub(crate) ctx: &'a SystemContext,
    pub(crate) inner: Arc<ThreadContext>,
}

impl<'a> ThreadRef<'a> {
    /// Creates a new `ThreadRef` query handle.
    pub fn new(ctx: &'a SystemContext, inner: Arc<ThreadContext>) -> Self {
        Self { ctx, inner }
    }

    /// Access the underlying `ThreadContext` directly.
    #[inline]
    pub fn context(&self) -> &ThreadContext {
        &self.inner
    }

    /// Returns the synthetic unique `ThreadKey`.
    #[inline]
    pub fn key(&self) -> ThreadKey {
        self.inner.key
    }

    /// Returns the synthetic key of the owning process.
    #[inline]
    pub fn owner_key(&self) -> ProcessKey {
        self.inner.owner_process
    }

    /// Resolves the owning process query reference.
    pub fn owner_process(&self) -> Option<ProcessRef<'a>> {
        self.ctx.process_by_key(self.inner.owner_process)
    }

    /// Returns the operating system Thread ID (TID).
    #[inline]
    pub fn tid(&self) -> u32 {
        self.inner.tid
    }

    /// Returns the virtual start address of the thread.
    #[inline]
    pub fn start_address(&self) -> u64 {
        self.inner.start_address
    }

    /// Returns the Thread Environment Block (TEB) base address if known.
    #[inline]
    pub fn teb_base(&self) -> Option<u64> {
        self.inner.teb_base
    }

    /// Returns the thread creation timestamp.
    #[inline]
    pub fn create_time(&self) -> i64 {
        self.inner.create_time
    }

    /// Checks if this thread is currently alive.
    #[inline]
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// Returns the impersonation token if explicitly set on this thread.
    pub fn impersonation_token(&self) -> Option<TokenContext> {
        self.inner.impersonation_token.read().clone()
    }
}
