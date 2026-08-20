# 10 — System Expansion Notes & Architectural Guidelines

This document gathers the overarching engineering conventions, coding standards, and architectural rules that keep Quasar clean, robust, and easy to maintain as new developers join the project and new features are added.

## Rust API & Naming Conventions

All modules, types, and functions in Quasar adhere to the official Rust API Guidelines (RFC 430 & RFC 199):

For getter methods (C-GETTER), do not prefix method names with `get_` when retrieving fields or simple properties. Use concise names like `file.sha256()` or `process.parent_key()`. The `get_` prefix is reserved exclusively for operations that perform non-trivial computation or explicitly allocate new resources.

For predicate methods that return a boolean (C-PREDICATE), use prefixes like `is_`, `has_`, or `can_`. Good examples include `process.is_alive()`, `process.is_pinned()`, and `handle.has_process_write_access()`. Avoid ambiguous names like `check_is_alive()`.

For container types and registries (C-COLLECTION), always provide standard `len(&self) -> usize` and `is_empty(&self) -> bool` methods so the collection behaves intuitively in standard Rust idioms.

## Documentation Standards (RFC 1574)

Every module, public struct, enum, and function should include clear rustdoc documentation.

At the top of each file, include a module-level doc comment (`//!`) explaining what that file does and how it fits into the broader architecture.

For functions and methods, write a concise one-line summary at the top, followed by any necessary technical details or security context. Always include structured sections for `# Arguments`, `# Returns`, and `# Errors` whenever the function accepts parameters, returns a value, or produces a `Result`.

When referencing code types, functions, or constants in documentation, always enclose them in backticks (like `\`ProcessContext\`` or `\`EventRecord\``) so rustdoc can automatically generate valid cross-references and links.

## Concurrency & Safety Guardrails

When contributing new code to Quasar, follow these four core concurrency rules:

First, never execute blocking operations inside kernel callbacks or ingress ingestion handlers. The ETW callback thread and Stage 1 parser must run as fast as possible. Any expensive work (like resolving symbols on disk or parsing complex behavioral graphs) belongs inside analytical sinks running in the background worker pool.

Second, never index persistent state by raw operating system identifiers. Always assign and use 64-bit synthetic monotonic keys (`ProcessKey`, `ThreadKey`, `FileKey`) to prevent temporal corruption from PID and TID recycling.

Third, avoid global locks. Use fine-grained interior mutability with `parking_lot::RwLock` on small sub-tables, use `DashMap` for concurrent collections, and use atomic primitives (`AtomicBool`, `AtomicU64`) for simple status flags and counters.

Fourth, always enforce bounded memory ceilings. Never allow a collection or history queue to grow without bounds. Use ring buffers (`VecDeque` with a capacity cap) or hook into the `RetentionManager` garbage collector to ensure older or inactive records are pruned predictably.

## Pre-Commit Verification Checklist

Before opening a pull request or merging code into the main branch, make sure your changes pass all four automated quality checks:

1. Check workspace compilation: `cargo check --workspace`
2. Strict Clippy lint check (zero warnings allowed): `cargo clippy -p pulsar --all-targets -- -D warnings`
3. All unit and integration tests pass: `cargo test --workspace`
4. Documentation builds cleanly without broken links or invalid tags: `cargo doc -p pulsar --no-deps`
