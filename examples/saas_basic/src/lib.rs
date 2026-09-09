//! A SaaS application that delegates all of its identity and authority to
//! AuthPort.
//!
//! ```text
//! authport.auth   the declaration
//! bootstrap.rs    the only wiring: contract, directory, policy, tenants
//! app.rs          handlers that receive an authoritative context
//! upstream.rs     the same handlers behind a standalone AuthPort
//! ```
//!
//! There is no authentication subsystem in this application.

pub mod app;
pub mod bootstrap;
pub mod demo;
pub mod support;
pub mod upstream;
