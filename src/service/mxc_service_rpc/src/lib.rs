// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LRPC bindings for `mxc-service`.
//!
//! Production-grade replacement for the named-pipe + CBOR transport.
//! The IDL (idl/mxc_service.idl) exposes a single `RpcCall` method
//! that round-trips CBOR blobs; protocol-level types live in
//! `mxc_service_proto` and are shared with the named-pipe path.
//!
//! Server:
//!   ```ignore
//!   mxc_service_rpc::server::start(|req| handler.dispatch(req))?;
//!   ```
//!
//! Client:
//!   ```ignore
//!   let resp = mxc_service_rpc::client::call(&request)?;
//!   ```

#![cfg(windows)]

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
mod sys;

pub use sys::ENDPOINT;

