// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Server-side LRPC bindings for `mxc-service`. Pairs with
//! `mxc_service_rpc_client`; the two crates are deliberately separate
//! so cargo cannot link the MIDL client and server stubs (both export
//! `RpcCall`) into the same binary.

#![cfg(windows)]

mod sys;
pub mod server;

pub use server::{shutdown, start};
pub use sys::ENDPOINT;
