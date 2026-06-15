// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Client-side LRPC bindings for `mxc-service`. Pairs with
//! `mxc_service_rpc_server`.

#![cfg(windows)]

mod sys;
mod client;

pub use client::Client;
pub use sys::ENDPOINT;
