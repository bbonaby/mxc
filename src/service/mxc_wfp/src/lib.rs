// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc_wfp` — safe(r) wrapper crate over [`mxc_wfp_sys`].
//!
//! Layout:
//!
//! - [`engine`] — RAII handle on a BFE session.
//! - [`grant`]  — engine-SD ACE install/uninstall (one-time, elevated).
//! - [`policy`] — per-sandbox [`PolicyManager`] (runtime).
//!
//! Unsafe surface in this crate is limited to a small set of one-line
//! `unsafe { mxc_wfp_sys::… }` call sites, each preceded by a
//! `// SAFETY:` comment explaining how the [`mxc_wfp_sys`] contract is
//! satisfied. Consumers (`mxc_service` and friends) need no `unsafe`
//! of their own for the WFP path.

#![cfg(target_os = "windows")]

pub mod engine;
pub mod grant;
pub mod policy;

pub use engine::Engine;
pub use grant::{install_grant, uninstall_grant};
pub use policy::{PolicyManager, MAX_ACTIVE_POLICIES};

use mxc_wfp_sys::Guid;

/// Stable identity GUIDs owned by MXC. Changing them breaks upgrade.
pub const MXC_PROVIDER_GUID: Guid =
    Guid::from_u128(0x7a3d1bbe_3f1e_4d7a_9c4e_5a36f51e9b21);
pub const MXC_SUBLAYER_GUID: Guid =
    Guid::from_u128(0x7a3d1bbf_3f1e_4d7a_9c4e_5a36f51e9b22);
pub const MXC_SUBLAYER_WEIGHT: u16 = 0x4000;
