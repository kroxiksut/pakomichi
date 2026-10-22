// SPDX-License-Identifier: MIT OR Apache-2.0

//! Release inventory and asset selection (P2-002).
//!
//! Contract: `docs/en/specifications/github.md`, items 3, 4, and 6. Two
//! phases, both pure and without I/O:
//!
//! 1. [`inventory_release`] reads one release from the provider's listing
//!    and decides, from asset names alone, which assets are worth
//!    downloading for the target system. A name is never evidence of
//!    compatibility; it only avoids downloading archives, signatures,
//!    packages of the other ecosystem, or files for another CPU. Unknown
//!    kinds of files need review and are never downloaded.
//! 2. [`admit_release`] takes the downloaded candidates with the native
//!    identity the inspector read (`inspect`) and decides which may go on
//!    to provenance verification and the family policy: the digest matches
//!    the provider's claim, the native architecture fits the target, the
//!    native version keeps the release on its channel, and no two files
//!    of the release claim the same package.
//!
//! The channel is stable only when the provider flag, the tag, and the
//! native version all say so (`channel`). Comparing native versions across
//! releases belongs to the family policy (P2-007), not to this module.

mod asset;
mod channel;
mod platform;
mod release;

pub use asset::{AssetKind, asset_kind};
pub use channel::{
    ChannelPolicy, ChannelVerdict, PrereleaseMarker, marker_in_native_version, marker_in_text,
};
pub use platform::{ArchFamily, ArchHint, Ecosystem, PlatformError, TargetPlatform, arch_hint};
pub use release::{
    Admission, AssetDecision, AssetEntry, InspectedAsset, InventoryError, InventoryPolicy,
    NativePackage, ReleaseExclusion, ReleaseInventory, SkipReason, admit_release,
    inventory_release,
};
