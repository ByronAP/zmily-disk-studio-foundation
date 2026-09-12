//! Reusable storage and file-format primitives shared by ZMILY products.
//!
//! This crate is the initial public-source boundary. It owns buffer-based
//! filesystem and image parsing, bounded previews, size parsing, checksums,
//! file inspection and supporting types. It has no platform storage API
//! dependency, product workflow executor, entitlements or private dependencies.
//! Generic file readers preserve caller-supplied paths; callers own admission.
//! The private core/platform crates re-export these implementations for their
//! existing callers. See the repository's source-publication documentation.

#![forbid(unsafe_code)]

pub mod boot_media;
pub mod build_id;
pub mod files;
pub mod model;
pub mod pe;
pub mod recovery;
pub mod size;
