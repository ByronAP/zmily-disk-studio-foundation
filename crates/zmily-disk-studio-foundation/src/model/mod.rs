//! Portable filesystem and partition-type identification.

pub mod filesystem;
pub mod mbr_type;

pub use filesystem::{DetectionSource, FilesystemType};
