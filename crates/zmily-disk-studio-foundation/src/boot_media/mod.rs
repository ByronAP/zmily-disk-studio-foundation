//! Bounded boot-image parsing and streaming checksums.

pub mod checksum;
pub mod el_torito;
pub mod iso_parser;
pub mod udf_parser;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod iso_fixtures;
