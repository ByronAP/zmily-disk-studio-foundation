//! Bounded, cancellable checksum calculation for images and other large files.

use std::io::Read;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

const DEFAULT_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl ChecksumAlgorithm {
    pub fn accepts_hex(self, value: &str) -> bool {
        value.len() == self.hex_length() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    pub const fn hex_length(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedChecksum {
    pub algorithm: ChecksumAlgorithm,
    pub hexadecimal: String,
}

impl ExpectedChecksum {
    /// Accepts a bare digest (algorithm inferred by length) or an explicitly
    /// prefixed value such as `sha256:abcd...`.
    pub fn parse(value: &str) -> Result<Self, ChecksumError> {
        let value = value.trim();
        let (algorithm, hexadecimal) = match value.split_once(':') {
            Some((name, digest)) => (parse_algorithm(name)?, digest.trim()),
            None => (algorithm_for_hex_length(value.len())?, value),
        };
        if !algorithm.accepts_hex(hexadecimal) {
            return Err(ChecksumError::InvalidExpected(
                "the expected checksum length or hexadecimal encoding is invalid".into(),
            ));
        }
        Ok(Self {
            algorithm,
            hexadecimal: hexadecimal.to_ascii_lowercase(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumConfig {
    pub block_bytes: usize,
    pub total_bytes: Option<u64>,
    pub expected: Option<ExpectedChecksum>,
}

impl Default for ChecksumConfig {
    fn default() -> Self {
        Self {
            block_bytes: DEFAULT_BLOCK_BYTES,
            total_bytes: None,
            expected: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumProgress {
    pub bytes_read: u64,
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksums {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

impl Checksums {
    pub fn get(&self, algorithm: ChecksumAlgorithm) -> &str {
        match algorithm {
            ChecksumAlgorithm::Md5 => &self.md5,
            ChecksumAlgorithm::Sha1 => &self.sha1,
            ChecksumAlgorithm::Sha256 => &self.sha256,
            ChecksumAlgorithm::Sha512 => &self.sha512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumComparison {
    pub algorithm: ChecksumAlgorithm,
    pub expected: String,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumReport {
    pub bytes_read: u64,
    pub cancelled: bool,
    pub checksums: Option<Checksums>,
    pub comparison: Option<ChecksumComparison>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChecksumError {
    #[error("the checksum configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("the expected checksum is invalid: {0}")]
    InvalidExpected(String),
    #[error("could not read checksum input at byte {offset}: {reason}")]
    Read { offset: u64, reason: String },
}

/// Calculates all supported digests during one bounded pass over `reader`.
pub fn calculate_checksums(
    mut reader: impl Read,
    config: ChecksumConfig,
    mut is_cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(ChecksumProgress),
) -> Result<ChecksumReport, ChecksumError> {
    if config.block_bytes == 0 || config.block_bytes > MAX_BLOCK_BYTES {
        return Err(ChecksumError::InvalidConfiguration(format!(
            "the read block must be between 1 and {MAX_BLOCK_BYTES} bytes"
        )));
    }
    let mut buffer = vec![0; config.block_bytes];
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut bytes_read = 0_u64;
    loop {
        if is_cancelled() {
            return Ok(ChecksumReport {
                bytes_read,
                cancelled: true,
                checksums: None,
                comparison: None,
            });
        }
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ChecksumError::Read {
                    offset: bytes_read,
                    reason: error.to_string(),
                });
            }
        };
        let block = &buffer[..read];
        md5.update(block);
        sha1.update(block);
        sha256.update(block);
        sha512.update(block);
        bytes_read = bytes_read.saturating_add(read as u64);
        progress(ChecksumProgress {
            bytes_read,
            total_bytes: config.total_bytes,
        });
    }
    let checksums = Checksums {
        md5: encode_hex(&md5.finalize()),
        sha1: encode_hex(&sha1.finalize()),
        sha256: encode_hex(&sha256.finalize()),
        sha512: encode_hex(&sha512.finalize()),
    };
    let comparison = config.expected.map(|expected| ChecksumComparison {
        algorithm: expected.algorithm,
        matches: checksums.get(expected.algorithm) == expected.hexadecimal,
        expected: expected.hexadecimal,
    });
    Ok(ChecksumReport {
        bytes_read,
        cancelled: false,
        checksums: Some(checksums),
        comparison,
    })
}

fn parse_algorithm(value: &str) -> Result<ChecksumAlgorithm, ChecksumError> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "md5" => Ok(ChecksumAlgorithm::Md5),
        "sha1" => Ok(ChecksumAlgorithm::Sha1),
        "sha256" => Ok(ChecksumAlgorithm::Sha256),
        "sha512" => Ok(ChecksumAlgorithm::Sha512),
        _ => Err(ChecksumError::InvalidExpected(
            "the checksum prefix must be md5, sha1, sha256, or sha512".into(),
        )),
    }
}

fn algorithm_for_hex_length(length: usize) -> Result<ChecksumAlgorithm, ChecksumError> {
    match length {
        32 => Ok(ChecksumAlgorithm::Md5),
        40 => Ok(ChecksumAlgorithm::Sha1),
        64 => Ok(ChecksumAlgorithm::Sha256),
        128 => Ok(ChecksumAlgorithm::Sha512),
        _ => Err(ChecksumError::InvalidExpected(
            "a checksum without a prefix must have a standard digest length".into(),
        )),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io::Cursor};

    use super::*;

    #[test]
    fn standard_vectors_are_calculated_in_one_pass() {
        let report = calculate_checksums(
            Cursor::new(b"abc"),
            ChecksumConfig::default(),
            || false,
            |_| {},
        )
        .unwrap();
        let checksums = report.checksums.unwrap();
        assert_eq!(checksums.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(checksums.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            checksums.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            checksums.sha512,
            concat!(
                "ddaf35a193617abacc417349ae204131",
                "12e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd",
                "454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn prefixed_and_inferred_expected_values_compare_case_insensitively() {
        let expected = ExpectedChecksum::parse(
            "SHA-256: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        )
        .unwrap();
        let report = calculate_checksums(
            Cursor::new(b"abc"),
            ChecksumConfig {
                expected: Some(expected),
                ..ChecksumConfig::default()
            },
            || false,
            |_| {},
        )
        .unwrap();
        assert!(report.comparison.unwrap().matches);
        assert_eq!(
            ExpectedChecksum::parse("900150983cd24fb0d6963f7d28e17f72")
                .unwrap()
                .algorithm,
            ChecksumAlgorithm::Md5
        );
        let mismatch = calculate_checksums(
            Cursor::new(b"abc"),
            ChecksumConfig {
                expected: Some(
                    ExpectedChecksum::parse("00000000000000000000000000000000").unwrap(),
                ),
                ..ChecksumConfig::default()
            },
            || false,
            |_| {},
        )
        .unwrap();
        assert!(!mismatch.comparison.unwrap().matches);
    }

    #[test]
    fn cancellation_returns_no_partial_digest() {
        let checks = Cell::new(0);
        let report = calculate_checksums(
            Cursor::new(vec![1; 64]),
            ChecksumConfig {
                block_bytes: 8,
                ..ChecksumConfig::default()
            },
            || {
                checks.set(checks.get() + 1);
                checks.get() > 2
            },
            |_| {},
        )
        .unwrap();
        assert!(report.cancelled);
        assert_eq!(report.bytes_read, 16);
        assert_eq!(report.checksums, None);
    }

    #[test]
    fn malformed_expected_values_and_unbounded_blocks_are_rejected() {
        assert!(ExpectedChecksum::parse("sha256:not-hex").is_err());
        let error = calculate_checksums(
            Cursor::new([]),
            ChecksumConfig {
                block_bytes: MAX_BLOCK_BYTES + 1,
                ..ChecksumConfig::default()
            },
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error, ChecksumError::InvalidConfiguration(_)));
    }
}
