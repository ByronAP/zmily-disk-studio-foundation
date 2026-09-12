//! Bounded ISO 9660/Joliet catalog traversal and file reads.

use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const DESCRIPTOR_BYTES: usize = 2048;
const FIRST_DESCRIPTOR_SECTOR: u64 = 16;
const FILE_READ_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoConfig {
    pub total_bytes: u64,
    pub max_descriptors: u16,
    pub max_directories: u32,
    pub max_entries: u32,
    pub max_depth: u16,
    pub max_directory_bytes: usize,
}

impl IsoConfig {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            max_descriptors: 64,
            max_directories: 100_000,
            max_entries: 1_000_000,
            max_depth: 128,
            max_directory_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoVolume {
    pub volume_id: String,
    pub logical_block_bytes: u32,
    pub volume_bytes: u64,
    pub joliet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoEntry {
    pub path: String,
    pub name: String,
    pub extent_offset: u64,
    pub length: u64,
    pub directory: bool,
    pub hidden: bool,
    pub multi_extent: bool,
    pub depth: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoCatalog {
    pub volume: IsoVolume,
    pub entries: Vec<IsoEntry>,
    pub directories_read: u32,
    pub bytes_read: u64,
    pub cancelled: bool,
    pub limit_reached: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoProgress {
    pub directories_read: u32,
    pub entries_found: u32,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoFileProgress {
    pub bytes_read: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoFileReadReport {
    pub bytes_read: u64,
    pub cancelled: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IsoError {
    #[error("the ISO parser configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("could not read the ISO at byte {offset}: {reason}")]
    Read { offset: u64, reason: String },
    #[error("the image has no valid ISO 9660 primary volume descriptor")]
    MissingPrimaryDescriptor,
    #[error("the ISO 9660 volume descriptor is inconsistent: {0}")]
    InvalidDescriptor(String),
    #[error("the selected ISO entry cannot be read: {0}")]
    InvalidEntry(String),
    #[error("could not write ISO file data: {0}")]
    Write(String),
}

#[derive(Clone)]
struct ParsedDescriptor {
    volume: IsoVolume,
    root: DirectoryLocation,
}

#[derive(Clone, Copy)]
struct DirectoryLocation {
    offset: u64,
    length: usize,
    depth: u16,
}

/// Builds a bounded catalog without writing to the source or destination media.
pub fn catalog_iso(
    config: IsoConfig,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    mut is_cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(IsoProgress),
) -> Result<IsoCatalog, IsoError> {
    validate_config(&config)?;
    let mut bytes_read = 0_u64;
    let mut primary = None;
    let mut joliet = None;
    let mut terminated = false;
    for index in 0..config.max_descriptors {
        if is_cancelled() {
            return Ok(cancelled_catalog(bytes_read));
        }
        let offset = (FIRST_DESCRIPTOR_SECTOR + u64::from(index)) * DESCRIPTOR_BYTES as u64;
        if offset
            .checked_add(DESCRIPTOR_BYTES as u64)
            .is_none_or(|end| end > config.total_bytes)
        {
            return Err(IsoError::InvalidDescriptor(
                "the descriptor sequence extends beyond the source".into(),
            ));
        }
        let descriptor = read_exact(&mut read, offset, DESCRIPTOR_BYTES)?;
        bytes_read += descriptor.len() as u64;
        if descriptor.get(1..6) != Some(b"CD001") || descriptor.get(6) != Some(&1) {
            return Err(IsoError::InvalidDescriptor(format!(
                "descriptor {index} has an invalid identifier or version"
            )));
        }
        match descriptor[0] {
            1 => primary = Some(parse_descriptor(&descriptor, false, config.total_bytes)?),
            2 if is_joliet(&descriptor) => {
                joliet = Some(parse_descriptor(&descriptor, true, config.total_bytes)?)
            }
            255 => {
                terminated = true;
                break;
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(IsoError::InvalidDescriptor(
            "the volume descriptor sequence has no terminator within its limit".into(),
        ));
    }
    let primary = primary.ok_or(IsoError::MissingPrimaryDescriptor)?;
    let selected = joliet.unwrap_or(primary);
    if selected.root.length > config.max_directory_bytes {
        return Err(IsoError::InvalidDescriptor(
            "the root directory exceeds the configured byte limit".into(),
        ));
    }
    let mut catalog = IsoCatalog {
        volume: selected.volume,
        entries: Vec::new(),
        directories_read: 0,
        bytes_read,
        cancelled: false,
        limit_reached: false,
        issues: Vec::new(),
    };
    let mut pending = VecDeque::from([(String::new(), selected.root)]);
    let mut visited = HashSet::new();
    while let Some((parent, directory)) = pending.pop_front() {
        if is_cancelled() {
            catalog.cancelled = true;
            break;
        }
        if catalog.directories_read >= config.max_directories
            || catalog.entries.len() >= config.max_entries as usize
        {
            catalog.limit_reached = true;
            break;
        }
        if !visited.insert((directory.offset, directory.length)) {
            catalog.issues.push(format!(
                "directory extent at byte {} was already traversed",
                directory.offset
            ));
            continue;
        }
        let bytes = read_exact(&mut read, directory.offset, directory.length)?;
        catalog.bytes_read += bytes.len() as u64;
        catalog.directories_read += 1;
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let record_length = bytes[cursor] as usize;
            if record_length == 0 {
                cursor = next_block(cursor, catalog.volume.logical_block_bytes as usize)
                    .min(bytes.len());
                continue;
            }
            if record_length < 34 || cursor + record_length > bytes.len() {
                catalog.issues.push(format!(
                    "directory {parent:?} contains a truncated record at byte {cursor}"
                ));
                break;
            }
            let record = &bytes[cursor..cursor + record_length];
            cursor += record_length;
            let name_length = record[32] as usize;
            if 33 + name_length > record.len() {
                catalog.issues.push(format!(
                    "directory {parent:?} contains an invalid name length"
                ));
                continue;
            }
            let raw_name = &record[33..33 + name_length];
            if raw_name == [0] || raw_name == [1] {
                continue;
            }
            let Some(name) = decode_name(raw_name, catalog.volume.joliet) else {
                catalog.issues.push(format!(
                    "directory {parent:?} contains an invalid file name"
                ));
                continue;
            };
            let extent = match dual_u32(record, 2, "directory-record extent") {
                Ok(value) => value,
                Err(error) => {
                    catalog.issues.push(error);
                    continue;
                }
            };
            let length = match dual_u32(record, 10, "directory-record length") {
                Ok(value) => value,
                Err(error) => {
                    catalog.issues.push(error);
                    continue;
                }
            };
            let extended_blocks = u64::from(record[1]);
            let Some(offset) = u64::from(extent)
                .checked_add(extended_blocks)
                .and_then(|block| block.checked_mul(catalog.volume.logical_block_bytes as u64))
            else {
                catalog
                    .issues
                    .push(format!("entry {name:?} has an overflowing extent"));
                continue;
            };
            if offset
                .checked_add(u64::from(length))
                .is_none_or(|end| end > catalog.volume.volume_bytes || end > config.total_bytes)
            {
                catalog
                    .issues
                    .push(format!("entry {name:?} lies outside the volume"));
                continue;
            }
            let flags = record[25];
            if record[26] != 0 || record[27] != 0 {
                catalog.issues.push(format!(
                    "entry {name:?} uses unsupported interleaved recording"
                ));
                continue;
            }
            if dual_u16(record, 28, "directory-record volume sequence").is_err() {
                catalog.issues.push(format!(
                    "entry {name:?} has inconsistent volume-sequence copies"
                ));
                continue;
            }
            let directory_entry = flags & 0x02 != 0;
            let depth = directory.depth.saturating_add(1);
            let path = if parent.is_empty() {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            };
            let entry = IsoEntry {
                path: path.clone(),
                name,
                extent_offset: offset,
                length: u64::from(length),
                directory: directory_entry,
                hidden: flags & 0x01 != 0,
                multi_extent: flags & 0x80 != 0,
                depth,
            };
            if directory_entry {
                if depth > config.max_depth {
                    catalog.limit_reached = true;
                } else if usize::try_from(length)
                    .ok()
                    .is_none_or(|length| length > config.max_directory_bytes)
                {
                    catalog.issues.push(format!(
                        "directory {path:?} exceeds the configured byte limit"
                    ));
                } else {
                    pending.push_back((
                        path,
                        DirectoryLocation {
                            offset,
                            length: length as usize,
                            depth,
                        },
                    ));
                }
            }
            catalog.entries.push(entry);
            if catalog.entries.len() >= config.max_entries as usize {
                catalog.limit_reached = true;
                break;
            }
        }
        progress(IsoProgress {
            directories_read: catalog.directories_read,
            entries_found: catalog.entries.len() as u32,
            bytes_read: catalog.bytes_read,
        });
        if catalog.limit_reached {
            break;
        }
    }
    Ok(catalog)
}

/// Streams one ordinary, single-extent catalog entry to a caller-owned sink.
pub fn read_iso_file(
    entry: &IsoEntry,
    source_bytes: u64,
    max_output_bytes: u64,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    mut is_cancelled: impl FnMut() -> bool,
    mut write: impl FnMut(&[u8]) -> Result<(), String>,
    mut progress: impl FnMut(IsoFileProgress),
) -> Result<IsoFileReadReport, IsoError> {
    if entry.directory
        || entry.multi_extent
        || entry.length > max_output_bytes
        || entry
            .extent_offset
            .checked_add(entry.length)
            .is_none_or(|end| end > source_bytes)
    {
        return Err(IsoError::InvalidEntry(
            "directories, multi-extent files, out-of-source extents, and files over the output limit are refused".into(),
        ));
    }
    let mut completed = 0_u64;
    while completed < entry.length {
        if is_cancelled() {
            return Ok(IsoFileReadReport {
                bytes_read: completed,
                cancelled: true,
            });
        }
        let wanted = usize::try_from((entry.length - completed).min(FILE_READ_BYTES as u64))
            .expect("the file read chunk is bounded by usize");
        let block = read_exact(&mut read, entry.extent_offset + completed, wanted)?;
        write(&block).map_err(IsoError::Write)?;
        completed += block.len() as u64;
        progress(IsoFileProgress {
            bytes_read: completed,
            total_bytes: entry.length,
        });
    }
    Ok(IsoFileReadReport {
        bytes_read: completed,
        cancelled: false,
    })
}

fn validate_config(config: &IsoConfig) -> Result<(), IsoError> {
    if config.total_bytes < (FIRST_DESCRIPTOR_SECTOR + 2) * DESCRIPTOR_BYTES as u64
        || config.max_descriptors == 0
        || config.max_directories == 0
        || config.max_entries == 0
        || config.max_depth == 0
        || config.max_directory_bytes < 34
    {
        return Err(IsoError::InvalidConfiguration(
            "the source size and every traversal limit must be nonzero and usable".into(),
        ));
    }
    Ok(())
}

fn cancelled_catalog(bytes_read: u64) -> IsoCatalog {
    IsoCatalog {
        volume: IsoVolume {
            volume_id: String::new(),
            logical_block_bytes: 0,
            volume_bytes: 0,
            joliet: false,
        },
        entries: Vec::new(),
        directories_read: 0,
        bytes_read,
        cancelled: true,
        limit_reached: false,
        issues: Vec::new(),
    }
}

fn parse_descriptor(
    descriptor: &[u8],
    joliet: bool,
    source_bytes: u64,
) -> Result<ParsedDescriptor, IsoError> {
    let blocks =
        dual_u32(descriptor, 80, "volume-space size").map_err(IsoError::InvalidDescriptor)?;
    let block_bytes =
        dual_u16(descriptor, 128, "logical-block size").map_err(IsoError::InvalidDescriptor)?;
    if !(512..=32_768).contains(&block_bytes) || !block_bytes.is_power_of_two() {
        return Err(IsoError::InvalidDescriptor(
            "the logical-block size is unsupported".into(),
        ));
    }
    let volume_bytes = u64::from(blocks)
        .checked_mul(u64::from(block_bytes))
        .ok_or_else(|| IsoError::InvalidDescriptor("the volume size overflows".into()))?;
    if volume_bytes == 0 || volume_bytes > source_bytes {
        return Err(IsoError::InvalidDescriptor(
            "the declared volume does not fit in the source".into(),
        ));
    }
    let root_record = descriptor
        .get(156..)
        .and_then(|bytes| bytes.get(..usize::from(*bytes.first()?)))
        .ok_or_else(|| IsoError::InvalidDescriptor("the root record is truncated".into()))?;
    if root_record.len() < 34 || root_record[25] & 0x02 == 0 {
        return Err(IsoError::InvalidDescriptor(
            "the root record is not a directory".into(),
        ));
    }
    let extent = dual_u32(root_record, 2, "root extent").map_err(IsoError::InvalidDescriptor)?;
    let length = dual_u32(root_record, 10, "root length").map_err(IsoError::InvalidDescriptor)?;
    let offset = u64::from(extent) * u64::from(block_bytes);
    if usize::try_from(length).is_err()
        || offset
            .checked_add(u64::from(length))
            .is_none_or(|end| end > volume_bytes)
    {
        return Err(IsoError::InvalidDescriptor(
            "the root directory lies outside the volume".into(),
        ));
    }
    let volume_id = if joliet {
        decode_joliet(&descriptor[40..72])
            .unwrap_or_default()
            .trim_end_matches(' ')
            .to_string()
    } else {
        String::from_utf8_lossy(&descriptor[40..72])
            .trim_end_matches(' ')
            .to_string()
    };
    Ok(ParsedDescriptor {
        volume: IsoVolume {
            volume_id,
            logical_block_bytes: u32::from(block_bytes),
            volume_bytes,
            joliet,
        },
        root: DirectoryLocation {
            offset,
            length: length as usize,
            depth: 0,
        },
    })
}

fn is_joliet(descriptor: &[u8]) -> bool {
    matches!(descriptor.get(88..91), Some(b"%/@" | b"%/C" | b"%/E"))
}

fn decode_name(bytes: &[u8], joliet: bool) -> Option<String> {
    let decoded = if joliet {
        decode_joliet(bytes)?
    } else if bytes.iter().all(|byte| byte.is_ascii() && *byte != 0) {
        String::from_utf8(bytes.to_vec()).ok()?
    } else {
        return None;
    };
    let without_version = decoded
        .rsplit_once(';')
        .filter(|(_, version)| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map_or(decoded.as_str(), |(name, _)| name);
    let name = without_version.strip_suffix('.').unwrap_or(without_version);
    (!name.is_empty() && !name.contains(['/', '\\'])).then(|| name.to_string())
}

fn decode_joliet(bytes: &[u8]) -> Option<String> {
    let (words, remainder) = bytes.as_chunks::<2>();
    remainder.is_empty().then_some(())?;
    let units = words
        .iter()
        .map(|word| u16::from_be_bytes(*word))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

fn dual_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16, String> {
    let little = u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{field} is truncated"))?,
    );
    let big = u16::from_be_bytes(
        bytes
            .get(offset + 2..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{field} is truncated"))?,
    );
    (little == big)
        .then_some(little)
        .ok_or_else(|| format!("{field} endian copies disagree"))
}

fn dual_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32, String> {
    let little = u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{field} is truncated"))?,
    );
    let big = u32::from_be_bytes(
        bytes
            .get(offset + 4..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{field} is truncated"))?,
    );
    (little == big)
        .then_some(little)
        .ok_or_else(|| format!("{field} endian copies disagree"))
}

fn next_block(cursor: usize, block_bytes: usize) -> usize {
    cursor
        .checked_add(block_bytes - 1)
        .map_or(usize::MAX, |value| value / block_bytes * block_bytes)
}

fn read_exact(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, IsoError> {
    let bytes = read(offset, length).map_err(|reason| IsoError::Read { offset, reason })?;
    if bytes.len() != length {
        return Err(IsoError::Read {
            offset,
            reason: format!("returned {} of {length} requested bytes", bytes.len()),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::iso_fixtures::{BLOCK, image, record};
    use super::*;

    fn catalog(image: &[u8]) -> Result<IsoCatalog, IsoError> {
        catalog_iso(
            IsoConfig::new(image.len() as u64),
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || false,
            |_| {},
        )
    }

    #[test]
    fn primary_catalog_and_file_stream_are_exact_and_bounded() {
        let image = image(false);
        let catalog = catalog(&image).unwrap();
        assert!(!catalog.volume.joliet);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].path, "/HELLO.TXT");
        let mut output = Vec::new();
        let report = read_iso_file(
            &catalog.entries[0],
            image.len() as u64,
            5,
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || false,
            |bytes| {
                output.extend_from_slice(bytes);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(output, b"hello");
        assert_eq!(report.bytes_read, 5);
    }

    #[test]
    fn joliet_is_preferred_and_decoded_as_big_endian_utf16() {
        let image = image(true);
        let catalog = catalog(&image).unwrap();
        assert!(catalog.volume.joliet);
        assert_eq!(catalog.entries[0].path, "/hello world.txt");
    }

    #[test]
    fn disagreeing_endian_geometry_is_rejected() {
        let mut image = image(false);
        image[16 * BLOCK + 84] ^= 1;
        assert!(matches!(
            catalog(&image),
            Err(IsoError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn cancellation_never_returns_a_partial_file_as_complete() {
        let image = image(false);
        let catalog = catalog(&image).unwrap();
        let mut output = Vec::new();
        let report = read_iso_file(
            &catalog.entries[0],
            image.len() as u64,
            5,
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || true,
            |bytes| {
                output.extend_from_slice(bytes);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        assert!(report.cancelled);
        assert!(output.is_empty());
    }

    #[test]
    fn recursive_directories_are_bounded_and_cycle_checked() {
        let mut image = image(false);
        let root_start = 20 * BLOCK;
        let root_cursor = root_start
            + record(20, BLOCK as u32, 0x02, &[0]).len()
            + record(20, BLOCK as u32, 0x02, &[1]).len()
            + record(21, 5, 0, b"HELLO.TXT;1").len();
        let subdirectory = record(22, BLOCK as u32, 0x02, b"SUB");
        image[root_cursor..root_cursor + subdirectory.len()].copy_from_slice(&subdirectory);
        let records = [
            record(22, BLOCK as u32, 0x02, &[0]),
            record(20, BLOCK as u32, 0x02, &[1]),
            record(23, 1, 0, b"INNER.BIN;1"),
        ];
        let mut cursor = 22 * BLOCK;
        for record in records {
            image[cursor..cursor + record.len()].copy_from_slice(&record);
            cursor += record.len();
        }
        image[23 * BLOCK] = 0x5a;
        let catalog = catalog(&image).unwrap();
        assert_eq!(catalog.directories_read, 2);
        assert!(catalog.entries.iter().any(|entry| entry.path == "/SUB"));
        assert!(
            catalog
                .entries
                .iter()
                .any(|entry| entry.path == "/SUB/INNER.BIN")
        );

        let mut config = IsoConfig::new(image.len() as u64);
        config.max_entries = 1;
        let limited = catalog_iso(
            config,
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || false,
            |_| {},
        )
        .unwrap();
        assert!(limited.limit_reached);
        assert_eq!(limited.entries.len(), 1);
    }
}
