//! Bounded ECMA-167/UDF catalog traversal for ordinary Type 1 and read-only
//! UDF 2.50 metadata partition maps.

use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SECTOR_BYTES: usize = 2048;
const ANCHOR_SECTOR: u32 = 256;
const MAX_VDS_BYTES: usize = 16 * 1024 * 1024;
const FILE_READ_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfConfig {
    pub total_bytes: u64,
    pub max_directories: u32,
    pub max_entries: u32,
    pub max_depth: u16,
    pub max_directory_bytes: usize,
    pub max_file_entry_bytes: usize,
}

impl UdfConfig {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            max_directories: 100_000,
            max_entries: 1_000_000,
            max_depth: 128,
            max_directory_bytes: 64 * 1024 * 1024,
            max_file_entry_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfVolume {
    pub volume_id: String,
    pub logical_block_bytes: u32,
    pub partition_number: u16,
    pub partition_start_sector: u32,
    pub partition_sectors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfExtent {
    pub offset: u64,
    pub length: u64,
    pub recorded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfEntry {
    pub path: String,
    pub name: String,
    pub length: u64,
    pub directory: bool,
    pub hidden: bool,
    pub depth: u16,
    pub icb_logical_block: u32,
    pub icb_partition_reference: u16,
    pub extents: Vec<UdfExtent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfCatalog {
    pub volume: UdfVolume,
    pub entries: Vec<UdfEntry>,
    pub directories_read: u32,
    pub bytes_read: u64,
    pub cancelled: bool,
    pub limit_reached: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfProgress {
    pub directories_read: u32,
    pub entries_found: u32,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfFileReadReport {
    pub bytes_read: u64,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdfFileProgress {
    pub bytes_read: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UdfError {
    #[error("the UDF parser configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("could not read the UDF image at byte {offset}: {reason}")]
    Read { offset: u64, reason: String },
    #[error("the UDF structure is invalid: {0}")]
    InvalidStructure(String),
    #[error("this UDF feature is not supported: {0}")]
    Unsupported(String),
    #[error("the selected UDF entry cannot be read: {0}")]
    InvalidEntry(String),
    #[error("could not write UDF file data: {0}")]
    Write(String),
}

#[derive(Clone, Copy)]
struct Partition {
    number: u16,
    start_sector: u32,
    sectors: u32,
    access_type: u32,
}

#[derive(Clone)]
enum AddressSpace {
    Physical(Partition),
    Metadata {
        blocks: u32,
        backing: Vec<UdfExtent>,
    },
}

#[derive(Clone)]
struct FileBody {
    length: u64,
    directory: bool,
    extents: Vec<UdfExtent>,
    logical_extents: Vec<(u64, u64)>,
    extent_types: Vec<u8>,
    link_count: u16,
    unique_id: u64,
    extended_attribute_icb_length: u32,
    allocation_type: u16,
}

/// Catalogs a common UDF bridge/1.02 or read-only UDF 2.50 metadata image.
pub fn catalog_udf(
    config: UdfConfig,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    mut is_cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(UdfProgress),
) -> Result<UdfCatalog, UdfError> {
    validate_config(&config)?;
    if is_cancelled() {
        return Err(UdfError::InvalidStructure(
            "cataloguing was cancelled before the volume identity was read".into(),
        ));
    }
    let mut bytes_read = validate_volume_recognition(&mut read, config.total_bytes)?;
    let anchor = read_block(&mut read, ANCHOR_SECTOR, config.total_bytes)?;
    validate_tag(&anchor, 2, ANCHOR_SECTOR)?;
    bytes_read += SECTOR_BYTES as u64;
    bytes_read += validate_backup_anchor(&mut read, &anchor, config.total_bytes)?;
    let vds_length = le_u32(&anchor, 16)? as usize;
    let vds_sector = le_u32(&anchor, 20)?;
    if vds_length == 0 || vds_length > MAX_VDS_BYTES || !vds_length.is_multiple_of(SECTOR_BYTES) {
        return Err(UdfError::InvalidStructure(
            "the main volume descriptor extent is empty, unaligned, or over its limit".into(),
        ));
    }
    checked_range(
        u64::from(vds_sector) * SECTOR_BYTES as u64,
        vds_length as u64,
        config.total_bytes,
        "main volume descriptor sequence",
    )?;
    let mut partition = None;
    let mut logical = None;
    let mut terminated = false;
    for index in 0..vds_length / SECTOR_BYTES {
        let sector = vds_sector + index as u32;
        let descriptor = read_block(&mut read, sector, config.total_bytes)?;
        bytes_read += descriptor.len() as u64;
        let tag = le_u16(&descriptor, 0)?;
        validate_tag(&descriptor, tag, sector)?;
        match tag {
            5 => {
                let sequence = le_u32(&descriptor, 16)?;
                let candidate = Partition {
                    number: le_u16(&descriptor, 22)?,
                    start_sector: le_u32(&descriptor, 188)?,
                    sectors: le_u32(&descriptor, 192)?,
                    access_type: le_u32(&descriptor, 184)?,
                };
                if partition
                    .as_ref()
                    .is_none_or(|(current, _)| sequence > *current)
                {
                    partition = Some((sequence, candidate));
                }
            }
            6 => {
                let sequence = le_u32(&descriptor, 16)?;
                if logical
                    .as_ref()
                    .is_none_or(|(current, _)| sequence > *current)
                {
                    logical = Some((sequence, descriptor));
                }
            }
            8 => {
                terminated = true;
                break;
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(UdfError::InvalidStructure(
            "the main volume descriptor sequence has no terminator".into(),
        ));
    }
    let (_, partition) = partition.ok_or_else(|| {
        UdfError::InvalidStructure("the volume has no partition descriptor".into())
    })?;
    let (_, logical) = logical.ok_or_else(|| {
        UdfError::InvalidStructure("the volume has no logical volume descriptor".into())
    })?;
    let block_bytes = le_u32(&logical, 212)?;
    if block_bytes != SECTOR_BYTES as u32 {
        return Err(UdfError::Unsupported(format!(
            "logical blocks of {block_bytes} bytes are not supported"
        )));
    }
    checked_range(
        u64::from(partition.start_sector) * SECTOR_BYTES as u64,
        u64::from(partition.sectors) * SECTOR_BYTES as u64,
        config.total_bytes,
        "UDF partition",
    )?;
    let map_length = le_u32(&logical, 264)? as usize;
    let map_count = le_u32(&logical, 268)?;
    let map_end = 440usize.checked_add(map_length).ok_or_else(|| {
        UdfError::InvalidStructure("the logical volume partition map length overflows".into())
    })?;
    let maps = logical.get(440..map_end).ok_or_else(|| {
        UdfError::InvalidStructure("the logical volume partition maps are truncated".into())
    })?;
    let (spaces, map_bytes_read) = build_address_spaces(
        &mut read,
        maps,
        map_count,
        partition,
        config.total_bytes,
        config.max_file_entry_bytes,
    )?;
    bytes_read += map_bytes_read;
    let (fsd_length, fsd_block, fsd_partition) = long_ad(&logical, 248)?;
    if fsd_length < SECTOR_BYTES as u32 || usize::from(fsd_partition) >= spaces.len() {
        return Err(UdfError::InvalidStructure(
            "the file-set descriptor address is invalid".into(),
        ));
    }
    let fsd = read_address_block(
        &mut read,
        &spaces[usize::from(fsd_partition)],
        fsd_block,
        config.total_bytes,
    )?;
    bytes_read += fsd.len() as u64;
    validate_tag(&fsd, 256, fsd_block)?;
    let (_, root_block, root_partition) = long_ad(&fsd, 400)?;
    if usize::from(root_partition) >= spaces.len() {
        return Err(UdfError::InvalidStructure(
            "the root ICB uses an unknown partition map".into(),
        ));
    }
    let volume = UdfVolume {
        volume_id: decode_dstring(&logical[84..212]).unwrap_or_default(),
        logical_block_bytes: block_bytes,
        partition_number: partition.number,
        partition_start_sector: partition.start_sector,
        partition_sectors: partition.sectors,
    };
    let mut catalog = UdfCatalog {
        volume,
        entries: Vec::new(),
        directories_read: 0,
        bytes_read,
        cancelled: false,
        limit_reached: false,
        issues: Vec::new(),
    };
    let mut pending = VecDeque::from([(String::new(), root_block, root_partition, 0_u16)]);
    let mut visited = HashSet::new();
    while let Some((parent, icb_block, icb_partition, depth)) = pending.pop_front() {
        if is_cancelled() {
            catalog.cancelled = true;
            break;
        }
        if !visited.insert((icb_partition, icb_block)) {
            catalog.issues.push(format!(
                "ICB partition {icb_partition}, logical block {icb_block} was already traversed"
            ));
            continue;
        }
        if catalog.directories_read >= config.max_directories {
            catalog.limit_reached = true;
            break;
        }
        let body = read_file_entry(
            &mut read,
            &spaces,
            icb_partition,
            icb_block,
            config.total_bytes,
            config.max_file_entry_bytes,
        )?;
        catalog.bytes_read += SECTOR_BYTES as u64;
        if !body.directory || body.length > config.max_directory_bytes as u64 {
            catalog.issues.push(format!(
                "directory {parent:?} has an invalid type or exceeds its byte limit"
            ));
            continue;
        }
        let directory = read_body(&mut read, &body, config.total_bytes)?;
        catalog.bytes_read += directory.len() as u64;
        catalog.directories_read += 1;
        let mut cursor = 0usize;
        while cursor < directory.len() {
            if directory.len() - cursor < 38 {
                if directory[cursor..].iter().any(|byte| *byte != 0) {
                    catalog.issues.push(format!(
                        "directory {parent:?} has nonzero truncated trailing data"
                    ));
                }
                break;
            }
            let header = &directory[cursor..];
            let name_length = header[19] as usize;
            let implementation_length = le_u16(header, 36)? as usize;
            let raw_length = 38usize
                .checked_add(implementation_length)
                .and_then(|length| length.checked_add(name_length))
                .ok_or_else(|| UdfError::InvalidStructure("a file identifier overflows".into()))?;
            let record_length = align4(raw_length);
            let record = directory
                .get(cursor..cursor + record_length)
                .ok_or_else(|| {
                    UdfError::InvalidStructure("a file identifier is truncated".into())
                })?;
            let descriptor_block = body_logical_block(&body, cursor)?;
            validate_tag(record, 257, descriptor_block)?;
            cursor += record_length;
            let characteristics = record[18];
            if characteristics & 0x08 != 0 || characteristics & 0x04 != 0 {
                continue;
            }
            let name_bytes = &record[38 + implementation_length..raw_length];
            let Some(name) = decode_osta_name(name_bytes) else {
                catalog
                    .issues
                    .push(format!("directory {parent:?} has an invalid OSTA name"));
                continue;
            };
            let (_, child_block, child_partition) = long_ad(record, 20)?;
            if usize::from(child_partition) >= spaces.len() {
                catalog
                    .issues
                    .push(format!("entry {name:?} uses an unknown partition map"));
                continue;
            }
            let child = match read_file_entry(
                &mut read,
                &spaces,
                child_partition,
                child_block,
                config.total_bytes,
                config.max_file_entry_bytes,
            ) {
                Ok(child) => child,
                Err(error) => {
                    catalog.issues.push(format!("entry {name:?}: {error}"));
                    continue;
                }
            };
            catalog.bytes_read += SECTOR_BYTES as u64;
            let child_depth = depth.saturating_add(1);
            let path = if parent.is_empty() {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            };
            catalog.entries.push(UdfEntry {
                path: path.clone(),
                name,
                length: child.length,
                directory: child.directory,
                hidden: characteristics & 0x01 != 0,
                depth: child_depth,
                icb_logical_block: child_block,
                icb_partition_reference: child_partition,
                extents: child.extents,
            });
            if catalog.entries.len() >= config.max_entries as usize {
                catalog.limit_reached = true;
                break;
            }
            if child.directory {
                if child_depth > config.max_depth {
                    catalog.limit_reached = true;
                } else {
                    pending.push_back((path, child_block, child_partition, child_depth));
                }
            }
        }
        progress(UdfProgress {
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

/// Streams a catalogued UDF file, zeroing explicitly unrecorded extents.
pub fn read_udf_file(
    entry: &UdfEntry,
    source_bytes: u64,
    max_output_bytes: u64,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    mut is_cancelled: impl FnMut() -> bool,
    mut write: impl FnMut(&[u8]) -> Result<(), String>,
    mut progress: impl FnMut(UdfFileProgress),
) -> Result<UdfFileReadReport, UdfError> {
    if entry.directory || entry.length > max_output_bytes {
        return Err(UdfError::InvalidEntry(
            "directories and files over the output limit are refused".into(),
        ));
    }
    let mut completed = 0_u64;
    for extent in &entry.extents {
        let logical = (entry.length - completed).min(extent.length);
        let mut extent_completed = 0_u64;
        while extent_completed < logical {
            if is_cancelled() {
                return Ok(UdfFileReadReport {
                    bytes_read: completed,
                    cancelled: true,
                });
            }
            let wanted = usize::try_from((logical - extent_completed).min(FILE_READ_BYTES as u64))
                .expect("the file read chunk is bounded by usize");
            if extent.recorded {
                let offset = extent.offset.checked_add(extent_completed).ok_or_else(|| {
                    UdfError::InvalidEntry("a file extent offset overflows".into())
                })?;
                checked_range(offset, wanted as u64, source_bytes, "file extent")?;
                let bytes = read_exact(&mut read, offset, wanted)?;
                write(&bytes).map_err(UdfError::Write)?;
            } else {
                write(&vec![0; wanted]).map_err(UdfError::Write)?;
            }
            extent_completed += wanted as u64;
            completed += wanted as u64;
            progress(UdfFileProgress {
                bytes_read: completed,
                total_bytes: entry.length,
            });
        }
    }
    if completed != entry.length {
        return Err(UdfError::InvalidEntry(
            "the allocation descriptors do not cover the complete file".into(),
        ));
    }
    Ok(UdfFileReadReport {
        bytes_read: completed,
        cancelled: false,
    })
}

fn read_file_entry(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    spaces: &[AddressSpace],
    partition_reference: u16,
    block: u32,
    total_bytes: u64,
    max_entry_bytes: usize,
) -> Result<FileBody, UdfError> {
    read_file_entry_as(
        read,
        spaces,
        partition_reference,
        block,
        total_bytes,
        max_entry_bytes,
        &[4, 5],
    )
}

fn read_file_entry_as(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    spaces: &[AddressSpace],
    partition_reference: u16,
    block: u32,
    total_bytes: u64,
    max_entry_bytes: usize,
    allowed_types: &[u8],
) -> Result<FileBody, UdfError> {
    if max_entry_bytes < SECTOR_BYTES {
        return Err(UdfError::InvalidConfiguration(
            "the file-entry byte limit is smaller than one logical block".into(),
        ));
    }
    let space = spaces
        .get(usize::from(partition_reference))
        .ok_or_else(|| {
            UdfError::InvalidStructure("a file entry uses an unknown partition map".into())
        })?;
    let entry = read_address_block(read, space, block, total_bytes)?;
    let tag = le_u16(&entry, 0)?;
    let (information_offset, unique_id_offset, extended_icb_offset, lengths_offset, data_offset): (
        usize,
        usize,
        usize,
        usize,
        usize,
    ) = match tag {
        261 => (56, 160, 112, 168, 176),
        266 => (56, 200, 136, 208, 216),
        _ => {
            return Err(UdfError::InvalidStructure(
                "an ICB is neither a file entry nor an extended file entry".into(),
            ));
        }
    };
    validate_tag(&entry, tag, block)?;
    let file_type = entry[27];
    if !allowed_types.contains(&file_type) {
        return Err(UdfError::Unsupported(format!(
            "ICB file type {file_type} is not valid in this context"
        )));
    }
    let information_length = le_u64(&entry, information_offset)?;
    let extended_length = le_u32(&entry, lengths_offset)? as usize;
    let allocation_length = le_u32(&entry, lengths_offset + 4)? as usize;
    let allocation_offset = data_offset
        .checked_add(extended_length)
        .ok_or_else(|| UdfError::InvalidStructure("file-entry fields overflow".into()))?;
    let allocation_end = allocation_offset
        .checked_add(allocation_length)
        .ok_or_else(|| {
            UdfError::InvalidStructure("allocation descriptor length overflows".into())
        })?;
    let allocation = entry
        .get(allocation_offset..allocation_end)
        .ok_or_else(|| UdfError::InvalidStructure("allocation descriptors are truncated".into()))?;
    let allocation_type = le_u16(&entry, 34)? & 0x0007;
    let mut extents = Vec::new();
    let mut logical_extents = Vec::new();
    let mut extent_types = Vec::new();
    match allocation_type {
        0 => {
            let (records, remainder) = allocation.as_chunks::<8>();
            if !remainder.is_empty() {
                return Err(UdfError::InvalidStructure(
                    "short allocation descriptors are misaligned".into(),
                ));
            }
            for record in records {
                let raw_length = u32::from_le_bytes(record[..4].try_into().unwrap());
                let extent_type = raw_length >> 30;
                if extent_type == 3 {
                    return Err(UdfError::Unsupported(
                        "continuation allocation descriptors are not supported".into(),
                    ));
                }
                let length = u64::from(raw_length & 0x3fff_ffff);
                let location = u32::from_le_bytes(record[4..].try_into().unwrap());
                extent_types.push(extent_type as u8);
                logical_extents.push((u64::from(location) * SECTOR_BYTES as u64, length));
                extents.extend(translate_extent(
                    space,
                    u64::from(location) * SECTOR_BYTES as u64,
                    length,
                    extent_type == 0,
                    total_bytes,
                )?);
            }
        }
        1 => {
            let (records, remainder) = allocation.as_chunks::<16>();
            if !remainder.is_empty() {
                return Err(UdfError::InvalidStructure(
                    "long allocation descriptors are misaligned".into(),
                ));
            }
            for record in records {
                let raw_length = u32::from_le_bytes(record[..4].try_into().unwrap());
                let extent_type = raw_length >> 30;
                if extent_type == 3 {
                    return Err(UdfError::Unsupported(
                        "continuation allocation descriptors are not supported".into(),
                    ));
                }
                let length = u64::from(raw_length & 0x3fff_ffff);
                let location = u32::from_le_bytes(record[4..8].try_into().unwrap());
                let reference = u16::from_le_bytes(record[8..10].try_into().unwrap());
                extent_types.push(extent_type as u8);
                let target = spaces.get(usize::from(reference)).ok_or_else(|| {
                    UdfError::InvalidStructure(
                        "a long allocation descriptor uses an unknown partition map".into(),
                    )
                })?;
                logical_extents.push((u64::from(location) * SECTOR_BYTES as u64, length));
                extents.extend(translate_extent(
                    target,
                    u64::from(location) * SECTOR_BYTES as u64,
                    length,
                    extent_type == 0,
                    total_bytes,
                )?);
            }
        }
        3 => {
            if information_length > allocation.len() as u64 {
                return Err(UdfError::InvalidStructure(
                    "embedded file data is shorter than its information length".into(),
                ));
            }
            logical_extents.push((
                u64::from(block) * SECTOR_BYTES as u64 + allocation_offset as u64,
                information_length,
            ));
            extent_types.push(0);
            extents.extend(translate_extent(
                space,
                u64::from(block) * SECTOR_BYTES as u64 + allocation_offset as u64,
                information_length,
                true,
                total_bytes,
            )?);
        }
        value => {
            return Err(UdfError::Unsupported(format!(
                "allocation descriptor type {value} is not supported"
            )));
        }
    }
    if extents.iter().map(|extent| extent.length).sum::<u64>() < information_length {
        return Err(UdfError::InvalidStructure(
            "allocation descriptors do not cover the information length".into(),
        ));
    }
    Ok(FileBody {
        length: information_length,
        directory: file_type == 4,
        extents,
        logical_extents,
        extent_types,
        link_count: le_u16(&entry, 48)?,
        unique_id: le_u64(&entry, unique_id_offset)?,
        extended_attribute_icb_length: le_u32(&entry, extended_icb_offset)? & 0x3fff_ffff,
        allocation_type,
    })
}

fn read_body(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    body: &FileBody,
    total_bytes: u64,
) -> Result<Vec<u8>, UdfError> {
    let length = usize::try_from(body.length)
        .map_err(|_| UdfError::InvalidStructure("directory length is too large".into()))?;
    let mut bytes = Vec::with_capacity(length);
    for extent in &body.extents {
        let wanted = (length - bytes.len()).min(extent.length as usize);
        if wanted == 0 {
            break;
        }
        if extent.recorded {
            checked_range(
                extent.offset,
                wanted as u64,
                total_bytes,
                "directory extent",
            )?;
            bytes.extend_from_slice(&read_exact(read, extent.offset, wanted)?);
        } else {
            bytes.resize(bytes.len() + wanted, 0);
        }
    }
    (bytes.len() == length)
        .then_some(bytes)
        .ok_or_else(|| UdfError::InvalidStructure("directory extents are incomplete".into()))
}

fn body_logical_block(body: &FileBody, logical_offset: usize) -> Result<u32, UdfError> {
    let mut remaining = logical_offset as u64;
    for (offset, length) in &body.logical_extents {
        if remaining < *length {
            return offset
                .checked_add(remaining)
                .and_then(|byte| u32::try_from(byte / SECTOR_BYTES as u64).ok())
                .ok_or_else(|| {
                    UdfError::InvalidStructure("a directory tag location overflows".into())
                });
        }
        remaining -= *length;
    }
    Err(UdfError::InvalidStructure(
        "a directory record lies outside its allocation descriptors".into(),
    ))
}

#[derive(Clone, Copy)]
enum RawPartitionMap {
    Physical {
        volume_sequence: u16,
        partition_number: u16,
    },
    Metadata {
        volume_sequence: u16,
        partition_number: u16,
        file_block: u32,
        mirror_block: u32,
        bitmap_block: u32,
        allocation_blocks: u32,
        alignment_blocks: u16,
        duplicate: bool,
    },
}

fn build_address_spaces(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    bytes: &[u8],
    count: u32,
    partition: Partition,
    total_bytes: u64,
    max_entry_bytes: usize,
) -> Result<(Vec<AddressSpace>, u64), UdfError> {
    let mut maps = Vec::new();
    let mut cursor = 0usize;
    for _ in 0..count {
        let header = bytes.get(cursor..cursor + 2).ok_or_else(|| {
            UdfError::InvalidStructure("a partition map header is truncated".into())
        })?;
        let length = usize::from(header[1]);
        if length < 2 {
            return Err(UdfError::InvalidStructure(
                "a partition map has an invalid length".into(),
            ));
        }
        let record = bytes
            .get(cursor..cursor + length)
            .ok_or_else(|| UdfError::InvalidStructure("a partition map is truncated".into()))?;
        maps.push(match (record[0], length) {
            (1, 6) => RawPartitionMap::Physical {
                volume_sequence: le_u16(record, 2)?,
                partition_number: le_u16(record, 4)?,
            },
            (2, 64) if entity_identifier(record, 4) == b"*UDF Metadata Partition" => {
                if record[2..4].iter().any(|byte| *byte != 0)
                    || record[4] != 0
                    || record[59..64].iter().any(|byte| *byte != 0)
                {
                    return Err(UdfError::InvalidStructure(
                        "the metadata partition map has nonzero reserved bytes".into(),
                    ));
                }
                let flags = record[58];
                let allocation_blocks = le_u32(record, 52)?;
                let alignment_blocks = le_u16(record, 56)?;
                if allocation_blocks < 32
                    || !allocation_blocks.is_multiple_of(32)
                    || alignment_blocks == 0
                    || flags & !1 != 0
                {
                    return Err(UdfError::InvalidStructure(
                        "the metadata partition allocation, alignment, or flags are invalid".into(),
                    ));
                }
                RawPartitionMap::Metadata {
                    volume_sequence: le_u16(record, 36)?,
                    partition_number: le_u16(record, 38)?,
                    file_block: le_u32(record, 40)?,
                    mirror_block: le_u32(record, 44)?,
                    bitmap_block: le_u32(record, 48)?,
                    allocation_blocks,
                    alignment_blocks,
                    duplicate: flags & 1 != 0,
                }
            }
            (2, 64) => {
                return Err(UdfError::Unsupported(format!(
                    "Type 2 partition map {:?} is not supported",
                    String::from_utf8_lossy(entity_identifier(record, 4))
                )));
            }
            (kind, _) => {
                return Err(UdfError::Unsupported(format!(
                    "partition map type {kind} with length {length} is not supported"
                )));
            }
        });
        cursor += length;
    }
    if cursor != bytes.len() {
        return Err(UdfError::InvalidStructure(
            "the partition map table length does not match its records".into(),
        ));
    }
    match maps.as_slice() {
        [
            RawPartitionMap::Physical {
                volume_sequence,
                partition_number,
            },
        ] if *volume_sequence != 0 && *partition_number == partition.number => {
            Ok((vec![AddressSpace::Physical(partition)], 0))
        }
        [
            RawPartitionMap::Physical {
                volume_sequence,
                partition_number,
            },
            metadata @ RawPartitionMap::Metadata { .. },
        ] if *volume_sequence != 0 && *partition_number == partition.number => {
            let RawPartitionMap::Metadata {
                volume_sequence: metadata_volume_sequence,
                partition_number,
                file_block,
                mirror_block,
                bitmap_block,
                allocation_blocks,
                alignment_blocks,
                duplicate,
            } = *metadata
            else {
                unreachable!()
            };
            if metadata_volume_sequence != *volume_sequence
                || partition_number != partition.number
                || file_block == mirror_block
            {
                return Err(UdfError::InvalidStructure(
                    "the metadata map does not identify two distinct files in the physical partition"
                        .into(),
                ));
            }
            if partition.access_type != 1 || bitmap_block != u32::MAX {
                return Err(UdfError::Unsupported(
                    "only read-only metadata partitions without a metadata bitmap are currently supported"
                        .into(),
                ));
            }
            let physical = vec![AddressSpace::Physical(partition)];
            let main = read_file_entry_as(
                read,
                &physical,
                0,
                file_block,
                total_bytes,
                max_entry_bytes,
                &[250],
            )?;
            let mirror = read_file_entry_as(
                read,
                &physical,
                0,
                mirror_block,
                total_bytes,
                max_entry_bytes,
                &[251],
            )?;
            validate_metadata_backing(
                &main,
                &mirror,
                allocation_blocks,
                alignment_blocks,
                duplicate,
            )?;
            let blocks = u32::try_from(main.length / SECTOR_BYTES as u64).map_err(|_| {
                UdfError::InvalidStructure("the metadata partition is too large".into())
            })?;
            Ok((
                vec![
                    AddressSpace::Physical(partition),
                    AddressSpace::Metadata {
                        blocks,
                        backing: main.extents,
                    },
                ],
                2 * SECTOR_BYTES as u64,
            ))
        }
        _ => Err(UdfError::Unsupported(
            "the partition-map combination is not supported".into(),
        )),
    }
}

fn validate_metadata_backing(
    main: &FileBody,
    mirror: &FileBody,
    allocation_blocks: u32,
    alignment_blocks: u16,
    duplicate: bool,
) -> Result<(), UdfError> {
    if main.length == 0
        || !main.length.is_multiple_of(SECTOR_BYTES as u64)
        || main.length != mirror.length
        || main.extent_types.contains(&1)
        || mirror.extent_types.contains(&1)
        || main.link_count != 0
        || mirror.link_count != 0
        || main.unique_id != 0
        || mirror.unique_id != 0
        || main.extended_attribute_icb_length != 0
        || mirror.extended_attribute_icb_length != 0
        || main.allocation_type != 0
        || mirror.allocation_type != 0
        || main.extents.iter().map(|extent| extent.length).sum::<u64>() != main.length
        || mirror
            .extents
            .iter()
            .map(|extent| extent.length)
            .sum::<u64>()
            != mirror.length
    {
        return Err(UdfError::InvalidStructure(
            "the metadata file is empty, unaligned, incomplete, or differs in length from its mirror"
                .into(),
        ));
    }
    let allocation_bytes = u64::from(allocation_blocks) * SECTOR_BYTES as u64;
    let alignment_bytes = u64::from(alignment_blocks) * SECTOR_BYTES as u64;
    for body in [main, mirror] {
        if body.extents.iter().any(|extent| {
            extent.recorded && !extent.offset.is_multiple_of(SECTOR_BYTES as u64)
                || !extent.length.is_multiple_of(allocation_bytes)
        }) || body.logical_extents.iter().zip(&body.extent_types).any(
            |((offset, _), extent_type)| {
                *extent_type == 0 && !offset.is_multiple_of(alignment_bytes)
            },
        ) {
            return Err(UdfError::InvalidStructure(
                "the metadata file extents violate the map allocation or alignment units".into(),
            ));
        }
    }
    if !duplicate && main.extents != mirror.extents {
        return Err(UdfError::InvalidStructure(
            "shared metadata mode uses different main and mirror allocations".into(),
        ));
    }
    if duplicate && main.extents == mirror.extents {
        return Err(UdfError::InvalidStructure(
            "duplicate metadata mode reuses the main-file allocation".into(),
        ));
    }
    Ok(())
}

fn entity_identifier(bytes: &[u8], offset: usize) -> &[u8] {
    bytes
        .get(offset + 1..offset + 24)
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
}

fn translate_extent(
    space: &AddressSpace,
    logical_offset: u64,
    length: u64,
    recorded: bool,
    total_bytes: u64,
) -> Result<Vec<UdfExtent>, UdfError> {
    let capacity = match space {
        AddressSpace::Physical(partition) => u64::from(partition.sectors) * SECTOR_BYTES as u64,
        AddressSpace::Metadata { blocks, .. } => u64::from(*blocks) * SECTOR_BYTES as u64,
    };
    checked_range(
        logical_offset,
        length,
        capacity,
        "logical allocation extent",
    )?;
    if !recorded {
        return Ok(vec![UdfExtent {
            offset: 0,
            length,
            recorded: false,
        }]);
    }
    match space {
        AddressSpace::Physical(partition) => {
            let partition_start = u64::from(partition.start_sector) * SECTOR_BYTES as u64;
            let offset = partition_start.checked_add(logical_offset).ok_or_else(|| {
                UdfError::InvalidStructure("a physical extent offset overflows".into())
            })?;
            checked_range(offset, length, total_bytes, "physical allocation extent")?;
            Ok(vec![UdfExtent {
                offset,
                length,
                recorded: true,
            }])
        }
        AddressSpace::Metadata { backing, .. } => {
            let mut remaining_offset = logical_offset;
            let mut remaining_length = length;
            let mut translated = Vec::new();
            for extent in backing {
                if remaining_offset >= extent.length {
                    remaining_offset -= extent.length;
                    continue;
                }
                let take = remaining_length.min(extent.length - remaining_offset);
                if !extent.recorded {
                    return Err(UdfError::InvalidStructure(
                        "referenced metadata lies in an unallocated metadata-file extent".into(),
                    ));
                }
                let offset = extent.offset.checked_add(remaining_offset).ok_or_else(|| {
                    UdfError::InvalidStructure("a metadata extent offset overflows".into())
                })?;
                checked_range(offset, take, total_bytes, "metadata allocation extent")?;
                translated.push(UdfExtent {
                    offset,
                    length: take,
                    recorded: true,
                });
                remaining_length -= take;
                remaining_offset = 0;
                if remaining_length == 0 {
                    return Ok(translated);
                }
            }
            Err(UdfError::InvalidStructure(
                "the metadata file does not cover a referenced logical extent".into(),
            ))
        }
    }
}

fn validate_volume_recognition(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    total_bytes: u64,
) -> Result<u64, UdfError> {
    let mut began = false;
    let mut nsr = false;
    let mut bytes_read = 0_u64;
    for sector in 16..32_u32 {
        let block = read_block(read, sector, total_bytes)?;
        bytes_read += block.len() as u64;
        if block.get(6) != Some(&1) {
            continue;
        }
        match block.get(1..6) {
            Some(b"BEA01") => began = true,
            Some(b"NSR02" | b"NSR03") if began => nsr = true,
            Some(b"TEA01") if nsr => return Ok(bytes_read),
            _ => {}
        }
    }
    Err(UdfError::InvalidStructure(
        "the BEA/NSR/TEA volume recognition sequence is missing or out of order".into(),
    ))
}

fn validate_backup_anchor(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    primary: &[u8],
    total_bytes: u64,
) -> Result<u64, UdfError> {
    let last = (total_bytes / SECTOR_BYTES as u64)
        .checked_sub(1)
        .and_then(|sector| u32::try_from(sector).ok())
        .ok_or_else(|| UdfError::InvalidStructure("the image sector count is invalid".into()))?;
    let mut candidates = vec![last];
    if last > 256 {
        candidates.push(last - 256);
    }
    candidates.sort_unstable();
    candidates.dedup();
    let mut bytes_read = 0_u64;
    for sector in candidates {
        let Ok(anchor) = read_block(read, sector, total_bytes) else {
            continue;
        };
        bytes_read += anchor.len() as u64;
        if validate_tag(&anchor, 2, sector).is_ok() && anchor[16..32] == primary[16..32] {
            return Ok(bytes_read);
        }
    }
    Err(UdfError::InvalidStructure(
        "no backup anchor agrees with the primary anchor".into(),
    ))
}

fn validate_config(config: &UdfConfig) -> Result<(), UdfError> {
    if !config.total_bytes.is_multiple_of(SECTOR_BYTES as u64)
        || config.total_bytes < (u64::from(ANCHOR_SECTOR) + 1) * SECTOR_BYTES as u64
        || config.max_directories == 0
        || config.max_entries == 0
        || config.max_depth == 0
        || config.max_directory_bytes < 38
        || config.max_file_entry_bytes < SECTOR_BYTES
    {
        return Err(UdfError::InvalidConfiguration(
            "the source and traversal limits are not usable".into(),
        ));
    }
    Ok(())
}

fn validate_tag(bytes: &[u8], expected: u16, location: u32) -> Result<(), UdfError> {
    if bytes.len() < 16 || le_u16(bytes, 0)? != expected || !matches!(le_u16(bytes, 2)?, 2 | 3) {
        return Err(UdfError::InvalidStructure(format!(
            "descriptor tag {expected} is absent or has an unsupported version"
        )));
    }
    let checksum = bytes[..16]
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .fold(0_u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    if checksum != bytes[4] || bytes[5] != 0 || le_u32(bytes, 12)? != location {
        return Err(UdfError::InvalidStructure(format!(
            "descriptor tag {expected} has an invalid checksum, reserved byte, or location"
        )));
    }
    let crc_length = le_u16(bytes, 10)? as usize;
    let payload = bytes.get(16..16 + crc_length).ok_or_else(|| {
        UdfError::InvalidStructure(format!(
            "descriptor tag {expected} has a truncated CRC span"
        ))
    })?;
    if crc16(payload) != le_u16(bytes, 8)? {
        return Err(UdfError::InvalidStructure(format!(
            "descriptor tag {expected} has an invalid CRC"
        )));
    }
    Ok(())
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn decode_dstring(bytes: &[u8]) -> Option<String> {
    let length = usize::from(*bytes.last()?);
    (length > 0 && length < bytes.len()).then(|| decode_osta_name(&bytes[..length]))?
}

fn decode_osta_name(bytes: &[u8]) -> Option<String> {
    match bytes.split_first()? {
        (8, text) => Some(text.iter().map(|byte| char::from(*byte)).collect()),
        (16, text) => {
            let (units, remainder) = text.as_chunks::<2>();
            remainder.is_empty().then_some(())?;
            String::from_utf16(
                &units
                    .iter()
                    .map(|unit| u16::from_be_bytes(*unit))
                    .collect::<Vec<_>>(),
            )
            .ok()
        }
        _ => None,
    }
}

fn long_ad(bytes: &[u8], offset: usize) -> Result<(u32, u32, u16), UdfError> {
    Ok((
        le_u32(bytes, offset)? & 0x3fff_ffff,
        le_u32(bytes, offset + 4)?,
        le_u16(bytes, offset + 8)?,
    ))
}

fn read_block(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    sector: u32,
    total_bytes: u64,
) -> Result<Vec<u8>, UdfError> {
    let offset = u64::from(sector) * SECTOR_BYTES as u64;
    checked_range(offset, SECTOR_BYTES as u64, total_bytes, "descriptor block")?;
    read_exact(read, offset, SECTOR_BYTES)
}

fn read_address_block(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    space: &AddressSpace,
    block: u32,
    total_bytes: u64,
) -> Result<Vec<u8>, UdfError> {
    let extents = translate_extent(
        space,
        u64::from(block) * SECTOR_BYTES as u64,
        SECTOR_BYTES as u64,
        true,
        total_bytes,
    )?;
    let mut bytes = Vec::with_capacity(SECTOR_BYTES);
    for extent in extents {
        bytes.extend_from_slice(&read_exact(read, extent.offset, extent.length as usize)?);
    }
    Ok(bytes)
}

fn checked_range(offset: u64, length: u64, total: u64, name: &str) -> Result<(), UdfError> {
    if offset.checked_add(length).is_none_or(|end| end > total) {
        return Err(UdfError::InvalidStructure(format!(
            "the {name} lies outside the image"
        )));
    }
    Ok(())
}

fn read_exact(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, UdfError> {
    let bytes = read(offset, length).map_err(|reason| UdfError::Read { offset, reason })?;
    if bytes.len() != length {
        return Err(UdfError::Read {
            offset,
            reason: format!("returned {} of {length} requested bytes", bytes.len()),
        });
    }
    Ok(bytes)
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, UdfError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| UdfError::InvalidStructure("a 16-bit field is truncated".into()))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, UdfError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| UdfError::InvalidStructure("a 32-bit field is truncated".into()))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, UdfError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| UdfError::InvalidStructure("a 64-bit field is truncated".into()))
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) / 4 * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTITION_START: u32 = 270;

    fn finish_tag(bytes: &mut [u8], identifier: u16, location: u32, crc_length: usize) {
        bytes[0..2].copy_from_slice(&identifier.to_le_bytes());
        bytes[2..4].copy_from_slice(&2_u16.to_le_bytes());
        bytes[5] = 0;
        bytes[10..12].copy_from_slice(&(crc_length as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&location.to_le_bytes());
        let crc = crc16(&bytes[16..16 + crc_length]);
        bytes[8..10].copy_from_slice(&crc.to_le_bytes());
        bytes[4] = bytes[..16]
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 4)
            .fold(0_u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    }

    fn long_address(bytes: &mut [u8], offset: usize, length: u32, block: u32) {
        long_address_in(bytes, offset, length, block, 0);
    }

    fn long_address_in(
        bytes: &mut [u8],
        offset: usize,
        length: u32,
        block: u32,
        partition_reference: u16,
    ) {
        bytes[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&block.to_le_bytes());
        bytes[offset + 8..offset + 10].copy_from_slice(&partition_reference.to_le_bytes());
    }

    fn file_entry(block: u32, file_type: u8, length: u64, data_block: u32) -> Vec<u8> {
        let mut entry = vec![0; SECTOR_BYTES];
        entry[27] = file_type;
        entry[34..36].copy_from_slice(&0_u16.to_le_bytes());
        entry[56..64].copy_from_slice(&length.to_le_bytes());
        entry[168..172].copy_from_slice(&0_u32.to_le_bytes());
        entry[172..176].copy_from_slice(&8_u32.to_le_bytes());
        entry[176..180].copy_from_slice(&(length as u32).to_le_bytes());
        entry[180..184].copy_from_slice(&data_block.to_le_bytes());
        finish_tag(&mut entry, 261, block, 168);
        entry
    }

    fn file_identifier(name: &str, icb_block: u32, location: u32) -> Vec<u8> {
        file_identifier_in(name, icb_block, 0, location)
    }

    fn file_identifier_in(
        name: &str,
        icb_block: u32,
        partition_reference: u16,
        location: u32,
    ) -> Vec<u8> {
        let mut encoded = vec![8];
        encoded.extend_from_slice(name.as_bytes());
        let length = align4(38 + encoded.len());
        let mut record = vec![0; length];
        record[16..18].copy_from_slice(&1_u16.to_le_bytes());
        record[19] = encoded.len() as u8;
        long_address_in(
            &mut record,
            20,
            SECTOR_BYTES as u32,
            icb_block,
            partition_reference,
        );
        record[36..38].copy_from_slice(&0_u16.to_le_bytes());
        record[38..38 + encoded.len()].copy_from_slice(&encoded);
        finish_tag(&mut record, 257, location, length - 16);
        record
    }

    fn metadata_file_entry(block: u32, file_type: u8) -> Vec<u8> {
        let mut entry = vec![0; SECTOR_BYTES];
        entry[27] = file_type;
        entry[34..36].copy_from_slice(&0_u16.to_le_bytes());
        entry[56..64].copy_from_slice(&(64 * SECTOR_BYTES as u64).to_le_bytes());
        entry[172..176].copy_from_slice(&16_u32.to_le_bytes());
        entry[176..180].copy_from_slice(&(32 * SECTOR_BYTES as u32).to_le_bytes());
        entry[180..184].copy_from_slice(&32_u32.to_le_bytes());
        entry[184..188].copy_from_slice(&(32 * SECTOR_BYTES as u32).to_le_bytes());
        entry[188..192].copy_from_slice(&80_u32.to_le_bytes());
        finish_tag(&mut entry, 261, block, 176);
        entry
    }

    fn long_extended_file_entry(block: u32, length: u64, data_block: u32) -> Vec<u8> {
        let mut entry = vec![0; SECTOR_BYTES];
        entry[27] = 5;
        entry[34..36].copy_from_slice(&1_u16.to_le_bytes());
        entry[56..64].copy_from_slice(&length.to_le_bytes());
        entry[212..216].copy_from_slice(&16_u32.to_le_bytes());
        long_address(&mut entry, 216, length as u32, data_block);
        finish_tag(&mut entry, 266, block, 216);
        entry
    }

    fn image() -> Vec<u8> {
        let mut image = vec![0; 300 * SECTOR_BYTES];
        for (sector, identifier) in [(16, b"BEA01"), (17, b"NSR02"), (18, b"TEA01")] {
            image[sector * SECTOR_BYTES + 1..sector * SECTOR_BYTES + 6].copy_from_slice(identifier);
            image[sector * SECTOR_BYTES + 6] = 1;
        }
        let mut anchor = vec![0; SECTOR_BYTES];
        anchor[16..20].copy_from_slice(&(3 * SECTOR_BYTES as u32).to_le_bytes());
        anchor[20..24].copy_from_slice(&257_u32.to_le_bytes());
        finish_tag(&mut anchor, 2, 256, 496);
        image[256 * SECTOR_BYTES..257 * SECTOR_BYTES].copy_from_slice(&anchor);
        let mut backup_anchor = anchor.clone();
        finish_tag(&mut backup_anchor, 2, 299, 496);
        image[299 * SECTOR_BYTES..300 * SECTOR_BYTES].copy_from_slice(&backup_anchor);

        let mut partition = vec![0; SECTOR_BYTES];
        partition[22..24].copy_from_slice(&0_u16.to_le_bytes());
        partition[188..192].copy_from_slice(&PARTITION_START.to_le_bytes());
        partition[192..196].copy_from_slice(&30_u32.to_le_bytes());
        finish_tag(&mut partition, 5, 257, 496);
        image[257 * SECTOR_BYTES..258 * SECTOR_BYTES].copy_from_slice(&partition);

        let mut logical = vec![0; SECTOR_BYTES];
        logical[84] = 8;
        logical[85..89].copy_from_slice(b"TEST");
        logical[211] = 5;
        logical[212..216].copy_from_slice(&(SECTOR_BYTES as u32).to_le_bytes());
        long_address(&mut logical, 248, SECTOR_BYTES as u32, 0);
        logical[264..268].copy_from_slice(&6_u32.to_le_bytes());
        logical[268..272].copy_from_slice(&1_u32.to_le_bytes());
        logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        finish_tag(&mut logical, 6, 258, 430);
        image[258 * SECTOR_BYTES..259 * SECTOR_BYTES].copy_from_slice(&logical);

        let mut terminator = vec![0; SECTOR_BYTES];
        finish_tag(&mut terminator, 8, 259, 496);
        image[259 * SECTOR_BYTES..260 * SECTOR_BYTES].copy_from_slice(&terminator);

        let mut fsd = vec![0; SECTOR_BYTES];
        long_address(&mut fsd, 400, SECTOR_BYTES as u32, 1);
        finish_tag(&mut fsd, 256, 0, 496);
        image[PARTITION_START as usize * SECTOR_BYTES
            ..(PARTITION_START as usize + 1) * SECTOR_BYTES]
            .copy_from_slice(&fsd);

        let identifier = file_identifier("HELLO.TXT", 3, 2);
        let root = file_entry(1, 4, identifier.len() as u64, 2);
        image[(PARTITION_START as usize + 1) * SECTOR_BYTES
            ..(PARTITION_START as usize + 2) * SECTOR_BYTES]
            .copy_from_slice(&root);
        image[(PARTITION_START as usize + 2) * SECTOR_BYTES
            ..(PARTITION_START as usize + 2) * SECTOR_BYTES + identifier.len()]
            .copy_from_slice(&identifier);
        let file = file_entry(3, 5, 5, 4);
        image[(PARTITION_START as usize + 3) * SECTOR_BYTES
            ..(PARTITION_START as usize + 4) * SECTOR_BYTES]
            .copy_from_slice(&file);
        image[(PARTITION_START as usize + 4) * SECTOR_BYTES
            ..(PARTITION_START as usize + 4) * SECTOR_BYTES + 5]
            .copy_from_slice(b"hello");
        image
    }

    fn metadata_image() -> Vec<u8> {
        let mut image = image();
        image.resize(400 * SECTOR_BYTES, 0);
        image[299 * SECTOR_BYTES..300 * SECTOR_BYTES].fill(0);

        let primary_anchor = image[256 * SECTOR_BYTES..257 * SECTOR_BYTES].to_vec();
        let mut backup_anchor = primary_anchor;
        finish_tag(&mut backup_anchor, 2, 399, 496);
        image[399 * SECTOR_BYTES..400 * SECTOR_BYTES].copy_from_slice(&backup_anchor);

        let partition = &mut image[257 * SECTOR_BYTES..258 * SECTOR_BYTES];
        partition[184..188].copy_from_slice(&1_u32.to_le_bytes());
        partition[192..196].copy_from_slice(&120_u32.to_le_bytes());
        finish_tag(partition, 5, 257, 496);

        let logical = &mut image[258 * SECTOR_BYTES..259 * SECTOR_BYTES];
        long_address_in(logical, 248, SECTOR_BYTES as u32, 31, 1);
        logical[264..268].copy_from_slice(&70_u32.to_le_bytes());
        logical[268..272].copy_from_slice(&2_u32.to_le_bytes());
        logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        let metadata = &mut logical[446..510];
        metadata[0] = 2;
        metadata[1] = 64;
        metadata[5..28].fill(0);
        metadata[5..28].copy_from_slice(b"*UDF Metadata Partition");
        metadata[36..38].copy_from_slice(&1_u16.to_le_bytes());
        metadata[38..40].copy_from_slice(&0_u16.to_le_bytes());
        metadata[40..44].copy_from_slice(&0_u32.to_le_bytes());
        metadata[44..48].copy_from_slice(&1_u32.to_le_bytes());
        metadata[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        metadata[52..56].copy_from_slice(&32_u32.to_le_bytes());
        metadata[56..58].copy_from_slice(&1_u16.to_le_bytes());
        finish_tag(logical, 6, 258, 494);

        let main = metadata_file_entry(0, 250);
        image[PARTITION_START as usize * SECTOR_BYTES
            ..(PARTITION_START as usize + 1) * SECTOR_BYTES]
            .copy_from_slice(&main);
        let mirror = metadata_file_entry(1, 251);
        image[(PARTITION_START as usize + 1) * SECTOR_BYTES
            ..(PARTITION_START as usize + 2) * SECTOR_BYTES]
            .copy_from_slice(&mirror);

        let mut fsd = vec![0; SECTOR_BYTES];
        long_address_in(&mut fsd, 400, SECTOR_BYTES as u32, 32, 1);
        finish_tag(&mut fsd, 256, 31, 496);
        image[(PARTITION_START as usize + 63) * SECTOR_BYTES
            ..(PARTITION_START as usize + 64) * SECTOR_BYTES]
            .copy_from_slice(&fsd);

        let identifier = file_identifier_in("METADATA.TXT", 34, 1, 33);
        let root = file_entry(32, 4, identifier.len() as u64, 33);
        image[(PARTITION_START as usize + 80) * SECTOR_BYTES
            ..(PARTITION_START as usize + 81) * SECTOR_BYTES]
            .copy_from_slice(&root);
        image[(PARTITION_START as usize + 81) * SECTOR_BYTES
            ..(PARTITION_START as usize + 81) * SECTOR_BYTES + identifier.len()]
            .copy_from_slice(&identifier);
        let file = long_extended_file_entry(34, 8, 70);
        image[(PARTITION_START as usize + 82) * SECTOR_BYTES
            ..(PARTITION_START as usize + 83) * SECTOR_BYTES]
            .copy_from_slice(&file);
        image[(PARTITION_START as usize + 70) * SECTOR_BYTES
            ..(PARTITION_START as usize + 70) * SECTOR_BYTES + 8]
            .copy_from_slice(b"metadata");
        image
    }

    fn catalog(image: &[u8]) -> Result<UdfCatalog, UdfError> {
        catalog_udf(
            UdfConfig::new(image.len() as u64),
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || false,
            |_| {},
        )
    }

    #[test]
    fn type_one_partition_catalog_and_file_read_are_exact() {
        let image = image();
        let catalog = catalog(&image).unwrap();
        assert_eq!(catalog.volume.volume_id, "TEST");
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].path, "/HELLO.TXT");
        let mut output = Vec::new();
        let report = read_udf_file(
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
    fn metadata_partition_translates_fragmented_metadata_and_long_file_extents() {
        let image = metadata_image();
        let catalog = catalog(&image).unwrap();
        assert_eq!(catalog.entries.len(), 1);
        let entry = &catalog.entries[0];
        assert_eq!(entry.path, "/METADATA.TXT");
        assert_eq!(entry.icb_logical_block, 34);
        assert_eq!(entry.icb_partition_reference, 1);
        let mut output = Vec::new();
        let report = read_udf_file(
            entry,
            image.len() as u64,
            8,
            |offset, length| Ok(image[offset as usize..offset as usize + length].to_vec()),
            || false,
            |bytes| {
                output.extend_from_slice(bytes);
                Ok(())
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(output, b"metadata");
        assert_eq!(report.bytes_read, 8);
    }

    #[test]
    fn metadata_partition_rejects_unsafe_modes_and_backing_descriptors() {
        let mut rewritable = metadata_image();
        let partition = &mut rewritable[257 * SECTOR_BYTES..258 * SECTOR_BYTES];
        partition[184..188].copy_from_slice(&3_u32.to_le_bytes());
        finish_tag(partition, 5, 257, 496);
        assert!(matches!(
            catalog(&rewritable),
            Err(UdfError::Unsupported(_))
        ));

        let mut false_duplicate = metadata_image();
        let logical = &mut false_duplicate[258 * SECTOR_BYTES..259 * SECTOR_BYTES];
        logical[446 + 58] = 1;
        finish_tag(logical, 6, 258, 494);
        assert!(matches!(
            catalog(&false_duplicate),
            Err(UdfError::InvalidStructure(_))
        ));

        let mut unrecorded = metadata_image();
        let main = &mut unrecorded[PARTITION_START as usize * SECTOR_BYTES
            ..(PARTITION_START as usize + 1) * SECTOR_BYTES];
        main[176..180].copy_from_slice(&(0x4000_0000 | (32 * SECTOR_BYTES as u32)).to_le_bytes());
        finish_tag(main, 261, 0, 176);
        assert!(matches!(
            catalog(&unrecorded),
            Err(UdfError::InvalidStructure(_))
        ));
    }

    #[test]
    fn corrupt_descriptor_crc_is_rejected() {
        let mut image = image();
        image[258 * SECTOR_BYTES + 212] ^= 1;
        assert!(matches!(
            catalog(&image),
            Err(UdfError::InvalidStructure(_))
        ));
    }

    #[test]
    fn incomplete_type_two_partition_maps_are_explicitly_unsupported() {
        let mut image = image();
        image[258 * SECTOR_BYTES + 440] = 2;
        let descriptor = &mut image[258 * SECTOR_BYTES..259 * SECTOR_BYTES];
        finish_tag(descriptor, 6, 258, 430);
        assert!(matches!(catalog(&image), Err(UdfError::Unsupported(_))));
    }

    #[test]
    fn recognition_and_redundant_anchor_are_both_required() {
        let mut no_recognition = image();
        no_recognition[17 * SECTOR_BYTES + 1] = 0;
        assert!(matches!(
            catalog(&no_recognition),
            Err(UdfError::InvalidStructure(_))
        ));

        let mut no_backup = image();
        no_backup[299 * SECTOR_BYTES + 4] ^= 1;
        assert!(matches!(
            catalog(&no_backup),
            Err(UdfError::InvalidStructure(_))
        ));
    }

    #[test]
    fn cancelled_reads_publish_no_partial_claim() {
        let image = image();
        let catalog = catalog(&image).unwrap();
        let mut output = Vec::new();
        let report = read_udf_file(
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
}
