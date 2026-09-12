//! Bounded structural parsing for ISO 9660 El Torito boot catalogs.
//!
//! This module does not install boot code. It establishes the source authority
//! an installer must consume: a boot record from a terminated ISO descriptor
//! sequence, a checksummed catalog validation entry, and bounded boot entries
//! whose declared load spans remain inside the image.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ISO_BLOCK_BYTES: usize = 2048;
const FIRST_DESCRIPTOR_BLOCK: u64 = 16;
const CATALOG_ENTRY_BYTES: usize = 32;
const EL_TORITO_ID: &[u8] = b"EL TORITO SPECIFICATION";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElToritoConfig {
    pub total_bytes: u64,
    pub max_descriptors: u16,
    pub max_catalog_entries: u16,
}

impl ElToritoConfig {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            max_descriptors: 64,
            max_catalog_entries: 63,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElToritoPlatform {
    X86,
    PowerPc,
    Mac,
    Efi,
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElToritoEmulation {
    None,
    Floppy1200Kib,
    Floppy1440Kib,
    Floppy2880Kib,
    HardDisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElToritoBootEntry {
    pub platform: ElToritoPlatform,
    pub bootable: bool,
    pub emulation: ElToritoEmulation,
    pub load_segment: u16,
    pub system_type: u8,
    pub load_sector_count: u16,
    pub image_lba: u32,
    pub image_offset: u64,
    pub declared_load_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElToritoCatalog {
    pub catalog_lba: u32,
    pub validation_platform: ElToritoPlatform,
    pub entries: Vec<ElToritoBootEntry>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ElToritoError {
    #[error("the El Torito parser configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("could not read the ISO at byte {offset}: {reason}")]
    Read { offset: u64, reason: String },
    #[error("the ISO descriptor sequence is invalid: {0}")]
    InvalidDescriptor(String),
    #[error("the El Torito catalog is invalid: {0}")]
    InvalidCatalog(String),
}

/// Returns the one structurally valid El Torito catalog, or `None` when the
/// terminated ISO descriptor sequence contains no El Torito boot record.
pub fn catalog_el_torito(
    config: ElToritoConfig,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
) -> Result<Option<ElToritoCatalog>, ElToritoError> {
    validate_config(&config)?;
    let mut catalog_lba = None;
    let mut terminated = false;
    for index in 0..config.max_descriptors {
        let offset = (FIRST_DESCRIPTOR_BLOCK + u64::from(index)) * ISO_BLOCK_BYTES as u64;
        require_span(
            offset,
            ISO_BLOCK_BYTES as u64,
            config.total_bytes,
            "descriptor",
        )?;
        let descriptor = read_exact(&mut read, offset, ISO_BLOCK_BYTES)?;
        if descriptor.get(1..6) != Some(b"CD001") || descriptor.get(6) != Some(&1) {
            return Err(ElToritoError::InvalidDescriptor(format!(
                "descriptor {index} has an invalid identifier or version"
            )));
        }
        match descriptor[0] {
            0 if trim_ascii_spaces(&descriptor[7..39]) == EL_TORITO_ID => {
                let observed = le_u32(&descriptor, 71, "boot-catalog LBA")?;
                if observed == 0 {
                    return Err(ElToritoError::InvalidDescriptor(
                        "the boot record points to LBA zero".into(),
                    ));
                }
                if catalog_lba.replace(observed).is_some() {
                    return Err(ElToritoError::InvalidDescriptor(
                        "more than one El Torito boot record is present".into(),
                    ));
                }
            }
            255 => {
                terminated = true;
                break;
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(ElToritoError::InvalidDescriptor(
            "the descriptor sequence has no terminator within its limit".into(),
        ));
    }
    let Some(catalog_lba) = catalog_lba else {
        return Ok(None);
    };
    let catalog_offset = u64::from(catalog_lba)
        .checked_mul(ISO_BLOCK_BYTES as u64)
        .ok_or_else(|| ElToritoError::InvalidCatalog("catalog offset overflowed".into()))?;
    require_span(
        catalog_offset,
        ISO_BLOCK_BYTES as u64,
        config.total_bytes,
        "boot catalog",
    )?;
    let bytes = read_exact(&mut read, catalog_offset, ISO_BLOCK_BYTES)?;
    parse_catalog(&config, catalog_lba, &bytes)
}

fn parse_catalog(
    config: &ElToritoConfig,
    catalog_lba: u32,
    bytes: &[u8],
) -> Result<Option<ElToritoCatalog>, ElToritoError> {
    let validation = bytes
        .get(..CATALOG_ENTRY_BYTES)
        .ok_or_else(|| ElToritoError::InvalidCatalog("validation entry is truncated".into()))?;
    if validation[0] != 1 || validation[30..32] != [0x55, 0xAA] {
        return Err(ElToritoError::InvalidCatalog(
            "validation header or key bytes are invalid".into(),
        ));
    }
    let checksum = validation
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_le_bytes(*word))
        .fold(0_u16, u16::wrapping_add);
    if checksum != 0 {
        return Err(ElToritoError::InvalidCatalog(
            "the validation-entry checksum is invalid".into(),
        ));
    }
    let validation_platform = platform(validation[1]);
    let mut entries = Vec::new();
    let mut cursor = CATALOG_ENTRY_BYTES;
    parse_boot_entry(
        config,
        validation_platform,
        entry_at(bytes, cursor)?,
        &mut entries,
    )?;
    cursor += CATALOG_ENTRY_BYTES;

    let mut saw_final_section = false;
    while cursor < bytes.len() && bytes[cursor..].iter().any(|byte| *byte != 0) {
        if entries.len() >= config.max_catalog_entries as usize {
            return Err(ElToritoError::InvalidCatalog(
                "the catalog exceeds the configured entry limit".into(),
            ));
        }
        let header = entry_at(bytes, cursor)?;
        if !matches!(header[0], 0x90 | 0x91) {
            return Err(ElToritoError::InvalidCatalog(format!(
                "entry {} is not a section header",
                cursor / CATALOG_ENTRY_BYTES
            )));
        }
        if saw_final_section {
            return Err(ElToritoError::InvalidCatalog(
                "catalog data follows the final section".into(),
            ));
        }
        let section_platform = platform(header[1]);
        let count = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if count == 0 || entries.len().saturating_add(count) > config.max_catalog_entries as usize {
            return Err(ElToritoError::InvalidCatalog(
                "a section count is zero or exceeds the configured limit".into(),
            ));
        }
        saw_final_section = header[0] == 0x91;
        cursor += CATALOG_ENTRY_BYTES;
        for _ in 0..count {
            parse_boot_entry(
                config,
                section_platform,
                entry_at(bytes, cursor)?,
                &mut entries,
            )?;
            cursor += CATALOG_ENTRY_BYTES;
        }
    }
    Ok(Some(ElToritoCatalog {
        catalog_lba,
        validation_platform,
        entries,
    }))
}

fn parse_boot_entry(
    config: &ElToritoConfig,
    entry_platform: ElToritoPlatform,
    entry: &[u8],
    entries: &mut Vec<ElToritoBootEntry>,
) -> Result<(), ElToritoError> {
    let bootable = match entry[0] {
        0x88 => true,
        0x00 => false,
        0x44 => {
            return Err(ElToritoError::InvalidCatalog(
                "section-entry extensions are not supported".into(),
            ));
        }
        value => {
            return Err(ElToritoError::InvalidCatalog(format!(
                "boot entry indicator 0x{value:02X} is invalid"
            )));
        }
    };
    let emulation = match entry[1] {
        0 => ElToritoEmulation::None,
        1 => ElToritoEmulation::Floppy1200Kib,
        2 => ElToritoEmulation::Floppy1440Kib,
        3 => ElToritoEmulation::Floppy2880Kib,
        4 => ElToritoEmulation::HardDisk,
        value => {
            return Err(ElToritoError::InvalidCatalog(format!(
                "boot entry media type {value} is undefined"
            )));
        }
    };
    let load_sector_count = u16::from_le_bytes([entry[6], entry[7]]);
    let image_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
    if bootable && (load_sector_count == 0 || image_lba == 0) {
        return Err(ElToritoError::InvalidCatalog(
            "a bootable entry has no load sectors or image LBA".into(),
        ));
    }
    let declared_load_bytes = u64::from(load_sector_count) * 512;
    let image_offset = u64::from(image_lba)
        .checked_mul(ISO_BLOCK_BYTES as u64)
        .ok_or_else(|| ElToritoError::InvalidCatalog("boot-image offset overflowed".into()))?;
    if bootable {
        require_span(
            image_offset,
            declared_load_bytes,
            config.total_bytes,
            "boot image",
        )?;
    }
    entries.push(ElToritoBootEntry {
        platform: entry_platform,
        bootable,
        emulation,
        load_segment: u16::from_le_bytes([entry[2], entry[3]]),
        system_type: entry[4],
        load_sector_count,
        image_lba,
        image_offset,
        declared_load_bytes,
    });
    Ok(())
}

fn entry_at(bytes: &[u8], offset: usize) -> Result<&[u8], ElToritoError> {
    bytes
        .get(offset..offset + CATALOG_ENTRY_BYTES)
        .ok_or_else(|| ElToritoError::InvalidCatalog("a catalog entry is truncated".into()))
}

fn platform(value: u8) -> ElToritoPlatform {
    match value {
        0x00 => ElToritoPlatform::X86,
        0x01 => ElToritoPlatform::PowerPc,
        0x02 => ElToritoPlatform::Mac,
        0xEF => ElToritoPlatform::Efi,
        value => ElToritoPlatform::Unknown(value),
    }
}

fn trim_ascii_spaces(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != 0)
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

fn validate_config(config: &ElToritoConfig) -> Result<(), ElToritoError> {
    if config.total_bytes < (FIRST_DESCRIPTOR_BLOCK + 2) * ISO_BLOCK_BYTES as u64
        || config.max_descriptors == 0
        || config.max_catalog_entries == 0
        || config.max_catalog_entries as usize > ISO_BLOCK_BYTES / CATALOG_ENTRY_BYTES - 1
    {
        return Err(ElToritoError::InvalidConfiguration(
            "source size and descriptor/catalog limits must be bounded and usable".into(),
        ));
    }
    Ok(())
}

fn require_span(offset: u64, length: u64, total: u64, name: &str) -> Result<(), ElToritoError> {
    if length == 0 || offset.checked_add(length).is_none_or(|end| end > total) {
        return Err(ElToritoError::InvalidCatalog(format!(
            "the {name} span lies outside the source"
        )));
    }
    Ok(())
}

fn read_exact(
    read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, ElToritoError> {
    let bytes = read(offset, length).map_err(|reason| ElToritoError::Read { offset, reason })?;
    if bytes.len() != length {
        return Err(ElToritoError::Read {
            offset,
            reason: format!("requested {length} bytes but received {}", bytes.len()),
        });
    }
    Ok(bytes)
}

fn le_u32(bytes: &[u8], offset: usize, name: &str) -> Result<u32, ElToritoError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ElToritoError::InvalidDescriptor(format!("{name} is truncated")))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_BLOCKS: usize = 48;
    const CATALOG_LBA: usize = 20;
    const BOOT_IMAGE_LBA: usize = 24;

    fn fixture() -> Vec<u8> {
        let mut image = vec![0_u8; IMAGE_BLOCKS * ISO_BLOCK_BYTES];
        let boot = 16 * ISO_BLOCK_BYTES;
        image[boot] = 0;
        image[boot + 1..boot + 6].copy_from_slice(b"CD001");
        image[boot + 6] = 1;
        image[boot + 7..boot + 7 + EL_TORITO_ID.len()].copy_from_slice(EL_TORITO_ID);
        image[boot + 71..boot + 75].copy_from_slice(&(CATALOG_LBA as u32).to_le_bytes());
        let terminator = 17 * ISO_BLOCK_BYTES;
        image[terminator] = 255;
        image[terminator + 1..terminator + 6].copy_from_slice(b"CD001");
        image[terminator + 6] = 1;

        let catalog = CATALOG_LBA * ISO_BLOCK_BYTES;
        image[catalog] = 1;
        image[catalog + 1] = 0;
        image[catalog + 30] = 0x55;
        image[catalog + 31] = 0xAA;
        let sum = image[catalog..catalog + 32]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|word| u16::from_le_bytes(*word))
            .fold(0_u16, u16::wrapping_add);
        image[catalog + 28..catalog + 30].copy_from_slice(&sum.wrapping_neg().to_le_bytes());

        let entry = catalog + 32;
        image[entry] = 0x88;
        image[entry + 1] = 0;
        image[entry + 2..entry + 4].copy_from_slice(&0x07C0_u16.to_le_bytes());
        image[entry + 6..entry + 8].copy_from_slice(&4_u16.to_le_bytes());
        image[entry + 8..entry + 12].copy_from_slice(&(BOOT_IMAGE_LBA as u32).to_le_bytes());
        image
    }

    fn parse(image: &[u8]) -> Result<Option<ElToritoCatalog>, ElToritoError> {
        catalog_el_torito(ElToritoConfig::new(image.len() as u64), |offset, length| {
            let start = usize::try_from(offset).map_err(|error| error.to_string())?;
            image
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "read escaped fixture".into())
        })
    }

    #[test]
    fn checksummed_x86_no_emulation_entry_is_bounded_and_exact() {
        let catalog = parse(&fixture()).unwrap().unwrap();
        assert_eq!(catalog.catalog_lba, CATALOG_LBA as u32);
        assert_eq!(catalog.validation_platform, ElToritoPlatform::X86);
        assert_eq!(catalog.entries.len(), 1);
        let entry = &catalog.entries[0];
        assert!(entry.bootable);
        assert_eq!(entry.emulation, ElToritoEmulation::None);
        assert_eq!(entry.load_segment, 0x07C0);
        assert_eq!(
            entry.image_offset,
            (BOOT_IMAGE_LBA * ISO_BLOCK_BYTES) as u64
        );
        assert_eq!(entry.declared_load_bytes, 2048);
    }

    #[test]
    fn no_boot_record_is_distinct_from_a_corrupt_catalog() {
        let mut image = fixture();
        image[16 * ISO_BLOCK_BYTES] = 1;
        assert!(parse(&image).unwrap().is_none());

        let mut corrupt = fixture();
        corrupt[CATALOG_LBA * ISO_BLOCK_BYTES + 4] ^= 1;
        assert!(matches!(
            parse(&corrupt),
            Err(ElToritoError::InvalidCatalog(_))
        ));
    }

    #[test]
    fn invalid_keys_media_codes_and_load_spans_are_refused() {
        let mut keys = fixture();
        keys[CATALOG_LBA * ISO_BLOCK_BYTES + 30] = 0;
        assert!(parse(&keys).is_err());

        let mut media = fixture();
        media[CATALOG_LBA * ISO_BLOCK_BYTES + 33] = 5;
        assert!(parse(&media).is_err());

        let mut span = fixture();
        let entry = CATALOG_LBA * ISO_BLOCK_BYTES + 32;
        span[entry + 8..entry + 12].copy_from_slice(&(IMAGE_BLOCKS as u32).to_le_bytes());
        assert!(parse(&span).is_err());
    }

    #[test]
    fn section_platform_and_final_boundary_are_preserved() {
        let mut image = fixture();
        let catalog = CATALOG_LBA * ISO_BLOCK_BYTES;
        let header = catalog + 64;
        image[header] = 0x91;
        image[header + 1] = 0xEF;
        image[header + 2..header + 4].copy_from_slice(&1_u16.to_le_bytes());
        let entry = header + 32;
        image[entry] = 0x88;
        image[entry + 6..entry + 8].copy_from_slice(&1_u16.to_le_bytes());
        image[entry + 8..entry + 12].copy_from_slice(&(BOOT_IMAGE_LBA as u32).to_le_bytes());
        let parsed = parse(&image).unwrap().unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[1].platform, ElToritoPlatform::Efi);
    }
}
