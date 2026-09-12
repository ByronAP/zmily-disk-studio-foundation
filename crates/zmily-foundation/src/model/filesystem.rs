//! Filesystem identification.
//!
//! Three independent sources, in increasing order of authority:
//!
//! 1. **The volume layer** — what `GetVolumeInformationW` reports. Only ever
//!    available for filesystems Windows can actually mount, so a Linux or macOS
//!    partition is invisible here no matter how it is formatted.
//! 2. **The GPT partition type GUID** — declares *intent*, and survives the volume
//!    being unmountable. A partition tagged "Linux filesystem" tells us it is not
//!    free space even though Windows shows no volume for it.
//! 3. **The on-disk superblock** — the ground truth. Reading a few sectors from the
//!    start of the partition identifies the filesystem regardless of what the
//!    partition table claims.
//!
//! This matters because ZMILY's headline safety property is never destroying data
//! it did not understand. A partition Windows cannot mount must still be shown as
//! occupied, labelled with what it actually holds, and protected from operations
//! that assume it is empty.

use serde::{Deserialize, Serialize};

/// Maximum length of one FAT32 directory entry's file, shared by all workflows.
pub const FAT32_MAX_FILE_BYTES: u64 = u32::MAX as u64;

/// Filesystem occupying a partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemType {
    // Windows-native
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Refs,
    Udf,
    Cdfs,

    // Linux
    Ext2,
    Ext3,
    Ext4,
    Btrfs,
    Xfs,
    Zfs,
    F2fs,
    LinuxSwap,
    /// LVM physical volume — a container, not a filesystem.
    LinuxLvm,
    /// Linux software RAID member.
    LinuxRaid,

    // Apple
    Apfs,
    HfsPlus,

    /// Partition exists but carries no recognized filesystem.
    Unformatted,
    /// A name we were given but do not recognize.
    Other(String),
}

/// How a filesystem was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// Reported by Windows for a mounted volume.
    MountedVolume,
    /// Inferred from the GPT partition type GUID or MBR type byte.
    PartitionType,
    /// Read from the filesystem's own superblock.
    Superblock,
}

impl FilesystemType {
    /// The established single-file ceiling used by persistence preparation.
    /// Unknown and other filesystems retain their existing create-new I/O behavior.
    pub const fn known_file_size_limit_bytes(&self) -> Option<u64> {
        match self {
            Self::Fat32 => Some(FAT32_MAX_FILE_BYTES),
            _ => None,
        }
    }

    /// Maps the filesystem name Windows reports (`GetVolumeInformationW`) onto a variant.
    ///
    /// Third-party drivers (Paragon, WinBtrfs, and similar) mount foreign
    /// filesystems and report their real names here, so the Linux and Apple
    /// variants are reachable through this path on machines that have them.
    pub fn from_windows_name(name: &str) -> Self {
        match name.trim().to_ascii_uppercase().as_str() {
            "NTFS" => FilesystemType::Ntfs,
            "FAT32" => FilesystemType::Fat32,
            "FAT" | "FAT16" => FilesystemType::Fat16,
            "FAT12" => FilesystemType::Fat12,
            "EXFAT" => FilesystemType::ExFat,
            "REFS" => FilesystemType::Refs,
            "UDF" => FilesystemType::Udf,
            "CDFS" => FilesystemType::Cdfs,

            "EXT2" => FilesystemType::Ext2,
            "EXT3" => FilesystemType::Ext3,
            "EXT4" => FilesystemType::Ext4,
            "BTRFS" => FilesystemType::Btrfs,
            "XFS" => FilesystemType::Xfs,
            "ZFS" => FilesystemType::Zfs,
            "F2FS" => FilesystemType::F2fs,

            "APFS" => FilesystemType::Apfs,
            "HFS+" | "HFSPLUS" | "HFS" => FilesystemType::HfsPlus,

            "" | "RAW" => FilesystemType::Unformatted,
            other => FilesystemType::Other(other.to_string()),
        }
    }

    /// Infers a filesystem from a GPT partition type GUID.
    ///
    /// This is a declaration of intent, not proof: a partition tagged "Linux
    /// filesystem" could hold ext4, btrfs, or xfs. Callers that need certainty
    /// should read the superblock.
    pub fn from_gpt_type_guid(guid: &str) -> Option<Self> {
        match guid.to_ascii_lowercase().as_str() {
            gpt_type::LINUX_SWAP => Some(FilesystemType::LinuxSwap),
            gpt_type::LINUX_LVM => Some(FilesystemType::LinuxLvm),
            gpt_type::LINUX_RAID => Some(FilesystemType::LinuxRaid),
            gpt_type::APPLE_APFS => Some(FilesystemType::Apfs),
            gpt_type::APPLE_HFS_PLUS => Some(FilesystemType::HfsPlus),
            gpt_type::FREEBSD_ZFS | gpt_type::SOLARIS_ZFS => Some(FilesystemType::Zfs),
            // The generic Linux GUIDs say "some Linux filesystem" without saying
            // which, so they resolve to nothing rather than a guess.
            _ => None,
        }
    }

    /// Infers a filesystem from an MBR partition type byte.
    ///
    /// Hidden partitions are resolved through their visible counterpart: OS/2's
    /// Boot Manager marks a partition hidden by adding `0x10`, so `0x1B` holds
    /// FAT32 exactly as `0x0B` does.
    pub fn from_mbr_type(byte: u8) -> Option<Self> {
        let byte = crate::model::mbr_type::unhidden(byte).unwrap_or(byte);

        match byte {
            0x01 => Some(FilesystemType::Fat12),
            0x04 | 0x06 | 0x0E => Some(FilesystemType::Fat16),
            // NTFS *or* exFAT — they share the byte, so the superblock settles it.
            0x07 => None,
            0x0B | 0x0C => Some(FilesystemType::Fat32),
            // Fault-tolerant mirror halves carry the filesystem they mirror.
            0x86 => Some(FilesystemType::Fat16),
            0x82 => Some(FilesystemType::LinuxSwap),
            0x8E => Some(FilesystemType::LinuxLvm),
            0xFD => Some(FilesystemType::LinuxRaid),
            0xAF => Some(FilesystemType::HfsPlus),
            _ => None,
        }
    }

    /// Whether ZMILY can resize this filesystem in place.
    pub fn is_resizable(&self) -> bool {
        matches!(self, FilesystemType::Ntfs)
    }

    /// Whether ZMILY understands this filesystem's on-disk layout well enough to
    /// move or shrink it by relocating its clusters.
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            FilesystemType::Ntfs
                | FilesystemType::Fat32
                | FilesystemType::Fat16
                | FilesystemType::Fat12
                | FilesystemType::ExFat
        )
    }

    /// True for filesystems Windows cannot mount natively.
    ///
    /// These are shown, protected, and moved as opaque blocks: ZMILY will relocate
    /// them sector-for-sector but will never attempt to resize or reinterpret them.
    pub fn is_foreign(&self) -> bool {
        matches!(
            self,
            FilesystemType::Ext2
                | FilesystemType::Ext3
                | FilesystemType::Ext4
                | FilesystemType::Btrfs
                | FilesystemType::Xfs
                | FilesystemType::Zfs
                | FilesystemType::F2fs
                | FilesystemType::LinuxSwap
                | FilesystemType::LinuxLvm
                | FilesystemType::LinuxRaid
                | FilesystemType::Apfs
                | FilesystemType::HfsPlus
        )
    }

    /// True when the partition holds data ZMILY must not treat as free space.
    pub fn holds_data(&self) -> bool {
        !matches!(self, FilesystemType::Unformatted)
    }
}

impl std::fmt::Display for FilesystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FilesystemType::Ntfs => "NTFS",
            FilesystemType::Fat12 => "FAT12",
            FilesystemType::Fat16 => "FAT16",
            FilesystemType::Fat32 => "FAT32",
            FilesystemType::ExFat => "exFAT",
            FilesystemType::Refs => "ReFS",
            FilesystemType::Udf => "UDF",
            FilesystemType::Cdfs => "CDFS",
            FilesystemType::Ext2 => "ext2",
            FilesystemType::Ext3 => "ext3",
            FilesystemType::Ext4 => "ext4",
            FilesystemType::Btrfs => "Btrfs",
            FilesystemType::Xfs => "XFS",
            FilesystemType::Zfs => "ZFS",
            FilesystemType::F2fs => "F2FS",
            FilesystemType::LinuxSwap => "Linux swap",
            FilesystemType::LinuxLvm => "Linux LVM",
            FilesystemType::LinuxRaid => "Linux RAID",
            FilesystemType::Apfs => "APFS",
            FilesystemType::HfsPlus => "HFS+",
            FilesystemType::Unformatted => "Unformatted",
            FilesystemType::Other(name) => name,
        };
        f.write_str(s)
    }
}

/// Well-known GPT partition type GUIDs, lowercase and hyphenated.
pub mod gpt_type {
    pub const EFI_SYSTEM: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
    pub const MICROSOFT_RESERVED: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
    pub const BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    pub const WINDOWS_RECOVERY: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";
    pub const LDM_METADATA: &str = "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3";
    pub const LDM_DATA: &str = "af9b60a0-1431-4f62-bc68-3311714a69ad";

    /// Generic Linux data or root.
    ///
    /// **Read from real hardware**, not from a reference: disk 2 of the machine
    /// this was developed on carries a Linux partition reporting exactly this
    /// GUID through `IOCTL_DISK_GET_DRIVE_LAYOUT_EX`. A partition-type table
    /// supplied during development gave `0fc63daa` — one character out — and
    /// adopting it would have silently stopped ZMILY recognising Linux
    /// partitions, which is how a dual-boot user's root looks like free space.
    pub const LINUX_FILESYSTEM: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    pub const LINUX_SWAP: &str = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f";
    pub const LINUX_LVM: &str = "e6d6d379-f507-44c2-a23c-238f2a3df928";
    pub const LINUX_RAID: &str = "a19d880f-05fc-4d3b-a006-743f0f84911e";
    pub const LINUX_HOME: &str = "933ac7e1-2eb4-4f13-b844-0e14e2aef915";
    pub const LINUX_ROOT_X86_64: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
    pub const LINUX_ROOT_ARM64: &str = "b921b045-1df0-41c3-af44-4c6f280d3fae";

    /// Second-stage bootloader for BIOS booting from GPT.
    ///
    /// Self-checking: the bytes spell `Hah!IdontNeedEFI` once the mixed-endian
    /// field order is undone. See `bios_boot_and_apple_guids_spell_words`.
    pub const BIOS_BOOT: &str = "21686148-6449-6e6f-744e-656564454649";

    /// XBOOTLDR — a boot partition holding kernels and initramfs.
    pub const LINUX_BOOT: &str = "bc13c2ff-59e6-4262-a352-b175e03be99f";

    pub const APPLE_APFS: &str = "7c3457ef-0000-11aa-aa11-00306543ecac";
    pub const APPLE_HFS_PLUS: &str = "48465300-0000-11aa-aa11-00306543ecac";
    pub const APPLE_BOOT: &str = "426f6f74-0000-11aa-aa11-00306543ecac";

    /// Physical volume behind FileVault and Fusion Drive.
    ///
    /// Note the shape: five groups, `53746f72-6167-11aa-...`. A table supplied
    /// during development wrote it with six groups, which is not a GUID at all —
    /// the kind of error that is visible without any reference to check against.
    pub const APPLE_CORE_STORAGE: &str = "53746f72-6167-11aa-aa11-00306543ecac";

    /// FreeBSD data, swap, and ZFS differ only in the last digit of the first
    /// field — b4, b5, ba — which is what makes the family checkable.
    pub const FREEBSD_DATA: &str = "516e7cb4-6ecf-11d6-8ff8-00022d09712b";
    pub const FREEBSD_SWAP: &str = "516e7cb5-6ecf-11d6-8ff8-00022d09712b";
    pub const FREEBSD_ZFS: &str = "516e7cba-6ecf-11d6-8ff8-00022d09712b";
    pub const SOLARIS_ZFS: &str = "6a898cc3-1dd2-11b2-99a6-080020736631";

    /// True for any GUID that marks a Linux-owned partition.
    pub fn is_linux(guid: &str) -> bool {
        matches!(
            guid.to_ascii_lowercase().as_str(),
            LINUX_FILESYSTEM
                | LINUX_SWAP
                | LINUX_LVM
                | LINUX_RAID
                | LINUX_HOME
                | LINUX_ROOT_X86_64
                | LINUX_ROOT_ARM64
                | LINUX_BOOT
        )
    }

    /// True for any GUID that marks an Apple-owned partition.
    pub fn is_apple(guid: &str) -> bool {
        matches!(
            guid.to_ascii_lowercase().as_str(),
            APPLE_APFS | APPLE_HFS_PLUS | APPLE_BOOT | APPLE_CORE_STORAGE
        )
    }
}

/// Number of bytes from the start of a partition needed by [`detect_from_superblock`].
///
/// Btrfs keeps its primary superblock at 64 KiB, which is the deepest probe here.
pub const SUPERBLOCK_PROBE_LEN: usize = 68 * 1024;

/// Identifies a filesystem from the bytes at the start of a partition.
///
/// `data` should begin at the partition's first sector and be at least
/// [`SUPERBLOCK_PROBE_LEN`] long; shorter buffers still work but can only match
/// the signatures that fall inside them.
///
/// Returns `None` when nothing matches, which is not the same as "empty" — an
/// unrecognized filesystem is still data.
pub fn detect_from_superblock(data: &[u8]) -> Option<FilesystemType> {
    // Order matters: FAT and NTFS share a boot-sector layout, and ext's magic sits
    // far enough in that a FAT volume could coincidentally contain those bytes.
    detect_windows_family(data)
        .or_else(|| detect_ext_family(data))
        .or_else(|| detect_btrfs(data))
        .or_else(|| detect_xfs(data))
        .or_else(|| detect_f2fs(data))
        .or_else(|| detect_apple(data))
        .or_else(|| detect_linux_swap(data))
}

fn magic_at(data: &[u8], offset: usize, magic: &[u8]) -> bool {
    data.len() >= offset + magic.len() && &data[offset..offset + magic.len()] == magic
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// NTFS, exFAT, and FAT all identify themselves in the boot sector.
fn detect_windows_family(data: &[u8]) -> Option<FilesystemType> {
    if magic_at(data, 3, b"NTFS    ") {
        return Some(FilesystemType::Ntfs);
    }
    if magic_at(data, 3, b"EXFAT   ") {
        return Some(FilesystemType::ExFat);
    }
    // FAT32 puts its type string in the extended BPB; FAT12/16 use an earlier one.
    if magic_at(data, 82, b"FAT32   ") {
        return Some(FilesystemType::Fat32);
    }
    if magic_at(data, 54, b"FAT16   ") {
        return Some(FilesystemType::Fat16);
    }
    if magic_at(data, 54, b"FAT12   ") {
        return Some(FilesystemType::Fat12);
    }
    None
}

/// ext2/3/4 superblock: magic 0xEF53 at byte 1080, feature flags just after.
fn detect_ext_family(data: &[u8]) -> Option<FilesystemType> {
    const SUPERBLOCK_OFFSET: usize = 1024;
    const MAGIC_OFFSET: usize = SUPERBLOCK_OFFSET + 0x38;

    if u16_at(data, MAGIC_OFFSET)? != 0xEF53 {
        return None;
    }

    let compat = u32_at(data, SUPERBLOCK_OFFSET + 0x5C).unwrap_or(0);
    let incompat = u32_at(data, SUPERBLOCK_OFFSET + 0x60).unwrap_or(0);
    let ro_compat = u32_at(data, SUPERBLOCK_OFFSET + 0x64).unwrap_or(0);

    const HAS_JOURNAL: u32 = 0x0004;
    // Any of these being set means the driver must be ext4-capable.
    const INCOMPAT_EXT4: u32 = 0x0040 /* extents */ | 0x0080 /* 64bit */ | 0x0200 /* flex_bg */;
    const RO_COMPAT_EXT4: u32 = 0x0008 /* huge_file */ | 0x0010 /* gdt_csum */
        | 0x0020 /* dir_nlink */ | 0x0040 /* extra_isize */ | 0x0400 /* metadata_csum */;

    if incompat & INCOMPAT_EXT4 != 0 || ro_compat & RO_COMPAT_EXT4 != 0 {
        Some(FilesystemType::Ext4)
    } else if compat & HAS_JOURNAL != 0 {
        Some(FilesystemType::Ext3)
    } else {
        Some(FilesystemType::Ext2)
    }
}

/// Btrfs keeps its primary superblock at 64 KiB, magic at +0x40 within it.
fn detect_btrfs(data: &[u8]) -> Option<FilesystemType> {
    magic_at(data, 0x10040, b"_BHRfS_M").then_some(FilesystemType::Btrfs)
}

/// XFS puts a big-endian "XFSB" at offset zero.
fn detect_xfs(data: &[u8]) -> Option<FilesystemType> {
    magic_at(data, 0, b"XFSB").then_some(FilesystemType::Xfs)
}

/// F2FS superblock begins at 1 KiB with a little-endian magic.
fn detect_f2fs(data: &[u8]) -> Option<FilesystemType> {
    (u32_at(data, 1024)? == 0xF2F5_2010).then_some(FilesystemType::F2fs)
}

fn detect_apple(data: &[u8]) -> Option<FilesystemType> {
    // APFS container superblock: "NXSB" at +0x20 of the first block.
    if magic_at(data, 0x20, b"NXSB") {
        return Some(FilesystemType::Apfs);
    }
    // HFS+ volume header sits at 1 KiB; "H+" is HFS+, "HX" is HFSX.
    if magic_at(data, 1024, b"H+") || magic_at(data, 1024, b"HX") {
        return Some(FilesystemType::HfsPlus);
    }
    None
}

/// A swap area writes its signature at the end of the first 4 KiB page.
fn detect_linux_swap(data: &[u8]) -> Option<FilesystemType> {
    const SIGNATURE_OFFSET: usize = 4096 - 10;

    (magic_at(data, SIGNATURE_OFFSET, b"SWAPSPACE2")
        || magic_at(data, SIGNATURE_OFFSET, b"SWAP-SPACE"))
    .then_some(FilesystemType::LinuxSwap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer() -> Vec<u8> {
        vec![0u8; SUPERBLOCK_PROBE_LEN]
    }

    fn write(data: &mut [u8], offset: usize, bytes: &[u8]) {
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn windows_names_still_map() {
        assert_eq!(
            FilesystemType::from_windows_name("ntfs"),
            FilesystemType::Ntfs
        );
        assert_eq!(
            FilesystemType::from_windows_name(" FAT32 "),
            FilesystemType::Fat32
        );
        assert_eq!(
            FilesystemType::from_windows_name(""),
            FilesystemType::Unformatted
        );
    }

    #[test]
    fn third_party_drivers_reporting_foreign_names_are_recognized() {
        // WinBtrfs, Paragon extFS, and friends surface these through Windows.
        assert_eq!(
            FilesystemType::from_windows_name("ext4"),
            FilesystemType::Ext4
        );
        assert_eq!(
            FilesystemType::from_windows_name("Btrfs"),
            FilesystemType::Btrfs
        );
        assert_eq!(
            FilesystemType::from_windows_name("APFS"),
            FilesystemType::Apfs
        );
        assert!(matches!(
            FilesystemType::from_windows_name("jfs"),
            FilesystemType::Other(_)
        ));
    }

    #[test]
    fn gpt_guids_identify_specific_filesystems() {
        assert_eq!(
            FilesystemType::from_gpt_type_guid(gpt_type::LINUX_SWAP),
            Some(FilesystemType::LinuxSwap)
        );
        assert_eq!(
            FilesystemType::from_gpt_type_guid(gpt_type::APPLE_APFS),
            Some(FilesystemType::Apfs)
        );
        assert_eq!(
            FilesystemType::from_gpt_type_guid(gpt_type::FREEBSD_ZFS),
            Some(FilesystemType::Zfs)
        );
    }

    #[test]
    fn the_generic_linux_guid_does_not_guess_a_filesystem() {
        // It could be ext4, btrfs, or xfs — claiming one would be a lie.
        assert_eq!(
            FilesystemType::from_gpt_type_guid(gpt_type::LINUX_FILESYSTEM),
            None
        );
        assert!(gpt_type::is_linux(gpt_type::LINUX_FILESYSTEM));
    }

    #[test]
    fn guid_matching_is_case_insensitive() {
        assert_eq!(
            FilesystemType::from_gpt_type_guid("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"),
            Some(FilesystemType::LinuxSwap)
        );
        assert!(gpt_type::is_apple("48465300-0000-11AA-AA11-00306543ECAC"));
    }

    #[test]
    fn mbr_type_07_defers_to_the_superblock() {
        // 0x07 is used by both NTFS and exFAT, so the byte alone proves nothing.
        assert_eq!(FilesystemType::from_mbr_type(0x07), None);
        assert_eq!(
            FilesystemType::from_mbr_type(0x82),
            Some(FilesystemType::LinuxSwap)
        );
    }

    #[test]
    fn ntfs_and_exfat_boot_sectors_are_detected() {
        let mut data = buffer();
        write(&mut data, 3, b"NTFS    ");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ntfs));

        let mut data = buffer();
        write(&mut data, 3, b"EXFAT   ");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::ExFat));
    }

    #[test]
    fn fat_variants_are_distinguished_by_their_type_strings() {
        let mut data = buffer();
        write(&mut data, 82, b"FAT32   ");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Fat32));

        let mut data = buffer();
        write(&mut data, 54, b"FAT16   ");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Fat16));
    }

    fn ext_superblock(compat: u32, incompat: u32, ro_compat: u32) -> Vec<u8> {
        let mut data = buffer();
        write(&mut data, 1024 + 0x38, &0xEF53u16.to_le_bytes());
        write(&mut data, 1024 + 0x5C, &compat.to_le_bytes());
        write(&mut data, 1024 + 0x60, &incompat.to_le_bytes());
        write(&mut data, 1024 + 0x64, &ro_compat.to_le_bytes());
        data
    }

    #[test]
    fn ext2_has_no_journal_and_no_ext4_features() {
        let data = ext_superblock(0, 0, 0);
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ext2));
    }

    #[test]
    fn ext3_is_ext2_plus_a_journal() {
        let data = ext_superblock(0x0004, 0, 0);
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ext3));
    }

    #[test]
    fn ext4_is_identified_by_its_incompatible_features() {
        // Extents alone is enough — this is the common modern case.
        let data = ext_superblock(0x0004, 0x0040, 0);
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ext4));

        // metadata_csum is ro_compat only, and still means ext4.
        let data = ext_superblock(0x0004, 0, 0x0400);
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ext4));
    }

    #[test]
    fn a_wrong_ext_magic_is_not_matched() {
        let mut data = buffer();
        write(&mut data, 1024 + 0x38, &0x1234u16.to_le_bytes());
        assert_eq!(detect_from_superblock(&data), None);
    }

    #[test]
    fn btrfs_xfs_and_f2fs_are_detected() {
        let mut data = buffer();
        write(&mut data, 0x10040, b"_BHRfS_M");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Btrfs));

        let mut data = buffer();
        write(&mut data, 0, b"XFSB");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Xfs));

        let mut data = buffer();
        write(&mut data, 1024, &0xF2F5_2010u32.to_le_bytes());
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::F2fs));
    }

    #[test]
    fn apfs_and_hfs_plus_are_detected() {
        let mut data = buffer();
        write(&mut data, 0x20, b"NXSB");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Apfs));

        let mut data = buffer();
        write(&mut data, 1024, b"H+");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::HfsPlus));

        // HFSX is the case-sensitive variant and shares the layout.
        let mut data = buffer();
        write(&mut data, 1024, b"HX");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::HfsPlus));
    }

    #[test]
    fn linux_swap_signatures_are_detected() {
        for signature in [b"SWAPSPACE2", b"SWAP-SPACE"] {
            let mut data = buffer();
            write(&mut data, 4096 - 10, signature);
            assert_eq!(
                detect_from_superblock(&data),
                Some(FilesystemType::LinuxSwap)
            );
        }
    }

    #[test]
    fn an_empty_partition_matches_nothing() {
        assert_eq!(detect_from_superblock(&buffer()), None);
    }

    #[test]
    fn short_buffers_do_not_panic() {
        // Probing must degrade gracefully rather than index out of bounds.
        for len in [0usize, 1, 3, 64, 512, 1024, 1030, 4096] {
            let data = vec![0u8; len];
            let _ = detect_from_superblock(&data);
        }

        // A signature that fits in a short buffer is still found.
        let mut data = vec![0u8; 512];
        write(&mut data, 3, b"NTFS    ");
        assert_eq!(detect_from_superblock(&data), Some(FilesystemType::Ntfs));
    }

    #[test]
    fn foreign_filesystems_are_flagged_but_not_claimed_as_supported() {
        for fs in [
            FilesystemType::Ext4,
            FilesystemType::Btrfs,
            FilesystemType::Apfs,
            FilesystemType::LinuxSwap,
        ] {
            assert!(fs.is_foreign(), "{fs} should be foreign");
            assert!(!fs.is_supported(), "{fs} must not claim cluster support");
            assert!(!fs.is_resizable(), "{fs} must not claim resize support");
            assert!(fs.holds_data(), "{fs} must not be mistaken for free space");
        }
    }

    #[test]
    fn windows_filesystems_are_not_foreign() {
        assert!(!FilesystemType::Ntfs.is_foreign());
        assert!(FilesystemType::Ntfs.is_supported());
        assert!(!FilesystemType::Unformatted.holds_data());
    }

    #[test]
    fn display_names_are_conventional() {
        assert_eq!(FilesystemType::Ext4.to_string(), "ext4");
        assert_eq!(FilesystemType::HfsPlus.to_string(), "HFS+");
        assert_eq!(FilesystemType::LinuxSwap.to_string(), "Linux swap");
        assert_eq!(FilesystemType::ExFat.to_string(), "exFAT");
    }

    /// Some GPT type GUIDs encode ASCII, which makes them checkable rather than
    /// trusted. Decoding them is a real guard: a reference table supplied during
    /// development had Apple CoreStorage with *six* groups — not a GUID at all —
    /// and several Linux entries with a correct first field and an invented tail.
    #[test]
    fn bios_boot_and_apple_guids_spell_words() {
        /// The bytes of a GUID's first three fields, in the order they are
        /// written rather than stored, so the ASCII reads forwards.
        fn leading_ascii(guid: &str) -> String {
            guid.replace('-', "")
                .as_bytes()
                .chunks(2)
                .take(8)
                .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .map(|b| b as char)
                .collect()
        }

        assert!(
            leading_ascii(gpt_type::APPLE_HFS_PLUS).starts_with("HFS"),
            "Apple's HFS+ GUID spells HFS"
        );
        assert!(
            leading_ascii(gpt_type::APPLE_BOOT).starts_with("Boot"),
            "Apple's boot GUID spells Boot"
        );
        assert!(
            leading_ascii(gpt_type::APPLE_CORE_STORAGE).starts_with("Storag"),
            "Apple's CoreStorage GUID spells Storage"
        );

        // BIOS boot spells "Hah!IdontNeedEFI" once the mixed-endian field order
        // is undone, so it reads in pieces here.
        let bios = gpt_type::BIOS_BOOT.replace('-', "");
        assert_eq!(&bios[16..], "744e656564454649", "…tNeedEFI");
    }

    /// Every GPT type GUID must have the five groups a GUID has.
    ///
    /// Trivial to state and worth stating: a supplied reference table failed it,
    /// and the failure is invisible unless something checks.
    #[test]
    fn every_type_guid_is_shaped_like_a_guid() {
        let all = [
            gpt_type::EFI_SYSTEM,
            gpt_type::MICROSOFT_RESERVED,
            gpt_type::BASIC_DATA,
            gpt_type::WINDOWS_RECOVERY,
            gpt_type::LDM_METADATA,
            gpt_type::LDM_DATA,
            gpt_type::BIOS_BOOT,
            gpt_type::LINUX_FILESYSTEM,
            gpt_type::LINUX_SWAP,
            gpt_type::LINUX_LVM,
            gpt_type::LINUX_RAID,
            gpt_type::LINUX_HOME,
            gpt_type::LINUX_ROOT_X86_64,
            gpt_type::LINUX_ROOT_ARM64,
            gpt_type::LINUX_BOOT,
            gpt_type::APPLE_APFS,
            gpt_type::APPLE_HFS_PLUS,
            gpt_type::APPLE_BOOT,
            gpt_type::APPLE_CORE_STORAGE,
            gpt_type::FREEBSD_DATA,
            gpt_type::FREEBSD_SWAP,
            gpt_type::FREEBSD_ZFS,
            gpt_type::SOLARIS_ZFS,
        ];

        for guid in all {
            let groups: Vec<&str> = guid.split('-').collect();
            assert_eq!(groups.len(), 5, "{guid} does not have five groups");
            assert_eq!(
                groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
                vec![8, 4, 4, 4, 12],
                "{guid} has the wrong group sizes"
            );
            assert!(
                guid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
                "{guid} is not hexadecimal"
            );
            assert!(
                guid.chars().all(|c| !c.is_ascii_uppercase()),
                "{guid} must be lowercase, since lookups compare lowercased"
            );
        }
    }

    /// Pins the Linux GUID against a value read from real hardware.
    ///
    /// A reference table supplied during development gave `0fc63daa`. The machine
    /// this was developed on carries a Linux partition that reports `0fc63daf`
    /// through `IOCTL_DISK_GET_DRIVE_LAYOUT_EX`, and Wikipedia agrees with the
    /// disk. Adopting the table would have stopped ZMILY recognising Linux
    /// partitions — which is exactly how a dual-boot user's root starts looking
    /// like free space.
    #[test]
    fn the_linux_guid_matches_what_a_real_disk_reports() {
        assert_eq!(
            gpt_type::LINUX_FILESYSTEM,
            "0fc63daf-8483-4772-8e79-3d69d8477de4"
        );
        assert!(gpt_type::is_linux("0FC63DAF-8483-4772-8E79-3D69D8477DE4"));
        assert!(
            !gpt_type::is_linux("0fc63daa-8483-4772-8e79-3d69d8477de4"),
            "the near-miss must not be accepted as Linux"
        );
    }
}
