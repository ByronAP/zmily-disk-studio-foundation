//! MBR partition type bytes.
//!
//! # Why this is not just cosmetic
//!
//! MBR has one byte per entry to say what the partition holds. Windows will often
//! mount a volume whose byte disagrees with its contents — it sniffs the boot
//! sector — but nothing else will. Boot loaders, other operating systems,
//! recovery tools, and imaging software all read the byte and believe it.
//!
//! ZMILY used to write `0x07` for every MBR partition it created, converted, or
//! formatted, so `partition create --fs fat32` on an MBR disk produced a FAT32
//! filesystem labelled as NTFS. It worked on Windows and was wrong everywhere
//! else.
//!
//! # The classic and LBA variants are not interchangeable
//!
//! FAT16B and FAT32 each have two type bytes: one for CHS addressing and one for
//! LBA. The distinction is real — a partition that ends beyond what CHS can
//! address (1024 cylinders, ~8.4 GB) *must* use the LBA type, because a loader
//! reading the CHS fields gets a wrong answer. [`for_filesystem`] picks on that
//! boundary rather than always choosing one.

use crate::model::FilesystemType;

/// Empty entry.
pub const EMPTY: u8 = 0x00;
/// FAT12.
pub const FAT12: u8 = 0x01;
/// FAT16 below 65536 sectors — 32 MB.
pub const FAT16_SMALL: u8 = 0x04;
/// Extended partition, CHS addressing.
pub const EXTENDED_CHS: u8 = 0x05;
/// FAT16B, 65536 sectors or more.
pub const FAT16B: u8 = 0x06;
/// Installable file system: NTFS, HPFS, and exFAT all share it.
pub const IFS: u8 = 0x07;
/// FAT32 with CHS addressing.
pub const FAT32_CHS: u8 = 0x0B;
/// FAT32 with LBA.
pub const FAT32_LBA: u8 = 0x0C;
/// FAT16B with LBA.
pub const FAT16B_LBA: u8 = 0x0E;
/// Extended partition with LBA.
pub const EXTENDED_LBA: u8 = 0x0F;
/// OEM service, diagnostics, and recovery partitions — Compaq, EISA, NCR, Intel,
/// and IBM Rescue and Recovery all use it.
pub const SERVICE: u8 = 0x12;
/// Windows Recovery Environment; also Acer's `PQService` rescue partition.
pub const WINDOWS_RECOVERY: u8 = 0x27;
/// Dynamic disk (Logical Disk Manager) extended partition marker.
pub const DYNAMIC_EXTENDED: u8 = 0x42;
/// Linux swap. Shares the byte with Solaris x86.
pub const LINUX_SWAP: u8 = 0x82;
/// Any native Linux file system.
pub const LINUX_NATIVE: u8 = 0x83;
/// Linux extended partition.
pub const LINUX_EXTENDED: u8 = 0x85;
/// Fault-tolerant FAT16B mirrored volume set.
pub const FT_MIRROR_FAT16B: u8 = 0x86;
/// Fault-tolerant HPFS/NTFS mirrored volume set.
pub const FT_MIRROR_IFS: u8 = 0x87;
/// Linux LVM physical volume.
pub const LINUX_LVM: u8 = 0x8E;
/// Apple HFS/HFS+.
pub const HFS_PLUS: u8 = 0xAF;
/// Protective entry on a GPT disk.
pub const GPT_PROTECTIVE: u8 = 0xEE;
/// EFI System Partition on an MBR disk.
pub const EFI_SYSTEM: u8 = 0xEF;
/// Linux RAID with auto-detect.
pub const LINUX_RAID: u8 = 0xFD;

/// Largest offset CHS addressing can describe: 1024 cylinders × 255 heads ×
/// 63 sectors × 512 bytes, a little under 8.4 GB.
///
/// A partition ending past this cannot be described in the CHS fields, so it has
/// to carry an LBA type or a loader reading those fields gets a wrong answer.
pub const CHS_ADDRESSING_LIMIT: i64 = 1024 * 255 * 63 * 512;

/// The type byte to write for a partition holding `filesystem`.
///
/// `end_offset` is where the partition ends, which decides between the CHS and
/// LBA variants where a filesystem has both.
///
/// Returns `IFS` for anything without a better answer — the same byte NTFS,
/// HPFS, and exFAT share, and the least surprising default for a Windows tool.
pub fn for_filesystem(filesystem: &FilesystemType, end_offset: i64, length: i64) -> u8 {
    let needs_lba = end_offset > CHS_ADDRESSING_LIMIT;

    match filesystem {
        FilesystemType::Fat12 => FAT12,
        FilesystemType::Fat16 => {
            // The 32 MB boundary is the FAT16/FAT16B split: 65536 sectors of 512
            // bytes. Below it the older type is what other systems expect.
            if length < 65_536 * 512 {
                FAT16_SMALL
            } else if needs_lba {
                FAT16B_LBA
            } else {
                FAT16B
            }
        }
        FilesystemType::Fat32 => {
            if needs_lba {
                FAT32_LBA
            } else {
                FAT32_CHS
            }
        }
        // NTFS and exFAT genuinely share this byte; the boot sector is what tells
        // them apart, which is why reading it back cannot say which.
        FilesystemType::Ntfs | FilesystemType::ExFat => IFS,
        FilesystemType::LinuxSwap => LINUX_SWAP,
        FilesystemType::LinuxLvm => LINUX_LVM,
        FilesystemType::LinuxRaid => LINUX_RAID,
        FilesystemType::Ext2 | FilesystemType::Ext3 | FilesystemType::Ext4 => LINUX_NATIVE,
        FilesystemType::Btrfs | FilesystemType::Xfs | FilesystemType::F2fs => LINUX_NATIVE,
        FilesystemType::HfsPlus => HFS_PLUS,
        _ => IFS,
    }
}

/// Whether a type byte marks a partition hidden from the operating system.
///
/// OS/2's Boot Manager introduced these by adding `0x10` to the ordinary type, so
/// `0x1B` is a hidden FAT32 exactly as `0x0B` is a visible one. Windows leaves
/// them unmounted, which is the point.
pub fn is_hidden(byte: u8) -> bool {
    matches!(
        byte,
        0x11 | 0x14 | 0x15 | 0x16 | 0x17 | 0x1B | 0x1C | 0x1E | 0x1F
    )
}

/// The visible type a hidden byte corresponds to, if it is one.
pub fn unhidden(byte: u8) -> Option<u8> {
    is_hidden(byte).then(|| byte - 0x10)
}

/// Whether a type byte marks one half of a fault-tolerant mirrored set.
///
/// Operating on one half of a mirror without the volume manager's knowledge is
/// how a mirror is silently broken, so these are worth recognising rather than
/// filing under "foreign".
pub fn is_fault_tolerant_mirror(byte: u8) -> bool {
    matches!(byte, FT_MIRROR_FAT16B | FT_MIRROR_IFS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this module exists for: every filesystem used to be written as
    /// `0x07`, so a FAT32 partition claimed to be NTFS.
    #[test]
    fn each_filesystem_gets_its_own_byte() {
        let small = 100 * 1024 * 1024;

        assert_eq!(
            for_filesystem(&FilesystemType::Fat32, small, small),
            FAT32_CHS
        );
        assert_eq!(for_filesystem(&FilesystemType::Ntfs, small, small), IFS);
        assert_eq!(for_filesystem(&FilesystemType::Fat12, small, small), FAT12);
        assert_eq!(
            for_filesystem(&FilesystemType::LinuxSwap, small, small),
            LINUX_SWAP
        );
        assert_eq!(
            for_filesystem(&FilesystemType::Ext4, small, small),
            LINUX_NATIVE
        );
    }

    /// A partition ending past CHS's reach must carry an LBA type, or a loader
    /// reading the CHS fields lands somewhere else entirely.
    #[test]
    fn partitions_past_the_chs_limit_get_lba_types() {
        let beyond = CHS_ADDRESSING_LIMIT + 1;

        assert_eq!(
            for_filesystem(&FilesystemType::Fat32, beyond, 1024 * 1024 * 1024),
            FAT32_LBA
        );
        assert_eq!(
            for_filesystem(&FilesystemType::Fat16, beyond, 1024 * 1024 * 1024),
            FAT16B_LBA
        );

        // And one that fits keeps the classic type.
        assert_eq!(
            for_filesystem(
                &FilesystemType::Fat32,
                CHS_ADDRESSING_LIMIT,
                1024 * 1024 * 1024
            ),
            FAT32_CHS
        );
    }

    /// FAT16 below 32 MB is a different type from FAT16B above it.
    #[test]
    fn small_fat16_uses_the_older_type() {
        let small = 16 * 1024 * 1024;
        let large = 64 * 1024 * 1024;

        assert_eq!(
            for_filesystem(&FilesystemType::Fat16, small, small),
            FAT16_SMALL
        );
        assert_eq!(for_filesystem(&FilesystemType::Fat16, large, large), FAT16B);
    }

    /// NTFS and exFAT share a byte, which is why reading one back cannot say
    /// which filesystem is there.
    #[test]
    fn ntfs_and_exfat_are_indistinguishable_by_type_byte() {
        let size = 100 * 1024 * 1024;

        assert_eq!(
            for_filesystem(&FilesystemType::Ntfs, size, size),
            for_filesystem(&FilesystemType::ExFat, size, size)
        );
    }

    /// The hidden types are the ordinary ones plus 0x10, which is what makes the
    /// correspondence checkable rather than a list to be trusted.
    #[test]
    fn hidden_types_are_their_visible_counterparts_plus_ten() {
        assert_eq!(unhidden(0x1B), Some(FAT32_CHS));
        assert_eq!(unhidden(0x1C), Some(FAT32_LBA));
        assert_eq!(unhidden(0x17), Some(IFS));
        assert_eq!(unhidden(0x16), Some(FAT16B));
        assert_eq!(unhidden(0x11), Some(FAT12));

        assert_eq!(unhidden(FAT32_CHS), None, "a visible type is not hidden");
    }

    #[test]
    fn mirrored_set_members_are_recognised() {
        assert!(is_fault_tolerant_mirror(FT_MIRROR_IFS));
        assert!(is_fault_tolerant_mirror(FT_MIRROR_FAT16B));
        assert!(!is_fault_tolerant_mirror(IFS));
    }
}
