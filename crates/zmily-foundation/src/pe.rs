//! Portable PE header decoding for executable admission and recovery recognition.

pub struct PeHeader {
    pub machine: u16,
    pub sections: u16,
    pub optional_size: u16,
    pub characteristics: u16,
    pub optional_offset: usize,
    pub magic: u16,
    pub subsystem: u16,
}

impl PeHeader {
    /// Decode the common header only; callers select their admission profile.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !data.starts_with(b"MZ") || data.len() < 64 {
            return None;
        }
        let pe = u32_at(data, 0x3c)? as usize;
        if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let optional = pe.checked_add(24)?;
        Some(Self {
            machine: u16_at(data, pe.checked_add(4)?)?,
            sections: u16_at(data, pe.checked_add(6)?)?,
            optional_size: u16_at(data, pe.checked_add(20)?)?,
            characteristics: u16_at(data, pe.checked_add(22)?)?,
            optional_offset: optional,
            magic: u16_at(data, optional)?,
            subsystem: u16_at(data, optional.checked_add(68)?)?,
        })
    }

    pub fn require_x64(&self) -> Result<(), String> {
        if self.machine != 0x8664 || self.magic != 0x20b {
            return Err("executable must be x64 PE32+".into());
        }
        Ok(())
    }

    pub fn require_x64_console(&self) -> Result<(), String> {
        self.require_x64()?;
        if self.subsystem != 3 {
            return Err("executable must use the Windows console subsystem".into());
        }
        Ok(())
    }

    /// Recognize a fully contained PE file, with an explicit caller section budget.
    /// Section/header/certificate extent checks do not establish executable trust.
    pub fn contained_file_extent(&self, data: &[u8], maximum_sections: u16) -> Option<usize> {
        let sections = self.sections as usize;
        let optional_size = self.optional_size as usize;
        if self.machine == 0 || sections == 0 || self.sections > maximum_sections {
            return None;
        }
        let optional = self.optional_offset;
        let section_table = optional.checked_add(optional_size)?;
        let table_end = section_table.checked_add(sections.checked_mul(40)?)?;
        data.get(..table_end)?;
        let directory_offset = match self.magic {
            0x10b if optional_size >= 96 => 96,
            0x20b if optional_size >= 112 => 112,
            _ => return None,
        };
        let mut end = (u32_at(data, optional.checked_add(60)?)? as usize).max(table_end);
        for section in 0..sections {
            let cursor = section_table.checked_add(section.checked_mul(40)?)?;
            let size = u32_at(data, cursor.checked_add(16)?)? as usize;
            let offset = u32_at(data, cursor.checked_add(20)?)? as usize;
            end = end.max(offset.checked_add(size)?);
        }
        if directory_offset + 5 * 8 <= optional_size {
            let certificate = optional.checked_add(directory_offset + 4 * 8)?;
            let offset = u32_at(data, certificate)? as usize;
            let size = u32_at(data, certificate.checked_add(4)?)? as usize;
            if size > 0 {
                end = end.max(offset.checked_add(size)?);
            }
        }
        (end <= data.len()).then_some(end)
    }
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub fn validate_x64(data: &[u8]) -> Result<(), String> {
    PeHeader::parse(data)
        .ok_or("invalid or truncated Windows executable")?
        .require_x64()
}

pub fn validate_x64_console(data: &[u8]) -> Result<(), String> {
    PeHeader::parse(data)
        .ok_or("invalid or truncated Windows executable")?
        .require_x64_console()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executable_profiles_preserve_console_requirement_and_checked_bounds() {
        let mut data = vec![0; 512];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        data[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        data[0xdc..0xde].copy_from_slice(&3u16.to_le_bytes());
        assert!(validate_x64_console(&data).is_ok());
        data[0xdc] = 2;
        assert!(validate_x64(&data).is_ok());
        assert!(validate_x64_console(&data).is_err());
        data[0x84] = 0;
        assert!(validate_x64(&data).is_err());
        data[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PeHeader::parse(&data).is_none());
        for length in 0..64 {
            assert!(PeHeader::parse(&data[..length]).is_none());
        }
    }
}
