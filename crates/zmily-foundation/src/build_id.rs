//! Portable compact identifiers used in build metadata, filenames and arguments.

#[derive(Clone, PartialEq, Eq)]
pub struct CompactBuildId(String);

impl CompactBuildId {
    /// Exact identifier admission for command-line arguments.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("build identifier must contain exactly 32 ASCII hexadecimal digits".into());
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Text-file/UI profile permits surrounding whitespace, including a line ending.
    pub fn from_config(value: &str) -> Result<Self, String> {
        Self::parse(value.trim())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_and_text_profiles_share_identifier_admission() {
        let upper = "0123456789ABCDEF0123456789ABCDEF";
        assert_eq!(
            CompactBuildId::parse(upper).unwrap().as_str(),
            upper.to_ascii_lowercase()
        );
        assert!(CompactBuildId::parse(&format!("{upper}\r\n")).is_err());
        assert_eq!(
            CompactBuildId::from_config(&format!("{upper}\r\n"))
                .unwrap()
                .as_str(),
            upper.to_ascii_lowercase()
        );
        for id in [
            "",
            "..",
            "P:\\",
            "../other",
            "0123456789abcdef0123456789abcdeg",
            "Ａ123456789abcdef0123456789abcdef",
        ] {
            assert!(CompactBuildId::from_config(id).is_err());
        }
    }
}
