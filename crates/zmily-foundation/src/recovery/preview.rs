//! Filesystem-independent, bounded in-memory recovery previews.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_PREVIEW_BYTES: usize = 64 * 1024;
pub const DEFAULT_PREVIEW_HEX_BYTES: usize = 4 * 1024;
pub const DEFAULT_PREVIEW_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_PREVIEW_IMAGE_DIMENSION: u32 = 32_768;
pub const DEFAULT_PREVIEW_IMAGE_PIXELS: u64 = 16_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPreviewConfig {
    pub max_preview_bytes: usize,
    pub max_hex_bytes: usize,
    pub max_image_bytes: usize,
    pub max_image_dimension: u32,
    pub max_image_pixels: u64,
}

impl Default for RecoveryPreviewConfig {
    fn default() -> Self {
        Self {
            max_preview_bytes: DEFAULT_PREVIEW_BYTES,
            max_hex_bytes: DEFAULT_PREVIEW_HEX_BYTES,
            max_image_bytes: DEFAULT_PREVIEW_IMAGE_BYTES,
            max_image_dimension: DEFAULT_PREVIEW_IMAGE_DIMENSION,
            max_image_pixels: DEFAULT_PREVIEW_IMAGE_PIXELS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPreviewKind {
    Text,
    Image,
    Binary,
    Empty,
}

impl RecoveryPreviewKind {
    fn classify(total_bytes: u64, image: bool, text: bool) -> Self {
        if total_bytes == 0 {
            Self::Empty
        } else if image {
            Self::Image
        } else if text {
            Self::Text
        } else {
            Self::Binary
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryImageInfo {
    pub mime_type: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPreview {
    pub kind: RecoveryPreviewKind,
    pub total_bytes: u64,
    pub retained_bytes: Vec<u8>,
    pub truncated: bool,
    pub utf8_text: Option<String>,
    pub hex_dump: String,
    pub image: Option<RecoveryImageInfo>,
    pub complete_image_payload: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncodedRecoveryImage {
    #[serde(flatten)]
    pub header: RecoveryImageInfo,
    pub encoded_bytes: u64,
    pub base64: String,
}

/// Presentation evidence without source selectors or UI request state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPreviewView {
    pub stream_bytes: u64,
    pub preview_bytes: u64,
    pub truncated: bool,
    pub kind: RecoveryPreviewKind,
    pub text_encoding: Option<String>,
    pub text: Option<String>,
    pub hex_dump: String,
    pub image: Option<EncodedRecoveryImage>,
    pub source_bytes_read: u64,
}

const TEXT_ENCODING: &str = "utf-8";

impl RecoveryPreviewView {
    pub fn from_preview(preview: &RecoveryPreview, source_bytes_read: u64) -> Self {
        Self {
            stream_bytes: preview.total_bytes,
            preview_bytes: preview.retained_bytes.len() as u64,
            truncated: preview.truncated,
            kind: preview.kind,
            text_encoding: preview.utf8_text.as_ref().map(|_| TEXT_ENCODING.into()),
            text: preview.utf8_text.clone(),
            hex_dump: preview.hex_dump.clone(),
            image: preview
                .image
                .as_ref()
                .filter(|_| preview.complete_image_payload)
                .map(|header| EncodedRecoveryImage {
                    header: header.clone(),
                    encoded_bytes: preview.retained_bytes.len() as u64,
                    base64: BASE64.encode(&preview.retained_bytes),
                }),
            source_bytes_read,
        }
    }

    pub fn validate(&self, config: RecoveryPreviewConfig) -> Result<(), String> {
        config.validate().map_err(|error| error.to_string())?;
        let limit = if self.image.is_some() {
            config.max_image_bytes
        } else {
            config.max_preview_bytes
        };
        if self.preview_bytes > self.stream_bytes
            || self.preview_bytes > limit as u64
            || self.truncated != (self.preview_bytes < self.stream_bytes)
            || self.hex_dump.len() > config.max_hex_characters()?
            || self.text_encoding.as_deref() != self.text.as_ref().map(|_| TEXT_ENCODING)
        {
            return Err(
                "recovery preview byte counts, text encoding or renderer limits are inconsistent"
                    .into(),
            );
        }
        if let Some(text) = &self.text
            && (text.len() > config.max_preview_bytes
                || text.len() as u64 > self.preview_bytes
                || !supported_preview_text(text))
        {
            return Err("recovery preview text is not a bounded supported text view".into());
        }
        // An image classification may describe a prefix without a complete
        // image payload. Only a complete payload is offered to a renderer.
        let consistent_kind = self.kind
            == RecoveryPreviewKind::classify(
                self.stream_bytes,
                self.kind == RecoveryPreviewKind::Image || self.image.is_some(),
                self.text.is_some(),
            )
            && (self.kind != RecoveryPreviewKind::Image || self.text.is_none())
            && (self.stream_bytes != 0 || self.image.is_none());
        if !consistent_kind {
            return Err("recovery preview kind contradicts its contents".into());
        }
        if let Some(image) = &self.image {
            let encoded_length = image
                .encoded_bytes
                .checked_add(2)
                .map(|n| n / 3)
                .and_then(|n| n.checked_mul(4));
            if image.encoded_bytes != self.stream_bytes
                || image.encoded_bytes > config.max_image_bytes as u64
                || self.preview_bytes != self.stream_bytes
                || encoded_length != Some(image.base64.len() as u64)
            {
                return Err("recovery image is not a complete bounded encoded payload".into());
            }
            let bytes = BASE64
                .decode(&image.base64)
                .map_err(|error| error.to_string())?;
            if bytes.len() as u64 != image.encoded_bytes
                || preview_image_info(&bytes[..bytes.len().min(config.max_preview_bytes)], config)
                    .as_ref()
                    != Some(&image.header)
            {
                return Err("recovery image metadata disagrees with its encoded header".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RecoveryPreviewError {
    #[error("invalid recovery-preview configuration: {0}")]
    InvalidConfiguration(String),
    #[error(
        "the supplied preview contains {actual} bytes but the complete stream has only {total}"
    )]
    BytesExceedTotal { actual: usize, total: u64 },
}

pub struct GuardedPreview {
    pub preview: RecoveryPreview,
    pub source_bytes_read: u64,
}

pub struct CapturedPrefix {
    pub bytes: Vec<u8>,
    pub source_bytes_read: u64,
}

pub fn analyze_guarded_preview(
    total_bytes: u64,
    config: RecoveryPreviewConfig,
    mut capture: impl FnMut(usize) -> Result<CapturedPrefix, String>,
) -> Result<GuardedPreview, String> {
    config.validate().map_err(|error| error.to_string())?;
    let initial = capture(config.max_preview_bytes)?;
    let mut source_bytes_read = initial.source_bytes_read;
    let mut preview = inspect_recovery_preview(&initial.bytes, total_bytes, config)
        .map_err(|error| error.to_string())?;
    if preview.kind == RecoveryPreviewKind::Image
        && preview.truncated
        && total_bytes <= config.max_image_bytes as u64
    {
        let complete = capture(
            usize::try_from(total_bytes)
                .map_err(|_| "the image preview length does not fit this process".to_string())?,
        )?;
        source_bytes_read = source_bytes_read
            .checked_add(complete.source_bytes_read)
            .ok_or_else(|| "the preview source-byte count overflowed".to_string())?;
        preview = inspect_recovery_preview(&complete.bytes, total_bytes, config)
            .map_err(|error| error.to_string())?;
    }
    Ok(GuardedPreview {
        preview,
        source_bytes_read,
    })
}

/// Analyzes a caller-supplied complete stream or prefix. The caller remains
/// responsible for obtaining those bytes through a guarded filesystem transfer.
pub fn inspect_recovery_preview(
    bytes: &[u8],
    total_bytes: u64,
    config: RecoveryPreviewConfig,
) -> Result<RecoveryPreview, RecoveryPreviewError> {
    config.validate()?;
    if bytes.len() as u64 > total_bytes {
        return Err(RecoveryPreviewError::BytesExceedTotal {
            actual: bytes.len(),
            total: total_bytes,
        });
    }
    let header_len = bytes.len().min(config.max_preview_bytes);
    let header_image = preview_image_info(&bytes[..header_len], config);
    let retain_limit = if header_image.is_some() && total_bytes <= config.max_image_bytes as u64 {
        config.max_image_bytes
    } else {
        config.max_preview_bytes
    };
    let retained_len = bytes.len().min(retain_limit);
    let retained = bytes[..retained_len].to_vec();
    let truncated = retained_len as u64 != total_bytes;
    let utf8_text = if header_image.is_none() {
        preview_utf8_text(&retained[..retained.len().min(config.max_preview_bytes)])
    } else {
        None
    };
    let image = header_image;
    let complete_image_payload = image.is_some()
        && !truncated
        && total_bytes <= config.max_image_bytes as u64
        && bytes.len() as u64 == total_bytes;
    let kind = RecoveryPreviewKind::classify(total_bytes, image.is_some(), utf8_text.is_some());
    Ok(RecoveryPreview {
        kind,
        total_bytes,
        retained_bytes: retained.clone(),
        truncated,
        utf8_text,
        hex_dump: preview_hex_dump(&retained[..retained.len().min(config.max_hex_bytes)]),
        image,
        complete_image_payload,
    })
}

pub fn preview_utf8_text(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    supported_preview_text(text).then(|| text.to_owned())
}

fn supported_preview_text(text: &str) -> bool {
    !text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
}

const HEX_ROW_BYTES: usize = 16;

pub fn preview_hex_dump(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(4));
    for (line, chunk) in bytes.chunks(HEX_ROW_BYTES).enumerate() {
        append_hex_row(&mut output, line.saturating_mul(HEX_ROW_BYTES), chunk);
    }
    output
}

fn append_hex_row(output: &mut String, offset: usize, chunk: &[u8]) {
    let _ = write!(output, "{:08x}  ", offset);
    for index in 0..HEX_ROW_BYTES {
        if let Some(byte) = chunk.get(index) {
            let _ = write!(output, "{byte:02x} ");
        } else {
            output.push_str("   ");
        }
        if index == 7 {
            output.push(' ');
        }
    }
    output.push_str(" |");
    for byte in chunk {
        output.push(if byte.is_ascii_graphic() || *byte == b' ' {
            char::from(*byte)
        } else {
            '.'
        });
    }
    output.push_str("|\n");
}

pub fn preview_image_info(
    bytes: &[u8],
    config: RecoveryPreviewConfig,
) -> Option<RecoveryImageInfo> {
    let (mime_type, width, height) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        && bytes.get(12..16) == Some(b"IHDR")
        && u32::from_be_bytes(bytes.get(8..12)?.try_into().ok()?) == 13
    {
        (
            "image/png",
            u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?),
            u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?),
        )
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        (
            "image/gif",
            u16::from_le_bytes(bytes.get(6..8)?.try_into().ok()?).into(),
            u16::from_le_bytes(bytes.get(8..10)?.try_into().ok()?).into(),
        )
    } else if bytes.starts_with(b"BM") {
        bmp_dimensions(bytes).map(|(width, height)| ("image/bmp", width, height))?
    } else if bytes.starts_with(&[0xff, 0xd8]) {
        jpeg_dimensions(bytes).map(|(width, height)| ("image/jpeg", width, height))?
    } else {
        return None;
    };
    let pixels = u64::from(width).checked_mul(u64::from(height))?;
    (width != 0
        && height != 0
        && width <= config.max_image_dimension
        && height <= config.max_image_dimension
        && pixels <= config.max_image_pixels)
        .then_some(RecoveryImageInfo {
            mime_type: mime_type.into(),
            width,
            height,
        })
}

fn bmp_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let dib_bytes = u32::from_le_bytes(bytes.get(14..18)?.try_into().ok()?);
    if dib_bytes == 12 {
        Some((
            u16::from_le_bytes(bytes.get(18..20)?.try_into().ok()?).into(),
            u16::from_le_bytes(bytes.get(20..22)?.try_into().ok()?).into(),
        ))
    } else if dib_bytes >= 40 {
        let width = i32::from_le_bytes(bytes.get(18..22)?.try_into().ok()?);
        let height = i32::from_le_bytes(bytes.get(22..26)?.try_into().ok()?);
        Some((
            u32::try_from(width).ok()?,
            height
                .checked_abs()
                .and_then(|value| u32::try_from(value).ok())?,
        ))
    } else {
        None
    }
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let mut offset = 2usize;
    while offset < bytes.len() {
        while bytes.get(offset) == Some(&0xff) {
            offset = offset.checked_add(1)?;
        }
        let marker = *bytes.get(offset)?;
        offset = offset.checked_add(1)?;
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let segment_bytes = usize::from(u16::from_be_bytes(
            bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
        ));
        if segment_bytes < 2 {
            return None;
        }
        let end = offset.checked_add(segment_bytes)?;
        if end > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if segment_bytes < 8 {
                return None;
            }
            let height = u16::from_be_bytes(bytes.get(offset + 3..offset + 5)?.try_into().ok()?);
            let width = u16::from_be_bytes(bytes.get(offset + 5..offset + 7)?.try_into().ok()?);
            return Some((width.into(), height.into()));
        }
        offset = end;
    }
    None
}

impl RecoveryPreviewConfig {
    /// Derives the output ceiling from the actual row formatter, including
    /// addresses wider than eight hex digits and a partially filled final row.
    pub fn max_hex_characters(self) -> Result<usize, String> {
        let mut row = String::new();
        append_hex_row(
            &mut row,
            self.max_hex_bytes.saturating_sub(1),
            &[0; HEX_ROW_BYTES],
        );
        self.max_hex_bytes
            .div_ceil(HEX_ROW_BYTES)
            .checked_mul(row.len())
            .ok_or_else(|| "recovery hex renderer size overflowed".into())
    }
    pub fn validate(self) -> Result<(), RecoveryPreviewError> {
        let config = self;
        if config.max_preview_bytes == 0
            || config.max_hex_bytes == 0
            || config.max_hex_bytes > config.max_preview_bytes
            || config.max_image_bytes < config.max_preview_bytes
            || config.max_image_dimension == 0
            || config.max_image_pixels == 0
        {
            return Err(RecoveryPreviewError::InvalidConfiguration(
            "preview, hex, image, dimension, and pixel limits must be nonzero and consistently ordered"
                .into(),
        ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.resize(40, 0);
        bytes
    }

    #[test]
    fn invalid_configuration_refuses_before_capture_and_profiles_remain_caller_owned() {
        let invalid = RecoveryPreviewConfig {
            max_preview_bytes: 0,
            ..Default::default()
        };
        assert!(
            analyze_guarded_preview(20, invalid, |_| panic!("invalid config captured bytes"))
                .is_err()
        );
        let bytes = png(9_000, 1);
        let generic =
            inspect_recovery_preview(&bytes, bytes.len() as u64, RecoveryPreviewConfig::default())
                .unwrap();
        assert_eq!(generic.kind, RecoveryPreviewKind::Image);
        let restricted = RecoveryPreviewConfig {
            max_image_dimension: 8_192,
            ..Default::default()
        };
        let view = RecoveryPreviewView::from_preview(&generic, bytes.len() as u64);
        assert!(view.validate(RecoveryPreviewConfig::default()).is_ok());
        assert!(view.validate(restricted).is_err());
        assert_eq!(
            inspect_recovery_preview(&bytes, bytes.len() as u64, restricted)
                .unwrap()
                .kind,
            RecoveryPreviewKind::Binary
        );
        for length in 1..=33 {
            let config = RecoveryPreviewConfig {
                max_hex_bytes: length,
                ..Default::default()
            };
            assert!(
                preview_hex_dump(&vec![0; length]).len() <= config.max_hex_characters().unwrap()
            );
        }
    }

    #[test]
    fn text_and_hex_views_share_one_bounded_prefix() {
        let report =
            inspect_recovery_preview(b"hello\nworld", 11, RecoveryPreviewConfig::default())
                .unwrap();
        assert_eq!(report.kind, RecoveryPreviewKind::Text);
        assert_eq!(report.utf8_text.as_deref(), Some("hello\nworld"));
        assert!(report.hex_dump.contains("68 65 6c 6c 6f"));
        assert!(!report.truncated);
    }

    #[test]
    fn binary_controls_are_not_claimed_as_text() {
        let report =
            inspect_recovery_preview(&[0, 1, 2], 3, RecoveryPreviewConfig::default()).unwrap();
        assert_eq!(report.kind, RecoveryPreviewKind::Binary);
        assert!(report.utf8_text.is_none());
    }

    #[test]
    fn image_dimensions_and_complete_payload_are_independent() {
        let mut bytes = png(320, 200);
        bytes.resize(DEFAULT_PREVIEW_BYTES + 1_000, 0x5a);
        let complete =
            inspect_recovery_preview(&bytes, bytes.len() as u64, RecoveryPreviewConfig::default())
                .unwrap();
        assert_eq!(complete.kind, RecoveryPreviewKind::Image);
        assert_eq!(complete.image.as_ref().unwrap().width, 320);
        assert!(complete.complete_image_payload);
        let prefix = inspect_recovery_preview(
            &bytes[..24],
            bytes.len() as u64,
            RecoveryPreviewConfig::default(),
        )
        .unwrap();
        assert_eq!(prefix.kind, RecoveryPreviewKind::Image);
        assert!(!prefix.complete_image_payload);
    }

    #[test]
    fn dimensions_over_the_pixel_ceiling_are_rejected() {
        let bytes = png(32_768, 32_768);
        let report =
            inspect_recovery_preview(&bytes, bytes.len() as u64, RecoveryPreviewConfig::default())
                .unwrap();
        assert_eq!(report.kind, RecoveryPreviewKind::Binary);
    }

    #[test]
    fn supplied_bytes_cannot_exceed_the_declared_stream() {
        assert!(matches!(
            inspect_recovery_preview(b"too long", 2, RecoveryPreviewConfig::default()),
            Err(RecoveryPreviewError::BytesExceedTotal { .. })
        ));
    }
}
