//! Parsing human-written sizes.
//!
//! Accepts what people actually type: `40G`, `512MiB`, `1.5T`, `2048s`. Also
//! accepts relative forms — `+10G`, `-5G` — because "grow this by 10 GB" is how
//! resizing is usually expressed, and making the user compute the resulting
//! absolute size by hand is how off-by-one-gigabyte mistakes happen.
//!
//! # Binary units, always
//!
//! `1G` means 1 GiB (1,073,741,824 bytes), matching what Windows displays and
//! what every partitioning tool does. `GB` and `GiB` are both accepted and both
//! mean the same thing. This is technically an abuse of SI prefixes, but a tool
//! that made `40G` mean 40,000,000,000 bytes while Disk Management showed
//! 37.25 GB would be actively confusing.

use std::fmt;

/// A size argument, which may be absolute or relative to an existing size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeSpec {
    /// An exact size.
    Absolute(i64),
    /// A change relative to the current size; negative shrinks.
    Relative(i64),
}

/// Size accepted when creating a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSizeSpec {
    /// A resolved byte count.
    Bytes(i64),
    /// Fill one explicitly selected unallocated region after alignment.
    Max,
}

impl SizeSpec {
    /// Resolves against a current size, saturating at zero.
    pub fn resolve(self, current: i64) -> i64 {
        match self {
            SizeSpec::Absolute(bytes) => bytes,
            SizeSpec::Relative(delta) => current.saturating_add(delta).max(0),
        }
    }

    pub fn is_relative(self) -> bool {
        matches!(self, SizeSpec::Relative(_))
    }
}

/// Why a size could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeParseError {
    Empty,
    /// The numeric part was not a number.
    NotANumber(String),
    /// The unit suffix was not recognized.
    UnknownUnit(String),
    /// The value was negative where only a magnitude makes sense.
    NegativeAbsolute,
    /// The value overflowed `i64` bytes.
    TooLarge,
}

impl fmt::Display for SizeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizeParseError::Empty => f.write_str("no size given"),
            SizeParseError::NotANumber(s) => write!(f, "'{s}' is not a number"),
            SizeParseError::UnknownUnit(s) => write!(
                f,
                "'{s}' is not a known unit; use B, K, M, G, T, or s for sectors"
            ),
            SizeParseError::NegativeAbsolute => {
                f.write_str("a size cannot be negative; use -10G to shrink by an amount")
            }
            SizeParseError::TooLarge => f.write_str("the size is too large"),
        }
    }
}

impl std::error::Error for SizeParseError {}

const KIB: f64 = 1024.0;

/// Bytes per unit suffix. Sector-relative units are handled separately.
fn multiplier(unit: &str) -> Option<f64> {
    let normalized = unit.trim().to_ascii_lowercase();
    // Accept "g", "gb", and "gib" alike; the trailing b/ib is decoration.
    let stripped = normalized
        .strip_suffix("ib")
        .or_else(|| normalized.strip_suffix('b'))
        .unwrap_or(&normalized);

    Some(match stripped {
        "" => 1.0,
        "k" => KIB,
        "m" => KIB.powi(2),
        "g" => KIB.powi(3),
        "t" => KIB.powi(4),
        "p" => KIB.powi(5),
        _ => return None,
    })
}

/// Parses a size, which may carry a leading `+` or `-`.
///
/// `sector_size` interprets the `s` suffix; pass the disk's logical sector size.
pub fn parse_size_spec(input: &str, sector_size: u32) -> Result<SizeSpec, SizeParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SizeParseError::Empty);
    }

    let (relative, body) = match trimmed.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => match trimmed.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        },
    };
    let negative = trimmed.starts_with('-');

    let bytes = parse_magnitude(body, sector_size)?;

    if relative {
        Ok(SizeSpec::Relative(if negative { -bytes } else { bytes }))
    } else {
        Ok(SizeSpec::Absolute(bytes))
    }
}

/// Parses an absolute size. Rejects relative forms.
pub fn parse_size(input: &str, sector_size: u32) -> Result<i64, SizeParseError> {
    match parse_size_spec(input, sector_size)? {
        SizeSpec::Absolute(bytes) => Ok(bytes),
        SizeSpec::Relative(_) => Err(SizeParseError::NegativeAbsolute),
    }
}

/// Parses the create-only `max` spelling or an ordinary absolute size.
pub fn parse_create_size(input: &str, sector_size: u32) -> Result<CreateSizeSpec, SizeParseError> {
    if input.trim().eq_ignore_ascii_case("max") {
        Ok(CreateSizeSpec::Max)
    } else {
        parse_size(input, sector_size).map(CreateSizeSpec::Bytes)
    }
}

fn parse_magnitude(body: &str, sector_size: u32) -> Result<i64, SizeParseError> {
    let body = body.trim();
    if body.is_empty() {
        return Err(SizeParseError::Empty);
    }

    // Split where the digits end. The unit is whatever follows.
    let split = body
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != ',')
        .unwrap_or(body.len());
    let (number, unit) = body.split_at(split);

    // Accept a comma as a decimal separator, which is what a German or French
    // user will type even in an otherwise-English command line.
    let number = number.replace(',', ".");

    let value: f64 = number
        .parse()
        .map_err(|_| SizeParseError::NotANumber(number.clone()))?;

    if value < 0.0 {
        return Err(SizeParseError::NegativeAbsolute);
    }

    // Sectors are a count, not a byte quantity, so they scale by sector size.
    let unit_trimmed = unit.trim();
    let bytes = if unit_trimmed.eq_ignore_ascii_case("s")
        || unit_trimmed.eq_ignore_ascii_case("sec")
        || unit_trimmed.eq_ignore_ascii_case("sectors")
    {
        value * sector_size.max(1) as f64
    } else {
        let multiplier = multiplier(unit_trimmed)
            .ok_or_else(|| SizeParseError::UnknownUnit(unit_trimmed.to_string()))?;
        value * multiplier
    };

    if !bytes.is_finite() || bytes > i64::MAX as f64 {
        return Err(SizeParseError::TooLarge);
    }

    Ok(bytes as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * MIB;

    #[test]
    fn plain_numbers_are_bytes() {
        assert_eq!(parse_size("4096", 512).unwrap(), 4096);
        assert_eq!(parse_size("4096B", 512).unwrap(), 4096);
    }

    #[test]
    fn suffixes_are_binary_multiples() {
        assert_eq!(parse_size("1K", 512).unwrap(), 1024);
        assert_eq!(parse_size("1M", 512).unwrap(), MIB);
        assert_eq!(parse_size("1G", 512).unwrap(), GIB);
        assert_eq!(parse_size("1T", 512).unwrap(), 1024 * GIB);
    }

    /// `GB` and `GiB` mean the same thing here, matching what Windows shows.
    #[test]
    fn decimal_and_binary_spellings_agree() {
        let g = parse_size("40G", 512).unwrap();
        assert_eq!(parse_size("40GB", 512).unwrap(), g);
        assert_eq!(parse_size("40GiB", 512).unwrap(), g);
        assert_eq!(g, 40 * GIB);
    }

    #[test]
    fn units_are_case_insensitive() {
        assert_eq!(parse_size("1g", 512).unwrap(), GIB);
        assert_eq!(parse_size("1Gb", 512).unwrap(), GIB);
        assert_eq!(parse_size("1gIb", 512).unwrap(), GIB);
    }

    #[test]
    fn fractional_sizes_are_allowed() {
        assert_eq!(parse_size("1.5G", 512).unwrap(), GIB + GIB / 2);
        assert_eq!(parse_size("0.5M", 512).unwrap(), MIB / 2);
    }

    /// A user with a German keyboard layout types "1,5G" without thinking about it.
    #[test]
    fn a_comma_works_as_a_decimal_separator() {
        assert_eq!(
            parse_size("1,5G", 512).unwrap(),
            parse_size("1.5G", 512).unwrap()
        );
    }

    #[test]
    fn sectors_scale_by_the_disks_sector_size() {
        assert_eq!(parse_size("2048s", 512).unwrap(), MIB);
        assert_eq!(parse_size("256s", 4096).unwrap(), MIB);
        assert_eq!(parse_size("1sectors", 512).unwrap(), 512);
    }

    #[test]
    fn whitespace_is_tolerated() {
        assert_eq!(parse_size("  40 G  ", 512).unwrap(), 40 * GIB);
    }

    #[test]
    fn relative_sizes_carry_their_sign() {
        assert_eq!(
            parse_size_spec("+10G", 512).unwrap(),
            SizeSpec::Relative(10 * GIB)
        );
        assert_eq!(
            parse_size_spec("-5G", 512).unwrap(),
            SizeSpec::Relative(-5 * GIB)
        );
        assert_eq!(
            parse_size_spec("40G", 512).unwrap(),
            SizeSpec::Absolute(40 * GIB)
        );
    }

    #[test]
    fn relative_sizes_resolve_against_a_current_size() {
        assert_eq!(SizeSpec::Relative(10 * GIB).resolve(30 * GIB), 40 * GIB);
        assert_eq!(SizeSpec::Relative(-10 * GIB).resolve(30 * GIB), 20 * GIB);
        assert_eq!(SizeSpec::Absolute(40 * GIB).resolve(30 * GIB), 40 * GIB);
    }

    /// Shrinking by more than the partition holds clamps to zero rather than
    /// producing a negative length that would corrupt a partition table.
    #[test]
    fn shrinking_past_zero_clamps() {
        assert_eq!(SizeSpec::Relative(-100 * GIB).resolve(30 * GIB), 0);
    }

    #[test]
    fn a_relative_size_is_rejected_where_an_absolute_one_is_required() {
        assert!(parse_size("+10G", 512).is_err());
    }

    #[test]
    fn unknown_units_are_rejected_with_a_helpful_message() {
        let err = parse_size("10X", 512).unwrap_err();
        assert!(matches!(err, SizeParseError::UnknownUnit(_)));
        assert!(err.to_string().contains("not a known unit"));
    }

    #[test]
    fn nonsense_is_rejected() {
        assert_eq!(parse_size("", 512).unwrap_err(), SizeParseError::Empty);
        assert_eq!(parse_size("   ", 512).unwrap_err(), SizeParseError::Empty);
        assert!(matches!(
            parse_size("abc", 512).unwrap_err(),
            SizeParseError::NotANumber(_)
        ));
        assert!(matches!(
            parse_size("G", 512).unwrap_err(),
            SizeParseError::NotANumber(_)
        ));
    }

    #[test]
    fn absurd_sizes_are_rejected_rather_than_wrapping() {
        assert_eq!(
            parse_size("999999999P", 512).unwrap_err(),
            SizeParseError::TooLarge
        );
    }

    #[test]
    fn zero_is_a_valid_parse_even_if_not_a_valid_partition() {
        // Rejecting it here would hide the clearer "below the minimum size"
        // message that validation produces.
        assert_eq!(parse_size("0", 512).unwrap(), 0);
    }

    #[test]
    fn create_size_accepts_max_without_weakening_other_size_parsers() {
        assert_eq!(
            parse_create_size(" max ", 512).unwrap(),
            CreateSizeSpec::Max
        );
        assert_eq!(parse_create_size("MAX", 4096).unwrap(), CreateSizeSpec::Max);
        assert_eq!(
            parse_create_size("2048s", 512).unwrap(),
            CreateSizeSpec::Bytes(1024 * 1024)
        );
        assert!(parse_size("max", 512).is_err());
        assert!(parse_size_spec("max", 512).is_err());
    }
}
