//! Portable bounded file reads and local artifact path syntax; no device I/O.
use std::{io::Read, path::Path};

pub fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("could not open {}: {e}", path.display()))?;
    let budget = u64::try_from(maximum_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or("invalid file read budget")?;
    let mut bytes = Vec::new();
    file.take(budget)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    if bytes.len() > maximum_bytes {
        return Err(format!("{} exceeds the permitted size", path.display()));
    }
    Ok(bytes)
}

/// UTF-8 text-file profile accepts a leading BOM. Limits apply to on-disk bytes.
pub fn read_bounded_text(path: &Path, maximum_bytes: usize) -> Result<String, String> {
    let text = String::from_utf8(read_bounded(path, maximum_bytes)?)
        .map_err(|_| format!("{} is not UTF-8", path.display()))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

pub fn is_local_report_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(r"\\")
        && !path.starts_with("//")
        && path
            .char_indices()
            .all(|(i, c)| c != ':' || i == 1 && path.as_bytes()[0].is_ascii_alphabetic())
}
