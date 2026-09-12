//! Bounded decoder for the LZNT1 byte stream stored in NTFS compression units.

const LZNT1_CHUNK_BYTES: usize = 4096;
const LZNT1_SIGNATURE: u16 = 0x3000;
const LZNT1_SIGNATURE_MASK: u16 = 0x7000;
const LZNT1_COMPRESSED: u16 = 0x8000;
const LZNT1_SIZE_MASK: u16 = 0x0fff;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Lznt1Error {
    #[error("the LZNT1 output limit must be greater than zero")]
    InvalidOutputLimit,
    #[error("the LZNT1 chunk header at byte {offset} is truncated")]
    TruncatedHeader { offset: usize },
    #[error("the LZNT1 chunk at byte {offset} has invalid signature 0x{signature:03x}")]
    InvalidSignature { offset: usize, signature: u16 },
    #[error("the LZNT1 chunk at byte {offset} claims {declared} bytes but only {available} remain")]
    TruncatedChunk {
        offset: usize,
        declared: usize,
        available: usize,
    },
    #[error("the LZNT1 match token at byte {offset} is truncated")]
    TruncatedMatch { offset: usize },
    #[error(
        "the LZNT1 match at byte {offset} uses displacement {displacement} with only {produced} bytes available"
    )]
    InvalidDisplacement {
        offset: usize,
        displacement: usize,
        produced: usize,
    },
    #[error("the LZNT1 chunk at byte {offset} expands beyond 4096 bytes")]
    ChunkOutputLimit { offset: usize },
    #[error("the LZNT1 stream expands beyond the configured {limit}-byte output limit")]
    OutputLimit { limit: usize },
    #[error("the LZNT1 end marker at byte {offset} is followed by nonzero data")]
    DataAfterEndMarker { offset: usize },
}

/// Decodes one complete, size-bounded LZNT1 buffer.
///
/// LZNT1 resets its match window at each 4096-byte chunk. NTFS may pad the
/// physical compression-unit allocation after a zero end marker, so trailing
/// zero bytes are accepted while any nonzero trailing byte fails closed.
pub fn decompress_lznt1(input: &[u8], output_limit: usize) -> Result<Vec<u8>, Lznt1Error> {
    if output_limit == 0 {
        return Err(Lznt1Error::InvalidOutputLimit);
    }
    let mut output = Vec::new();
    output
        .try_reserve(output_limit.min(input.len().saturating_mul(2)))
        .map_err(|_| Lznt1Error::OutputLimit {
            limit: output_limit,
        })?;
    let mut cursor = 0;
    while cursor < input.len() {
        if input.len() - cursor < 2 {
            return Err(Lznt1Error::TruncatedHeader { offset: cursor });
        }
        let chunk_offset = cursor;
        let header = u16::from_le_bytes([input[cursor], input[cursor + 1]]);
        cursor += 2;
        if header == 0 {
            if input[cursor..].iter().any(|byte| *byte != 0) {
                return Err(Lznt1Error::DataAfterEndMarker {
                    offset: chunk_offset,
                });
            }
            break;
        }
        let signature = header & LZNT1_SIGNATURE_MASK;
        if signature != LZNT1_SIGNATURE {
            return Err(Lznt1Error::InvalidSignature {
                offset: chunk_offset,
                signature,
            });
        }
        let total_bytes = usize::from(header & LZNT1_SIZE_MASK) + 3;
        let payload_bytes = total_bytes - 2;
        if payload_bytes > input.len() - cursor {
            return Err(Lznt1Error::TruncatedChunk {
                offset: chunk_offset,
                declared: total_bytes,
                available: input.len() - chunk_offset,
            });
        }
        let chunk_end = cursor + payload_bytes;
        let payload = &input[cursor..chunk_end];
        if header & LZNT1_COMPRESSED == 0 {
            append_literals(&mut output, payload, chunk_offset, output_limit)?;
        } else {
            decompress_chunk(payload, chunk_offset, output_limit, &mut output)?;
        }
        cursor = chunk_end;
    }
    Ok(output)
}

fn append_literals(
    output: &mut Vec<u8>,
    literals: &[u8],
    chunk_offset: usize,
    output_limit: usize,
) -> Result<(), Lznt1Error> {
    if literals.len() > LZNT1_CHUNK_BYTES {
        return Err(Lznt1Error::ChunkOutputLimit {
            offset: chunk_offset,
        });
    }
    if literals.len() > output_limit.saturating_sub(output.len()) {
        return Err(Lznt1Error::OutputLimit {
            limit: output_limit,
        });
    }
    output.extend_from_slice(literals);
    Ok(())
}

fn decompress_chunk(
    payload: &[u8],
    chunk_offset: usize,
    output_limit: usize,
    output: &mut Vec<u8>,
) -> Result<(), Lznt1Error> {
    let output_start = output.len();
    let mut cursor = 0;
    while cursor < payload.len() {
        let flags = payload[cursor];
        cursor += 1;
        for bit in 0..8 {
            if cursor >= payload.len() {
                break;
            }
            if flags & (1 << bit) == 0 {
                append_one(
                    output,
                    payload[cursor],
                    output_start,
                    chunk_offset,
                    output_limit,
                )?;
                cursor += 1;
                continue;
            }
            if payload.len() - cursor < 2 {
                return Err(Lznt1Error::TruncatedMatch {
                    offset: chunk_offset + 2 + cursor,
                });
            }
            let token_offset = chunk_offset + 2 + cursor;
            let token = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]);
            cursor += 2;
            let produced = output.len() - output_start;
            let (displacement, length) = decode_match(token, produced);
            if displacement > produced {
                return Err(Lznt1Error::InvalidDisplacement {
                    offset: token_offset,
                    displacement,
                    produced,
                });
            }
            if length > LZNT1_CHUNK_BYTES.saturating_sub(produced) {
                return Err(Lznt1Error::ChunkOutputLimit {
                    offset: chunk_offset,
                });
            }
            if length > output_limit.saturating_sub(output.len()) {
                return Err(Lznt1Error::OutputLimit {
                    limit: output_limit,
                });
            }
            for _ in 0..length {
                let source = output.len() - displacement;
                let byte = output[source];
                output.push(byte);
            }
        }
    }
    Ok(())
}

fn append_one(
    output: &mut Vec<u8>,
    byte: u8,
    output_start: usize,
    chunk_offset: usize,
    output_limit: usize,
) -> Result<(), Lznt1Error> {
    if output.len() - output_start == LZNT1_CHUNK_BYTES {
        return Err(Lznt1Error::ChunkOutputLimit {
            offset: chunk_offset,
        });
    }
    if output.len() == output_limit {
        return Err(Lznt1Error::OutputLimit {
            limit: output_limit,
        });
    }
    output.push(byte);
    Ok(())
}

fn decode_match(token: u16, produced: usize) -> (usize, usize) {
    let mut length_mask = 0x0fff_u16;
    let mut displacement_shift = 12_u32;
    let mut position = produced;
    while position >= 0x10 {
        length_mask >>= 1;
        displacement_shift -= 1;
        position >>= 1;
    }
    let length = usize::from(token & length_mask) + 3;
    let displacement = usize::from(token >> displacement_shift) + 1;
    (displacement, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_lznt1_example_decodes_exactly() {
        let encoded = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2,
            0x47, 0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58,
            0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let expected = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";
        assert_eq!(expected.len(), 142);
        assert_eq!(decompress_lznt1(&encoded, 4096).unwrap(), expected);
    }

    #[test]
    fn uncompressed_chunks_and_zero_padding_are_bounded() {
        let encoded = [0x02, 0x30, b'a', b'b', b'c', 0, 0, 0, 0];
        assert_eq!(decompress_lznt1(&encoded, 3).unwrap(), b"abc");
        assert_eq!(
            decompress_lznt1(&encoded, 2),
            Err(Lznt1Error::OutputLimit { limit: 2 })
        );
    }

    #[test]
    fn overlapping_matches_copy_newly_produced_bytes() {
        let encoded = [0x03, 0xb0, 0x02, b'a', 0x02, 0x00];
        assert_eq!(decompress_lznt1(&encoded, 6).unwrap(), b"aaaaaa");
    }

    #[test]
    fn malformed_chunks_tokens_and_back_references_fail_closed() {
        assert!(matches!(
            decompress_lznt1(&[0x00], 4096),
            Err(Lznt1Error::TruncatedHeader { .. })
        ));
        assert!(matches!(
            decompress_lznt1(&[0x00, 0x20, 0], 4096),
            Err(Lznt1Error::InvalidSignature { .. })
        ));
        assert!(matches!(
            decompress_lznt1(&[0x03, 0xb0, 0x01, 0], 4096),
            Err(Lznt1Error::TruncatedChunk { .. })
        ));
        assert!(matches!(
            decompress_lznt1(&[0x01, 0xb0, 0x01, 0], 4096),
            Err(Lznt1Error::TruncatedMatch { .. })
        ));
        assert!(matches!(
            decompress_lznt1(&[0x02, 0xb0, 0x01, 0, 0], 4096),
            Err(Lznt1Error::InvalidDisplacement { .. })
        ));
        assert!(matches!(
            decompress_lznt1(&[0, 0, 1], 4096),
            Err(Lznt1Error::DataAfterEndMarker { .. })
        ));
        let expansion_bomb = [
            0x0b, 0xb0, 0x00, b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', 0x01, 0xff, 0x0f,
        ];
        assert!(matches!(
            decompress_lznt1(&expansion_bomb, 8192),
            Err(Lznt1Error::ChunkOutputLimit { .. })
        ));
    }
}
