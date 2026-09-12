//! Synthetic ISO images for parser and downstream preparation tests.
//!
//! Available only to tests or when the `test-fixtures` feature is enabled.

pub(crate) const BLOCK: usize = 2048;

fn put_dual_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_dual_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn record(extent: u32, length: u32, flags: u8, name: &[u8]) -> Vec<u8> {
    let record_length = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    let mut record = vec![0; record_length];
    record[0] = record_length as u8;
    put_dual_u32(&mut record, 2, extent);
    put_dual_u32(&mut record, 10, length);
    record[25] = flags;
    put_dual_u16(&mut record, 28, 1);
    record[32] = name.len() as u8;
    record[33..33 + name.len()].copy_from_slice(name);
    record
}

fn descriptor(kind: u8, root_extent: u32, joliet: bool) -> Vec<u8> {
    let mut descriptor = vec![0; BLOCK];
    descriptor[0] = kind;
    descriptor[1..6].copy_from_slice(b"CD001");
    descriptor[6] = 1;
    descriptor[40..50].copy_from_slice(b"TEST_IMAGE");
    put_dual_u32(&mut descriptor, 80, 24);
    put_dual_u16(&mut descriptor, 120, 1);
    put_dual_u16(&mut descriptor, 124, 1);
    put_dual_u16(&mut descriptor, 128, BLOCK as u16);
    if joliet {
        descriptor[88..91].copy_from_slice(b"%/E");
    }
    let root = record(root_extent, BLOCK as u32, 0x02, &[0]);
    descriptor[156..156 + root.len()].copy_from_slice(&root);
    descriptor
}

pub fn image(joliet: bool) -> Vec<u8> {
    let mut image = vec![0; 24 * BLOCK];
    image[16 * BLOCK..17 * BLOCK].copy_from_slice(&descriptor(1, 20, false));
    let terminator_sector = if joliet {
        image[17 * BLOCK..18 * BLOCK].copy_from_slice(&descriptor(2, 20, true));
        18
    } else {
        17
    };
    let mut terminator = vec![0; BLOCK];
    terminator[0] = 255;
    terminator[1..6].copy_from_slice(b"CD001");
    terminator[6] = 1;
    image[terminator_sector * BLOCK..(terminator_sector + 1) * BLOCK].copy_from_slice(&terminator);
    let names: Vec<Vec<u8>> = if joliet {
        vec![
            vec![0],
            vec![1],
            "hello world.txt;1"
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect(),
        ]
    } else {
        vec![vec![0], vec![1], b"HELLO.TXT;1".to_vec()]
    };
    let records = [
        record(20, BLOCK as u32, 0x02, &names[0]),
        record(20, BLOCK as u32, 0x02, &names[1]),
        record(21, 5, 0, &names[2]),
    ];
    let mut cursor = 20 * BLOCK;
    for record in records {
        image[cursor..cursor + record.len()].copy_from_slice(&record);
        cursor += record.len();
    }
    image[21 * BLOCK..21 * BLOCK + 5].copy_from_slice(b"hello");
    image
}
