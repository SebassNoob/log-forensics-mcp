use crate::constants::*;
use lzma_rust2::XzReader;
use ruzstd::decoding::StreamingDecoder;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};

pub fn le(buf: &[u8], base: u64, field: u64, width: usize) -> Option<u64> {
    let start = usize::try_from(base.checked_add(field)?).ok()?;
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(buf.get(start..start.checked_add(width)?)?);
    Some(u64::from_le_bytes(value))
}

pub fn decompress(blob: &[u8], flags: u8) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match flags & (OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD) {
        0 => out.extend_from_slice(blob),
        OBJECT_COMPRESSED_XZ => {
            XzReader::new(blob, false).read_to_end(&mut out)?;
        }
        OBJECT_COMPRESSED_LZ4 => {
            let size = le(blob, 0, 0, 8)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "truncated lz4 payload"))?;
            out = lz4_flex::block::decompress(&blob[8..], size as usize)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        }
        OBJECT_COMPRESSED_ZSTD => {
            StreamingDecoder::new(blob)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
                .read_to_end(&mut out)?;
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "more than one compression flag",
            ))
        }
    }
    Ok(out)
}

/// The entry, plus the offsets of the DATA objects holding its fields.
pub fn parse_entry(buf: &[u8], offset: u64, compact: bool) -> Result<EntryObject> {
    let invalid = |why| Error::new(ErrorKind::InvalidData, why);
    let start = usize::try_from(offset).map_err(|_| invalid("entry offset out of range"))?;
    let size = usize::try_from(le(buf, offset, OBJECT_SIZE_OFFSET, 8).ok_or(invalid("truncated"))?)
        .map_err(|_| invalid("entry size out of range"))?;
    let entry = buf
        .get(start..start.checked_add(size).ok_or(invalid("truncated"))?)
        .filter(|slice| slice.len() >= ENTRY_ITEMS_OFFSET)
        .ok_or(invalid("entry shorter than its header"))?;

    let mut at = Cursor { buf: entry, at: 0 };
    let object = ObjectHeader {
        r#type: at.take::<1>()[0],
        flags: at.take::<1>()[0],
        reserved: at.take(),
        size: at.u64(),
    };
    if object.r#type != OBJECT_ENTRY {
        return Err(invalid("not an entry object"));
    }

    let (seqnum, realtime, monotonic, boot_id, xor_hash) =
        (at.u64(), at.u64(), at.u64(), at.take(), at.u64());
    let stride = if compact {
        ENTRY_ITEM_SIZE_COMPACT
    } else {
        ENTRY_ITEM_SIZE
    };
    let mut fields = Vec::new();
    while at.at + stride <= size {
        let item = at.at;
        let data = if compact {
            u64::from(at.u32())
        } else {
            at.u64()
        };
        at.at = item + stride;
        if let Some(field) = field(buf, data, compact) {
            fields.push(field);
        }
    }

    Ok(EntryObject {
        object,
        seqnum,
        realtime,
        monotonic,
        boot_id,
        xor_hash,
        fields,
    })
}

/// The `FIELD=value` text of one DATA object, decompressed if it was stored that way.
fn field(buf: &[u8], data: u64, compact: bool) -> Option<String> {
    let payload = if compact {
        DATA_PAYLOAD_OFFSET_COMPACT
    } else {
        DATA_PAYLOAD_OFFSET
    };
    let start = usize::try_from(data.checked_add(payload)?).ok()?;
    let end = usize::try_from(data.checked_add(le(buf, data, OBJECT_SIZE_OFFSET, 8)?)?).ok()?;
    let flags = le(buf, data, OBJECT_FLAGS_OFFSET, 1)? as u8;
    let blob = decompress(buf.get(start..end)?, flags).ok()?;
    Some(String::from_utf8_lossy(&blob).into_owned())
}

pub(crate) struct Cursor<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) at: usize,
}

impl Cursor<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> [u8; N] {
        let bytes = self.buf[self.at..self.at + N].try_into().unwrap();
        self.at += N;
        bytes
    }

    pub(crate) fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }

    pub(crate) fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }
}

pub fn parse_header(file_path: &str) -> Result<Header> {
    let mut file = File::open(file_path)?;
    let mut buf = [0u8; size_of::<Header>()];
    file.read_exact(&mut buf)?;

    if buf[..8] != SIGNATURE {
        return Err(Error::new(ErrorKind::InvalidData, "not a journal file"));
    }
    let header_size = u64::from_le_bytes(
        buf[HEADER_SIZE_OFFSET..HEADER_SIZE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if header_size < HEADER_SIZE_MIN || header_size > file.metadata()?.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "implausible header_size",
        ));
    }
    // all fields after n_data is new, so on an older file those bytes are arena content rather than header fields.
    buf[(header_size as usize).min(size_of::<Header>())..].fill(0);

    let mut at = Cursor { buf: &buf, at: 0 };
    let header = Header {
        signature: at.take(),
        compatible_flags: at.u32(),
        incompatible_flags: at.u32(),
        state: at.take::<1>()[0],
        reserved: at.take(),
        file_id: at.take(),
        machine_id: at.take(),
        tail_entry_boot_id: at.take(),
        seqnum_id: at.take(),
        header_size: at.u64(),
        arena_size: at.u64(),
        data_hash_table_offset: at.u64(),
        data_hash_table_size: at.u64(),
        field_hash_table_offset: at.u64(),
        field_hash_table_size: at.u64(),
        tail_object_offset: at.u64(),
        n_objects: at.u64(),
        n_entries: at.u64(),
        tail_entry_seqnum: at.u64(),
        head_entry_seqnum: at.u64(),
        entry_array_offset: at.u64(),
        head_entry_realtime: at.u64(),
        tail_entry_realtime: at.u64(),
        tail_entry_monotonic: at.u64(),
        n_data: at.u64(),
        n_fields: at.u64(),
        n_tags: at.u64(),
        n_entry_arrays: at.u64(),
        data_hash_chain_depth: at.u64(),
        field_hash_chain_depth: at.u64(),
        tail_entry_array_offset: at.u32(),
        tail_entry_array_n_entries: at.u32(),
        tail_entry_offset: at.u64(),
    };

    Ok(header)
}

pub struct Entries {
    pub(crate) buf: Vec<u8>,
    pub(crate) array: u64,
    pub(crate) item: u64,
    pub(crate) compact: bool,
}

impl Iterator for Entries {
    type Item = EntryObject;

    fn next(&mut self) -> Option<EntryObject> {
        let width = if self.compact {
            ENTRY_ARRAY_ITEM_SIZE_COMPACT
        } else {
            ENTRY_ARRAY_ITEM_SIZE
        };
        loop {
            if self.array == 0 {
                return None;
            }
            let size = le(&self.buf, self.array, OBJECT_SIZE_OFFSET, 8)?;
            if self.item >= size.saturating_sub(ENTRY_ARRAY_ITEMS_OFFSET) / width as u64 {
                self.array = le(&self.buf, self.array, ENTRY_ARRAY_NEXT_OFFSET, 8)?;
                self.item = 0;
                continue;
            }
            let field = ENTRY_ARRAY_ITEMS_OFFSET + self.item * width as u64;
            self.item += 1;
            // Journald preallocates arrays, so unused trailing slots read as zero.
            match le(&self.buf, self.array, field, width) {
                Some(0) | None => continue,
                Some(offset) => {
                    if let Ok(entry) = parse_entry(&self.buf, offset, self.compact) {
                        return Some(entry);
                    }
                }
            }
        }
    }
}
