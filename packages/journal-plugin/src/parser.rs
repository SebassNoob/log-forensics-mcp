use crate::constants::{Header, HEADER_INCOMPATIBLE_COMPACT};
use crate::parser_utils::{parse_header, Entries};
use std::io::Result;

pub fn parse(file_path: &str) -> Result<Journal> {
    let header = parse_header(file_path)?;
    let compact = header.incompatible_flags & HEADER_INCOMPATIBLE_COMPACT != 0;
    let entries = Entries {
        buf: std::fs::read(file_path)?,
        array: header.entry_array_offset,
        item: 0,
        compact,
    };
    Ok(Journal { header, entries })
}

pub struct Journal {
    pub header: Header,
    pub entries: Entries,
}
