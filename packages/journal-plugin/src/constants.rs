// https://github.com/systemd/systemd/blob/main/docs/JOURNAL_FILE_FORMAT.md

#[repr(C, packed)]
pub struct ObjectHeader {
    pub r#type: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub size: u64,
}

#[repr(C, packed)]
pub struct Header {
    pub signature: [u8; 8],
    pub compatible_flags: u32,
    pub incompatible_flags: u32,
    pub state: u8,
    pub reserved: [u8; 7],
    pub file_id: [u8; 16],
    pub machine_id: [u8; 16],
    pub tail_entry_boot_id: [u8; 16],
    pub seqnum_id: [u8; 16],
    pub header_size: u64,
    pub arena_size: u64,
    pub data_hash_table_offset: u64,
    pub data_hash_table_size: u64,
    pub field_hash_table_offset: u64,
    pub field_hash_table_size: u64,
    pub tail_object_offset: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub entry_array_offset: u64,
    pub head_entry_realtime: u64,
    pub tail_entry_realtime: u64,
    pub tail_entry_monotonic: u64,
    // Added in 187
    pub n_data: u64,
    pub n_fields: u64,
    // Added in 189
    pub n_tags: u64,
    pub n_entry_arrays: u64,
    // Added in 246
    pub data_hash_chain_depth: u64,
    pub field_hash_chain_depth: u64,
    // Added in 252
    pub tail_entry_array_offset: u32,
    pub tail_entry_array_n_entries: u32,
    // Added in 254
    pub tail_entry_offset: u64,
}

pub const SIGNATURE: [u8; 8] = *b"LPKSHHRH";
pub const HEADER_SIZE_OFFSET: usize = 88;
pub const HEADER_SIZE_MIN: u64 = 208;

pub const HEADER_INCOMPATIBLE_COMPACT: u32 = 1 << 4;

pub const OBJECT_ENTRY: u8 = 3;

pub const OBJECT_COMPRESSED_XZ: u8 = 1 << 0;
pub const OBJECT_COMPRESSED_LZ4: u8 = 1 << 1;
pub const OBJECT_COMPRESSED_ZSTD: u8 = 1 << 2;

pub const OBJECT_FLAGS_OFFSET: u64 = 1;
pub const OBJECT_SIZE_OFFSET: u64 = 8;

pub const DATA_PAYLOAD_OFFSET: u64 = 64;
pub const DATA_PAYLOAD_OFFSET_COMPACT: u64 = 72;

pub const ENTRY_ARRAY_NEXT_OFFSET: u64 = 16;
pub const ENTRY_ARRAY_ITEMS_OFFSET: u64 = 24;
pub const ENTRY_ARRAY_ITEM_SIZE: usize = 8;
pub const ENTRY_ARRAY_ITEM_SIZE_COMPACT: usize = 4;

pub const ENTRY_ITEMS_OFFSET: usize = 64;
pub const ENTRY_ITEM_SIZE: usize = 16;
pub const ENTRY_ITEM_SIZE_COMPACT: usize = 4;

pub struct EntryObject {
    pub object: ObjectHeader,
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: [u8; 16],
    pub xor_hash: u64,
    pub fields: Vec<String>,
}
