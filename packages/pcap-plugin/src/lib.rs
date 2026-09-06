pub mod parser;

use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use parser::describe;
use pcap_parser::{create_reader, Block, Linktype, PcapBlockOwned, PcapError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use utils::{blocking, iso8601, unix_epoch_to_iso8601};

#[napi]
#[derive(Default)]
pub struct PcapPlugin {}

#[napi(object)]
pub struct FileStat {
    pub format: String,
    pub size_bytes: i64,
    pub modified_at: String,
    pub created_at: String,
    pub metadata: HashMap<String, Value>,
}

#[napi]
#[derive(Default)]
pub struct PcapTools {}

#[napi]
impl PcapPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        PcapPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "pcap-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to packet captures (pcap, pcapng).".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        let extension = Path::new(&file_path).extension();
        if ["pcap", "pcapng", "cap"]
            .iter()
            .any(|candidate| extension == Some(candidate.as_ref()))
        {
            return true;
        }
        let Ok(mut file) = File::open(&file_path) else {
            return false;
        };
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).is_ok()
            && matches!(
                u32::from_be_bytes(magic),
                // pcap in either byte order, at microsecond or nanosecond precision, plus the
                // pcapng section header block.
                0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 | 0x0a0d_0d0a
            )
    }

    #[napi(getter)]
    pub fn tools(&self) -> PcapTools {
        PcapTools {}
    }
}

#[napi]
impl PcapTools {
    #[napi]
    pub async fn search(&self, file_path: String, search_term: String) -> Result<Vec<String>> {
        if search_term.trim().is_empty() {
            return Err(Error::from_reason("search_term must not be empty"));
        }

        blocking(move || {
            let matcher = RegexMatcherBuilder::new()
                .fixed_strings(true)
                .case_smart(true)
                .build(&search_term)
                .map_err(|e| Error::from_reason(format!("Invalid search_term: {e}")))?;
            let mut lines = Vec::new();

            walk(&file_path, |line| {
                if matcher.is_match(line.as_bytes()).unwrap_or(false) {
                    lines.push(line.to_string());
                }
                true
            })?;

            Ok(lines)
        })
        .await
    }

    #[napi]
    pub async fn read(
        &self,
        file_path: String,
        offset: i64,
        max_bytes: i64,
    ) -> Result<Vec<String>> {
        if offset < 0 || max_bytes <= 0 {
            return Err(Error::from_reason("need offset >= 0 and max_bytes > 0"));
        }
        let (offset, max_bytes) = (offset as u64, max_bytes as usize);

        blocking(move || {
            let mut lines = Vec::new();
            let mut end = 0u64;
            let mut taken = 0usize;

            walk(&file_path, |line| {
                end += line.len() as u64 + 1; // newline the caller joins on
                if end <= offset {
                    return true;
                }
                if taken > 0 && taken + line.len() > max_bytes {
                    return false;
                }
                taken += line.len();
                lines.push(line.to_string());
                true
            })?;

            Ok(lines)
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let meta = std::fs::metadata(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;
            let capture = walk(&file_path, |_| true)?;

            let Value::Object(metadata) = json!({
                "version": capture.version,
                "snaplen": capture.snaplen,
                "linkTypes": capture.link_types,
                "packetCount": capture.packets,
                "firstPacketAt": capture.first_packet_at,
                "lastPacketAt": capture.last_packet_at,
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: capture.format,
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}

#[derive(Clone, Copy)]
struct Interface {
    linktype: Linktype,
    resolution: u64,
    ts_offset: i64,
}

struct Packet<'a> {
    timestamp: String,
    linktype: Linktype,
    data: &'a [u8],
    origlen: u32,
}

#[derive(Default)]
struct Capture {
    format: String,
    version: String,
    snaplen: u32,
    link_types: Vec<String>,
    packets: usize,
    first_packet_at: String,
    last_packet_at: String,
}

impl Capture {
    fn add_link_type(&mut self, linktype: Linktype) {
        let name = linktype.to_string();
        if !self.link_types.contains(&name) {
            self.link_types.push(name);
        }
    }
}

/// Stream every packet through `visit`, which returns false to stop early. The returned summary
/// only covers the blocks actually reached, so callers that stop early must not read its counters.
fn walk(file_path: &str, mut visit: impl FnMut(&str) -> bool) -> Result<Capture> {
    let file = File::open(file_path)
        .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\": {e}")))?;
    let mut reader = create_reader(65536, file)
        .map_err(|e| Error::from_reason(format!("\"{file_path}\" is not a capture file: {e}")))?;

    let mut capture = Capture::default();
    // Timestamp resolution and offset are per interface, and pcapng resets them at each section.
    let mut interfaces: Vec<Interface> = Vec::new();

    let mut stop = false;
    while !stop {
        match reader.next() {
            Ok((offset, block)) => {
                let packet = match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        capture.format = "pcap".to_string();
                        capture.version =
                            format!("{}.{}", header.version_major, header.version_minor);
                        capture.snaplen = header.snaplen;
                        capture.add_link_type(header.network);
                        interfaces = vec![Interface {
                            linktype: header.network,
                            resolution: if header.is_nanosecond_precision() {
                                1_000_000_000
                            } else {
                                1_000_000
                            },
                            ts_offset: 0,
                        }];
                        None
                    }
                    PcapBlockOwned::Legacy(packet) => interfaces.first().map(|interface| Packet {
                        timestamp: timestamp(
                            packet.ts_sec as u64,
                            packet.ts_usec as u64,
                            interface.resolution,
                        ),
                        linktype: interface.linktype,
                        data: packet.data,
                        origlen: packet.origlen,
                    }),
                    PcapBlockOwned::NG(Block::SectionHeader(section)) => {
                        capture.format = "pcapng".to_string();
                        capture.version =
                            format!("{}.{}", section.major_version, section.minor_version);
                        interfaces.clear();
                        None
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(description)) => {
                        capture.snaplen = capture.snaplen.max(description.snaplen);
                        capture.add_link_type(description.linktype);
                        interfaces.push(Interface {
                            linktype: description.linktype,
                            resolution: description.ts_resolution().unwrap_or(1_000_000),
                            ts_offset: description.ts_offset(),
                        });
                        None
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                        interfaces.get(packet.if_id as usize).map(|interface| {
                            let (seconds, fraction) =
                                packet.decode_ts(interface.ts_offset as u64, interface.resolution);
                            Packet {
                                timestamp: timestamp(
                                    seconds as u64,
                                    fraction as u64,
                                    interface.resolution,
                                ),
                                linktype: interface.linktype,
                                data: unpad(packet.data, packet.caplen),
                                origlen: packet.origlen,
                            }
                        })
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
                        interfaces.first().map(|interface| Packet {
                            // A simple packet block carries no timestamp of its own.
                            timestamp: String::new(),
                            linktype: interface.linktype,
                            data: unpad(packet.data, packet.origlen),
                            origlen: packet.origlen,
                        })
                    }
                    _ => None,
                };

                stop = match packet {
                    Some(packet) => {
                        let Value::Object(mut fields) = json!({
                            "linkType": packet.linktype.to_string(),
                            "capturedBytes": packet.data.len(),
                            "originalBytes": packet.origlen,
                        }) else {
                            unreachable!()
                        };
                        fields.extend(describe(packet.data, packet.linktype));
                        let line = format!(
                            "{}\t{}\t{}",
                            capture.packets,
                            packet.timestamp,
                            Value::Object(fields)
                        );

                        if capture.first_packet_at.is_empty() {
                            capture.first_packet_at = packet.timestamp.clone();
                        }
                        capture.last_packet_at = packet.timestamp;
                        capture.packets += 1;
                        !visit(&line)
                    }
                    None => false,
                };

                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    Ok(capture)
}

/// Packet blocks are padded to a 32-bit boundary; the trailing bytes are not captured data.
fn unpad(data: &[u8], captured: u32) -> &[u8] {
    data.get(..captured as usize).unwrap_or(data)
}

fn timestamp(seconds: u64, fraction: u64, resolution: u64) -> String {
    unix_epoch_to_iso8601(seconds * 1_000_000 + fraction.saturating_mul(1_000_000) / resolution)
}
