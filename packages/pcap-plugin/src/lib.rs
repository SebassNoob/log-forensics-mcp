pub mod parser;

use crate::parser::{get_type, legacy, ng, Capture, Packet, PcapType};
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use pcap_parser::create_reader;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::PcapError;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use utils::{blocking, iso8601};

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
    fn open(file_path: &str) -> Result<Box<dyn PcapReaderIterator + Send>> {
        let file = File::open(file_path)
            .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\": {e}")))?;
        create_reader(65536, file).map_err(|e| {
            Error::from_reason(format!("\"{file_path}\" is not a valid pcap file: {e}"))
        })
    }

    fn parse(file_path: &str) -> Result<Capture> {
        let mut reader = PcapTools::open(file_path)?;
        let capture = match get_type(reader.as_mut()) {
            Ok(PcapType::Legacy) => legacy(reader),
            Ok(PcapType::NG) => ng(reader),
            Err(e) => Err(e),
        };
        capture.map_err(|e| {
            Error::from_reason(format!("Failed to parse \"{file_path}\" as pcap: {e}"))
        })
    }

    fn packet(
        packet: std::result::Result<Packet, PcapError<&'static [u8]>>,
        file_path: &str,
    ) -> Result<Packet> {
        packet.map_err(|e| {
            Error::from_reason(format!("Failed to parse \"{file_path}\" as pcap: {e}"))
        })
    }

    fn line(index: usize, packet: &Packet) -> String {
        let mut payload = String::new();
        for &byte in &packet.data.payload {
            match byte {
                b' '..=b'~' => payload.push(byte as char),
                _ if !payload.ends_with('.') => payload.push('.'),
                _ => (),
            }
        }
        format!(
            "{index}\t{}\t{}\t{} > {}\t{}/{}\t{payload}",
            packet.timestamp,
            packet.data.protocol,
            packet.data.source,
            packet.data.destination,
            packet.caplen,
            packet.origlen
        )
    }

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
            for (index, packet) in PcapTools::parse(&file_path)?.packets.enumerate() {
                let line = PcapTools::line(index, &PcapTools::packet(packet, &file_path)?);
                if matcher.is_match(line.as_bytes()).unwrap_or(false) {
                    lines.push(line);
                }
            }

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

            for (index, packet) in PcapTools::parse(&file_path)?.packets.enumerate() {
                let line = PcapTools::line(index, &PcapTools::packet(packet, &file_path)?);
                end += line.len() as u64 + 1; // newline the caller joins on
                if end <= offset {
                    continue;
                }
                if taken > 0 && taken + line.len() > max_bytes {
                    break;
                }
                taken += line.len();
                lines.push(line);
            }

            Ok(lines)
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let meta = File::open(&file_path)
                .and_then(|file| file.metadata())
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;
            let capture = PcapTools::parse(&file_path)?;
            let mut count = 0usize;
            let mut first = None;
            let mut last = None;
            for packet in capture.packets {
                let packet = PcapTools::packet(packet, &file_path)?;
                if count == 0 {
                    first = Some(packet.timestamp.clone());
                }
                last = Some(packet.timestamp);
                count += 1;
            }

            let Value::Object(metadata) = json!({
                "linktype": capture.linktype,
                "snaplen": capture.snaplen,
                "packetCount": count,
                "firstPacket": first,
                "lastPacket": last,
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "pcap".to_string(),
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}
