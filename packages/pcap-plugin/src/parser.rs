use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::PcapHeader;
use pcap_parser::{Block, PcapBlockOwned, PcapError};
use utils::unix_epoch_to_iso8601;

pub enum PcapType {
    Legacy,
    NG,
}

pub fn get_type(reader: &mut dyn PcapReaderIterator) -> Result<PcapType, PcapError<&'static [u8]>> {
    // The first block identifies the format: a legacy pcap file header, or a pcapng section
    // header block.
    let (_, block) = reader.next().map_err(|e| e.to_owned_vec())?;
    match block {
        PcapBlockOwned::LegacyHeader(_) => Ok(PcapType::Legacy),
        PcapBlockOwned::NG(Block::SectionHeader(_)) => Ok(PcapType::NG),
        _ => Err(PcapError::HeaderNotRecognized),
    }
}

pub struct Capture {
    pub linktype: String,
    pub snaplen: u32,
    pub packets: Vec<Packet>,
}

pub struct Packet {
    pub timestamp: String,
    pub caplen: u32,
    pub origlen: u32,
    pub data: Vec<u8>,
}

pub fn legacy(reader: &mut dyn PcapReaderIterator) -> Result<Capture, PcapError<&'static [u8]>> {
    let mut header = None;
    let mut packets = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => header = Some(h),
                    PcapBlockOwned::Legacy(p) => {
                        // Nanosecond captures put nanos in ts_usec.
                        let scale = match header.as_ref().map(PcapHeader::is_nanosecond_precision) {
                            Some(true) => 1000,
                            _ => 1,
                        };
                        packets.push(Packet {
                            timestamp: unix_epoch_to_iso8601(
                                p.ts_sec as u64 * 1_000_000 + (p.ts_usec / scale) as u64,
                            ),
                            caplen: p.caplen,
                            origlen: p.origlen,
                            data: p.data.to_vec(),
                        });
                    }
                    _ => return Err(PcapError::HeaderNotRecognized),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| e.to_owned_vec())?,
            Err(e) => return Err(e.to_owned_vec()),
        }
    }
    let header = header.ok_or(PcapError::HeaderNotRecognized)?;
    Ok(Capture {
        linktype: header.network.to_string(),
        snaplen: header.snaplen,
        packets,
    })
}

pub fn ng(reader: &mut dyn PcapReaderIterator) -> Result<Capture, PcapError<&'static [u8]>> {
    let mut capture = None;
    let mut resolution = 1_000_000;
    let mut ts_offset = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    // Packet timestamps are raw counts, decoded with the resolution and offset of
                    // the interface they were captured on.
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) if capture.is_none() => {
                        resolution = idb.ts_resolution().ok_or(PcapError::HeaderNotRecognized)?;
                        ts_offset = idb.ts_offset();
                        capture = Some(Capture {
                            linktype: idb.linktype.to_string(),
                            snaplen: idb.snaplen,
                            packets: Vec::new(),
                        });
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let (secs, frac) = epb.decode_ts(ts_offset as u64, resolution);
                        capture
                            .as_mut()
                            .ok_or(PcapError::HeaderNotRecognized)?
                            .packets
                            .push(Packet {
                                timestamp: unix_epoch_to_iso8601(
                                    secs as u64 * 1_000_000
                                        + (frac as u128 * 1_000_000 / resolution as u128) as u64,
                                ),
                                caplen: epb.caplen,
                                origlen: epb.origlen,
                                data: epb.packet_data().to_vec(),
                            });
                    }
                    // Simple packets carry no timestamp.
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => capture
                        .as_mut()
                        .ok_or(PcapError::HeaderNotRecognized)?
                        .packets
                        .push(Packet {
                            timestamp: String::new(),
                            caplen: spb.packet_data().len() as u32,
                            origlen: spb.origlen,
                            data: spb.packet_data().to_vec(),
                        }),
                    PcapBlockOwned::NG(_) => (),
                    _ => return Err(PcapError::HeaderNotRecognized),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| e.to_owned_vec())?,
            Err(e) => return Err(e.to_owned_vec()),
        }
    }
    capture.ok_or(PcapError::HeaderNotRecognized)
}
