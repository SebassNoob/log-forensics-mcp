use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::Linktype;
use pcap_parser::{Block, PcapBlockOwned, PcapError};
use utils::unix_epoch_to_iso8601;

pub enum PcapType {
    Legacy,
    NG,
}

pub fn get_type(reader: &mut dyn PcapReaderIterator) -> Result<PcapType, PcapError<&'static [u8]>> {
    // The first block identifies the format
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
    pub packets: Box<dyn Iterator<Item = Result<Packet, PcapError<&'static [u8]>>>>,
}

pub struct Packet {
    pub timestamp: String,
    pub caplen: u32,
    pub origlen: u32,
    pub data: Frame,
}

pub struct Frame {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub payload: Vec<u8>,
}

fn decode(data: &[u8], linktype: Linktype) -> Frame {
    let packet = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => SlicedPacket::from_ip(data).ok(),
        _ => None,
    };
    let Some(packet) = packet else {
        return Frame {
            source: String::new(),
            destination: String::new(),
            protocol: linktype.to_string(),
            payload: data.to_vec(),
        };
    };

    let mac = |bytes: [u8; 6]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let (source, destination) = match (&packet.net, &packet.link) {
        (Some(NetSlice::Ipv4(ip)), _) => (
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        ),
        // Bracketed so the ":port" appended below cannot be read as another address group.
        (Some(NetSlice::Ipv6(ip)), _) => (
            format!("[{}]", ip.header().source_addr()),
            format!("[{}]", ip.header().destination_addr()),
        ),
        (_, Some(LinkSlice::Ethernet2(ethernet))) => {
            (mac(ethernet.source()), mac(ethernet.destination()))
        }
        _ => (String::new(), String::new()),
    };

    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => Frame {
            source: format!("{source}:{}", tcp.source_port()),
            destination: format!("{destination}:{}", tcp.destination_port()),
            protocol: "TCP".to_string(),
            payload: tcp.payload().to_vec(),
        },
        Some(TransportSlice::Udp(udp)) => Frame {
            source: format!("{source}:{}", udp.source_port()),
            destination: format!("{destination}:{}", udp.destination_port()),
            protocol: "UDP".to_string(),
            payload: udp.payload().to_vec(),
        },
        Some(TransportSlice::Icmpv4(icmp)) => Frame {
            source,
            destination,
            protocol: "ICMP".to_string(),
            payload: icmp.payload().to_vec(),
        },
        Some(TransportSlice::Icmpv6(icmp)) => Frame {
            source,
            destination,
            protocol: "ICMPv6".to_string(),
            payload: icmp.payload().to_vec(),
        },
        Some(TransportSlice::Igmp(igmp)) => Frame {
            source,
            destination,
            protocol: "IGMP".to_string(),
            payload: igmp.payload().to_vec(),
        },
        None => Frame {
            source,
            destination,
            protocol: match &packet.net {
                Some(NetSlice::Ipv4(_)) => "IPv4".to_string(),
                Some(NetSlice::Ipv6(_)) => "IPv6".to_string(),
                Some(NetSlice::Arp(_)) => "ARP".to_string(),
                None => linktype.to_string(),
            },
            payload: packet
                .net
                .as_ref()
                .and_then(NetSlice::ip_payload_ref)
                .map_or(data, |ip| ip.payload)
                .to_vec(),
        },
    }
}

fn recover(
    reader: &mut dyn PcapReaderIterator,
    error: PcapError<&'static [u8]>,
) -> Result<bool, PcapError<&'static [u8]>> {
    match error {
        PcapError::Eof => Ok(false),
        PcapError::Incomplete(_) => {
            reader.refill().map_err(|e| e.to_owned_vec())?;
            Ok(true)
        }
        PcapError::BufferTooSmall => {
            let size = reader.data().len().max(65536) * 2;
            if reader.grow(size) {
                Ok(true)
            } else {
                Err(PcapError::BufferTooSmall)
            }
        }
        error => Err(error),
    }
}

pub fn legacy(
    mut reader: Box<dyn PcapReaderIterator + Send>,
) -> Result<Capture, PcapError<&'static [u8]>> {
    let header = loop {
        match reader.next() {
            Ok((offset, PcapBlockOwned::LegacyHeader(header))) => {
                reader.consume(offset);
                break header;
            }
            Ok(_) => return Err(PcapError::HeaderNotRecognized),
            Err(error) => {
                let error = error.to_owned_vec();
                if !recover(reader.as_mut(), error)? {
                    return Err(PcapError::HeaderNotRecognized);
                }
            }
        }
    };
    // Nanosecond captures put nanos in ts_usec.
    let scale = if header.is_nanosecond_precision() {
        1000
    } else {
        1
    };

    Ok(Capture {
        linktype: header.network.to_string(),
        snaplen: header.snaplen,
        packets: Box::new(std::iter::from_fn(move || loop {
            match reader.next() {
                Ok((offset, PcapBlockOwned::Legacy(block))) => {
                    let packet = Packet {
                        timestamp: unix_epoch_to_iso8601(
                            block.ts_sec as u64 * 1_000_000 + (block.ts_usec / scale) as u64,
                        ),
                        caplen: block.caplen,
                        origlen: block.origlen,
                        data: decode(block.data, header.network),
                    };
                    reader.consume(offset);
                    return Some(Ok(packet));
                }
                Ok(_) => return Some(Err(PcapError::HeaderNotRecognized)),
                Err(error) => {
                    let error = error.to_owned_vec();
                    match recover(reader.as_mut(), error) {
                        Ok(true) => (),
                        Ok(false) => return None,
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        })),
    })
}

pub fn ng(
    mut reader: Box<dyn PcapReaderIterator + Send>,
) -> Result<Capture, PcapError<&'static [u8]>> {
    let linktype;
    let snaplen;
    let resolution;
    let ts_offset;
    loop {
        match reader.next() {
            Ok((offset, PcapBlockOwned::NG(Block::InterfaceDescription(idb)))) => {
                linktype = idb.linktype;
                snaplen = idb.snaplen;
                resolution = idb.ts_resolution().ok_or(PcapError::HeaderNotRecognized)?;
                ts_offset = idb.ts_offset();
                reader.consume(offset);
                break;
            }
            Ok((offset, _)) => reader.consume(offset),
            Err(error) => {
                let error = error.to_owned_vec();
                if !recover(reader.as_mut(), error)? {
                    return Err(PcapError::HeaderNotRecognized);
                }
            }
        }
    }

    Ok(Capture {
        linktype: linktype.to_string(),
        snaplen,
        packets: Box::new(std::iter::from_fn(move || loop {
            match reader.next() {
                Ok((offset, PcapBlockOwned::NG(block))) => {
                    let packet = match block {
                        Block::EnhancedPacket(epb) => {
                            let (secs, frac) = epb.decode_ts(ts_offset as u64, resolution);
                            Some(Packet {
                                timestamp: unix_epoch_to_iso8601(
                                    secs as u64 * 1_000_000
                                        + (frac as u128 * 1_000_000 / resolution as u128) as u64,
                                ),
                                caplen: epb.caplen,
                                origlen: epb.origlen,
                                data: decode(epb.packet_data(), linktype),
                            })
                        }
                        // Simple packets carry no timestamp.
                        Block::SimplePacket(spb) => Some(Packet {
                            timestamp: String::new(),
                            caplen: spb.packet_data().len() as u32,
                            origlen: spb.origlen,
                            data: decode(spb.packet_data(), linktype),
                        }),
                        _ => None,
                    };
                    reader.consume(offset);
                    if let Some(packet) = packet {
                        return Some(Ok(packet));
                    }
                }
                Ok(_) => return Some(Err(PcapError::HeaderNotRecognized)),
                Err(error) => {
                    let error = error.to_owned_vec();
                    match recover(reader.as_mut(), error) {
                        Ok(true) => (),
                        Ok(false) => return None,
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        })),
    })
}
