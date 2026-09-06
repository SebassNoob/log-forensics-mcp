use pcap_parser::data::{get_packetdata, PacketData, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use pcap_parser::Linktype;
use serde_json::{Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy)]
struct Network<'a> {
    ethertype: u16,
    packet: &'a [u8],
}

#[derive(Clone, Copy)]
struct Transport<'a> {
    protocol: u8,
    segment: &'a [u8],
}

/// Addresses, ports and flags an analyst would search a capture for. Anything below the transport
/// header, or behind an unsupported link type, is left undecoded.
pub fn describe(data: &[u8], linktype: Linktype) -> Map<String, Value> {
    let mut fields = Map::new();

    let network = match get_packetdata(data, linktype, data.len()) {
        Some(PacketData::L2(frame)) => ethernet(frame, &mut fields),
        Some(PacketData::L3(ethertype, packet)) => Some(Network { ethertype, packet }),
        Some(PacketData::L4(protocol, segment)) => {
            transport(Transport { protocol, segment }, &mut fields);
            None
        }
        _ => None,
    };

    if let Some(segment) = network.and_then(|network| ip(network, &mut fields)) {
        transport(segment, &mut fields);
    }

    fields
}

fn ethernet<'a>(frame: &'a [u8], fields: &mut Map<String, Value>) -> Option<Network<'a>> {
    let mac = |offset: usize| {
        frame[offset..offset + 6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let mut ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    fields.insert("srcMac".into(), mac(6).into());
    fields.insert("dstMac".into(), mac(0).into());

    // 802.1Q/802.1ad tags sit between the ethertype and the network header.
    let mut offset = 14;
    while matches!(ethertype, 0x8100 | 0x88a8) {
        ethertype = u16::from_be_bytes(frame.get(offset + 2..offset + 4)?.try_into().ok()?);
        offset += 4;
    }

    Some(Network {
        ethertype,
        packet: frame.get(offset..)?,
    })
}

fn ip<'a>(network: Network<'a>, fields: &mut Map<String, Value>) -> Option<Transport<'a>> {
    let packet = network.packet;
    let transport = match network.ethertype {
        ETHERTYPE_IPV4 => {
            let addr = |offset: usize| -> Option<String> {
                let octets: [u8; 4] = packet.get(offset..offset + 4)?.try_into().ok()?;
                Some(Ipv4Addr::from(octets).to_string())
            };
            fields.insert("srcIp".into(), addr(12)?.into());
            fields.insert("dstIp".into(), addr(16)?.into());
            Transport {
                protocol: *packet.get(9)?,
                segment: packet.get((packet[0] & 0x0f) as usize * 4..)?,
            }
        }
        ETHERTYPE_IPV6 => {
            let addr = |offset: usize| -> Option<String> {
                let octets: [u8; 16] = packet.get(offset..offset + 16)?.try_into().ok()?;
                Some(Ipv6Addr::from(octets).to_string())
            };
            fields.insert("srcIp".into(), addr(8)?.into());
            fields.insert("dstIp".into(), addr(24)?.into());
            Transport {
                protocol: *packet.get(6)?,
                segment: packet.get(40..)?,
            }
        }
        _ => return None,
    };

    fields.insert(
        "protocol".into(),
        match transport.protocol {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            47 => "GRE".to_string(),
            50 => "ESP".to_string(),
            58 => "ICMPv6".to_string(),
            other => other.to_string(),
        }
        .into(),
    );

    Some(transport)
}

fn transport(transport: Transport, fields: &mut Map<String, Value>) {
    if !matches!(transport.protocol, 6 | 17) {
        return;
    }
    let segment = transport.segment;

    let port = |offset: usize| -> Option<u16> {
        Some(u16::from_be_bytes(
            segment.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let Some(src) = port(0) else {
        return;
    };
    let Some(dst) = port(2) else {
        return;
    };
    fields.insert("srcPort".into(), src.into());
    fields.insert("dstPort".into(), dst.into());

    if transport.protocol == 6 {
        if let Some(bits) = segment.get(13) {
            let flags: Vec<&str> = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
                .into_iter()
                .enumerate()
                .filter(|(bit, _)| bits & (1 << bit) != 0)
                .map(|(_, name)| name)
                .collect();
            fields.insert("tcpFlags".into(), flags.join(",").into());
        }
    }
}
