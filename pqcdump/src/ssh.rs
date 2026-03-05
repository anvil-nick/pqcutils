use pcap::{Packet};
use etherparse::{SlicedPacket};
use std::{collections::HashMap};

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    src: String,
    dst: String,
}

impl FlowKey {
    pub fn src(&self) -> &str {
        &self.src
    }

    pub fn dst(&self) -> &str {
        &self.dst
    }
}

#[derive(Debug)]
pub struct SshSession {
    client_kexinit: Option<KexInit>,
    server_kexinit: Option<KexInit>,
    negotiated: Option<NegotiatedAlgorithms>,
}

impl SshSession {
    pub fn negotiated(&self) -> Option<&NegotiatedAlgorithms> {
        self.negotiated.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct KexInit {
    kex_algorithms: Vec<String>,
}

#[derive(Debug)]
pub struct NegotiatedAlgorithms {
    kex: String,
}

impl NegotiatedAlgorithms {
    pub fn kex(&self) -> &str {
        &self.kex
    }
}

#[derive(Default)]
pub struct HostCapabilities {
    supported_kex: linked_hash_set::LinkedHashSet<String>,
}

impl HostCapabilities {
    pub fn supported_kex(&self) -> &linked_hash_set::LinkedHashSet<String> {
        &self.supported_kex
    }
}

pub fn process_ssh(packet: &Packet, payload: &[u8], sessions: &mut HashMap<FlowKey, SshSession>,
    host_caps: &mut HashMap<String, HostCapabilities>){
    let kex = match parse_ssh_kexinit(payload) {
        Some(k) => k,
        None => return,
    };

    let sliced = match SlicedPacket::from_ethernet(packet) {
        Ok(v) => v,
        Err(_) => return,
    };

    let tcp = match sliced.transport {
        Some(etherparse::TransportSlice::Tcp(ref tcp)) => tcp,
        _ => return,
    };

    let (src_ip, dst_ip) = match sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
        ),
        Some(etherparse::NetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
        ),
        _ => return,
    };

    let flow = FlowKey {
        src: format!("{}:{}", src_ip, tcp.source_port()),
        dst: format!("{}:{}", dst_ip, tcp.destination_port()),
    };

    let reverse_flow = FlowKey {
        src: flow.dst.clone(),
        dst: flow.src.clone(),
    };

    // Determine if session already exists in forward or reverse direction
    let (session, is_forward) = if let Some(s) = sessions.get_mut(&flow) {
        (s, true)
    } else if let Some(s) = sessions.get_mut(&reverse_flow) {
        (s, false)
    } else {
        let s = sessions.entry(flow.clone()).or_insert(SshSession {
            client_kexinit: None,
            server_kexinit: None,
            negotiated: None,
        });
        (s, true)
    };

    if is_forward {
        if session.client_kexinit.is_none() {
            session.client_kexinit = Some(kex.clone());
            update_host_caps(host_caps, &src_ip, &kex);
        }
    } else {
        if session.server_kexinit.is_none() {
            session.server_kexinit = Some(kex.clone());
            update_host_caps(host_caps, &src_ip, &kex);
        }
    }

    // Perform negotiation if both present
    if session.client_kexinit.is_some()
        && session.server_kexinit.is_some()
        && session.negotiated.is_none()
    {
        let client = session.client_kexinit.as_ref().unwrap();
        let server = session.server_kexinit.as_ref().unwrap();

        if let Some(neg) = negotiate(&client.kex_algorithms, &server.kex_algorithms) {
            session.negotiated = Some(NegotiatedAlgorithms { kex: neg });
        }
    }
}

fn negotiate(client: &[String], server: &[String]) -> Option<String> {
    for alg in client {
        if server.contains(alg) {
            return Some(alg.clone());
        }
    }
    None
}

fn update_host_caps(
    host_caps: &mut HashMap<String, HostCapabilities>,
    host: &str,
    kex: &KexInit,
) {
    let entry = host_caps.entry(host.to_string()).or_default();

    for alg in &kex.kex_algorithms {
        entry.supported_kex.insert(alg.clone());
    }
}

fn parse_ssh_kexinit(payload: &[u8]) -> Option<KexInit> {
    if payload.len() < 6 || payload[5] != 20 {
        return None;
    }

    let mut data = &payload[6..];

    let _cookie: &[u8; 16] = data.get(..16)?.try_into().ok()?;
    data = &data[16..];

    let kex_algorithms = read_name_list_owned(&mut data)?;

    // Skip remaining 9 name-lists
    for _ in 0..9 {
        read_name_list_owned(&mut data)?;
    }

    Some(KexInit {
        kex_algorithms,
    })
}

fn read_name_list_owned(data: &mut &[u8]) -> Option<Vec<String>> {
    // Read u32 length prefix
    let len = read_u32(data)? as usize;

    if data.len() < len {
        return None;
    }

    let list_bytes = &data[..len];
    *data = &data[len..];

    // Convert to UTF-8 string
    let list_str = std::str::from_utf8(list_bytes).ok()?;

    // Split by commas and collect owned Strings
    let vec = list_str
        .split(',')
        .map(|s| s.to_string())
        .collect();

    Some(vec)
}

fn read_u32(data: &mut &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes(data[..4].try_into().unwrap());
    *data = &data[4..];
    Some(val)
}