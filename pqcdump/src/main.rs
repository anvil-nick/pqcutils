use pcap::{Capture, Packet};
use etherparse::{SlicedPacket, TransportSlice};
use std::collections::HashSet;
use std::{collections::HashMap, path::PathBuf};
use serde::Deserialize;
use rust_embed::RustEmbed;
use clap::Parser;
use crate::ssh::{FlowKey, SshSession, HostCapabilities};
use crate::tcp::{TcpReassembler, TcpFlowKey};

mod ssh;
mod tls;
mod tcp;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to the .pcap file
    #[arg(value_name = "PCAP")]
    pcap: PathBuf,
}

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../pqcscan/support"]
#[include = "kex_algos.json"]
#[include = "tls_groups.json"]
struct EmbeddedResources;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct KexAlgo {
    pqc: bool,
    broken: bool,
    hybrid: Option<bool>,
    desc: Option<String>,
    href: Option<String>
}



#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsGroup {
    #[serde(skip)]
    name: String,
    group_id: u16,
    pqc: bool,
    hybrid: bool,
    #[allow(dead_code)] // currently not used
    obsolete: bool,
    #[allow(dead_code)] // currently not used
    insecure: bool,
    #[allow(dead_code)] // currently not used
    desc: String,
    #[allow(dead_code)] // currently not used
    href: String,
}

fn load_kex_algos() -> HashMap<String, KexAlgo> {
    let json_file = EmbeddedResources::get("kex_algos.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
    let kex_algos = serde_json::from_str(&json_data).unwrap();
    return kex_algos;
}

fn load_groups() -> HashMap<u16, TlsGroup> {
    let json_file = EmbeddedResources::get("tls_groups.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();

    let groups_by_name: HashMap<String, TlsGroup> =
        serde_json::from_str(json_data).unwrap();

    let mut groups_by_id = HashMap::new();

    for (name, mut group) in groups_by_name {
        group.name = name.clone();
        groups_by_id.insert(group.group_id, group);
    }

    groups_by_id
}

fn main() {
    let args = Args::parse();

    let file_path = &args.pcap;

    let mut cap = Capture::from_file(file_path).expect("Failed to open pcap file");
    
    let mut sessions: HashMap<FlowKey, SshSession> = HashMap::new();
    let mut host_caps: HashMap<String, HostCapabilities> = HashMap::new();
    let mut tls_ciphers: HashMap<String, HashSet<String>> = HashMap::new();
	let mut keyshare_groups: HashMap<String, HashSet<u16>> = HashMap::new();
	let mut tls_sessions: HashMap<String, u16> = HashMap::new();
    let mut reassembler = TcpReassembler::new();

    let mut n = 1;
    while let Ok(packet) = cap.next_packet() {
        log::debug!("{}", n);
        process_packet(&packet,  &mut reassembler, &mut sessions, &mut host_caps, &mut tls_ciphers, &mut keyshare_groups, &mut tls_sessions);
        n = n+ 1;
    }

    let kex_algos = load_kex_algos();
    let groups = load_groups();

    println!("\n=== Host Capabilities ===");
    for (host, caps) in &host_caps {
        println!("{}", host);
        let mut pqc_supported = false;
        for alg in caps.supported_kex() {
            println!("  {}", alg);
            if let Some(algo) =  kex_algos.get(alg) {
                log::info!("{} {}", alg, algo.pqc);
                if algo.pqc {
                    pqc_supported = true;
                }
            } else {
                log::debug!("Algorithm not found ({})", alg);
            }
        }
        if pqc_supported {
            println!("PQC Supported")
        } else {
            println!("No Support")
        }
    }

    println!("\n=== Negotiated Sessions ===");
    for (flow, session) in &sessions {
        if let Some(neg) = &session.negotiated() {
            println!("{} -> {} : {}", flow.src(), flow.dst(), neg.kex());
            if let Some(algo) =  kex_algos.get(neg.kex()) {
                log::info!("{} {}", neg.kex(), algo.pqc);
                if algo.pqc {
                    println!("PQC Supported");
                } else {
                    println!("NOT Supported");
                }
            } else {
                log::debug!("Algorithm not found ({})", &neg.kex());
            }
        }
    }

    if !tls_ciphers.is_empty() {
        log::debug!("\n=== TLS CIPHERS Map ===");
        for (key, value) in &tls_ciphers {
            log::debug!("{} => {:?}", key, value);
        }
    }
	
    if !keyshare_groups.is_empty() {
        println!("\n=== KeyShare Groups Map ===");
        for (key, values) in &keyshare_groups {
            for value in values {
                if let Some(group) = groups.get(value) {
                    if group.hybrid {
                        println!("{} supports {} which is hybrid", key, group.name);
                    } else if group.pqc {
                        println!("{} supports {} which is pure PQC", key, group.name);
                    } else {
                        println!("{} supports {} which is not PQC safe at all", key, group.name);
                    }
                }
            }
        }
    }

    if !tls_sessions.is_empty() {
        println!("\n=== Negotiated TLS Sessions ===");
        for (key, value) in &tls_sessions {
            if let Some(group) = groups.get(value) {
                println!("{} -> {}", key, group.name);
                if group.hybrid {
                    println!("{} is hybrid", key);
                } else if group.pqc {
                    println!("{} is pure PQC", key);
                } else {
                    println!("{} is not PQC safe at all", key);
                }
            }
        }
    }
}

fn process_packet(packet: &Packet,
    reassembler: &mut TcpReassembler,
    sessions: &mut HashMap<FlowKey, SshSession>,
    host_caps: &mut HashMap<String, HostCapabilities>,
    tls_ciphers: &mut HashMap<String, HashSet<String>>,
    keyshare_groups: &mut HashMap<String, HashSet<u16>>,
    tls_sessions: &mut HashMap<String, u16>) {
    match SlicedPacket::from_ethernet(&packet) {
	    Err(value) => log::debug!("Err {:?}", value),
	    Ok(value) => {
			log::debug!("link: {:?}", value.link);
			log::debug!("link_exts: {:?}", value.link_exts); // contains vlan & macsec
			log::debug!("net: {:?}", value.net); // contains ip & arp
			log::debug!("transport: {:?}", value.transport);			

            let sliced = match SlicedPacket::from_ethernet(packet.data) {
                Ok(s) => s,
                Err(_) => return,
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


            let tcp = match sliced.transport {
                Some(TransportSlice::Tcp(t)) => t,
                _ => return,
            };


            let key = TcpFlowKey::new(
                src_ip,
                dst_ip,
                tcp.source_port(),
                tcp.destination_port()
            );
            
            let payload = tcp.payload();
            if payload.len() < 6 {
                return;
            }

            if payload[5] == 20 {                
                log::debug!("This may be an SSH_MSG_KEXINIT message");
                ssh::process_ssh(packet, &payload, sessions, host_caps);
            }

            // Check SSLv3+ ClientHello
            if payload.len() > 5
                && payload[0] == 0x16
                && payload[1] == 0x03
                && (0x00..=0x04).contains(&payload[2])
            {
                tls::process_ssl_hello(&value, &payload, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
            }

            // Try a reassembled packet
            if let Some(data) = reassembler.push(key, tcp.sequence_number(), tcp.payload()) { 
                let payload = &data; 
                if payload[5] == 20 {
                    log::debug!("This may be an SSH_MSG_KEXINIT message");
                    ssh::process_ssh(packet, &payload, sessions, host_caps);
                }

                // Check SSLv3+ ClientHello
                if payload.len() > 5
                    && payload[0] == 0x16
                    && payload[1] == 0x03
                    && (0x00..=0x04).contains(&payload[2])
                {
                    tls::process_ssl_hello(&value, &payload, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
                }
            }   
        }
    }	
}
