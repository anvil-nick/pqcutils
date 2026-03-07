use pcap::{Capture, Packet};
use etherparse::{SlicedPacket, TransportSlice};
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

fn load_kex_algos() -> HashMap<String, KexAlgo> {
    let json_file = EmbeddedResources::get("kex_algos.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
    let kex_algos = serde_json::from_str(&json_data).unwrap();
    return kex_algos;
}

fn main() {
    let args = Args::parse();

    let file_path = &args.pcap;

    let mut cap = Capture::from_file(file_path).expect("Failed to open pcap file");
    
    let mut sessions: HashMap<FlowKey, SshSession> = HashMap::new();
    let mut host_caps: HashMap<String, HostCapabilities> = HashMap::new();
    let mut tls_ciphers: HashMap<String, Vec<String>> = HashMap::new();
	let mut keyshare_groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut reassembler = TcpReassembler::new();

    let mut n = 1;
    while let Ok(packet) = cap.next_packet() {
        log::debug!("{}", n);
        process_packet(&packet,  &mut reassembler, &mut sessions, &mut host_caps, &mut tls_ciphers, &mut keyshare_groups);
        n = n+ 1;
    }

    let kex_algos = load_kex_algos();

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
        for (key, value) in &keyshare_groups {
            log::debug!("{} => {:?}", key, value);
            let pqc_support = detect_pqc_support(value);
            if pqc_support != PqcSupport::None {
                if pqc_support == PqcSupport::Hybrid{
                    println!("{} supports hybrid", key);
                } else {
                    println!("{} supports PQC", key);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PqcSupport {
    None,
    Hybrid,
    PurePqc,
}

pub fn detect_pqc_support(groups: &Vec<String>) -> PqcSupport {
    // Pure PQ groups (Kyber / ML-KEM)
    const PURE_PQ: &[&str] = &[
        "kyber512", "kyber768", "kyber1024",
        "mlkem512", "mlkem768", "mlkem1024",
    ];

    // Hybrid KEM groups
    const HYBRID_PQ: &[&str] = &[
        "x25519_kyber512", "x25519_kyber768", "x25519_kyber1024",
        "secp256r1_kyber512", "secp256r1_kyber768", "secp256r1_kyber1024",

        // New concatenated names used by OpenSSL ≥3.3 / OQS provider
        "x25519mlkem512", "x25519mlkem768", "x25519mlkem1024",
        "secp256r1mlkem512", "secp256r1mlkem768", "secp256r1mlkem1024",
        "X25519MLKEM512", "X25519MLKEM768", "X25519MLKEM1024",
    ];

    let mut has_pure_pq = false;
    let mut has_hybrid = false;

    for g in groups {
        let g = g.as_str();
        if PURE_PQ.contains(&g) {
            has_pure_pq = true;
        }
        if HYBRID_PQ.contains(&g) {
            has_hybrid = true;
        }
    }

    if has_pure_pq {
        PqcSupport::PurePqc
    } else if has_hybrid {
        PqcSupport::Hybrid
    } else {
        PqcSupport::None
    }
}

fn process_packet(packet: &Packet,
    reassembler: &mut TcpReassembler,
    sessions: &mut HashMap<FlowKey, SshSession>,
    host_caps: &mut HashMap<String, HostCapabilities>,
    tls_ciphers: &mut HashMap<String, Vec<String>>, 
    keyshare_groups: &mut HashMap<String, Vec<String>>) {
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
                tls::process_ssl_hello(&value, &payload, &tcp, tls_ciphers, keyshare_groups);
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
                    tls::process_ssl_hello(&value, &payload, &tcp, tls_ciphers, keyshare_groups);
                }
            }
            
            
        }
    }	
}
