use pcap::{Capture, Packet};
use etherparse::{SlicedPacket};
use std::{collections::HashMap, path::PathBuf};
use serde::Deserialize;
use rust_embed::RustEmbed;
use clap::Parser;
use crate::ssh::{FlowKey, SshSession, HostCapabilities};

mod ssh;

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

    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet, &mut sessions, &mut host_caps);
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
}

fn process_packet(packet: &Packet, sessions: &mut HashMap<FlowKey, SshSession>,
    host_caps: &mut HashMap<String, HostCapabilities>) {
    match SlicedPacket::from_ethernet(&packet) {
	    Err(value) => log::debug!("Err {:?}", value),
	    Ok(value) => {
			log::debug!("link: {:?}", value.link);
			log::debug!("link_exts: {:?}", value.link_exts); // contains vlan & macsec
			log::debug!("net: {:?}", value.net); // contains ip & arp
			log::debug!("transport: {:?}", value.transport);			
		
			if let Some(etherparse::TransportSlice::Tcp(ref tcp)) = value.transport {
				
				let payload = tcp.payload();
				
				if payload.len() < 6 {
                    return;
                }

				if payload[5] == 20 {
					log::debug!("This may be an SSH_MSG_KEXINIT message");

                    ssh::process_ssh(packet, payload, sessions, host_caps);
				}
            }
        }
    }	
}

