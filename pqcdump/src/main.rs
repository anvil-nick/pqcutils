use pcap::{Capture, Packet};
use etherparse::{SlicedPacket};
use std::{collections::HashMap, path::PathBuf};
use serde::Deserialize;
use rust_embed::RustEmbed;
use clap::Parser;

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
    let mut ssh_kex_map: HashMap<String, Vec<String>> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet, &mut ssh_kex_map);
    }

    let kex_algos = load_kex_algos();

    if !ssh_kex_map.is_empty() {
        println!("\n=== SSH KEXINIT Map ===");
        for (key, value) in ssh_kex_map {
            let mut pqc_supported = false;
            println!("{}", key);
            for alg in value.iter() {
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
            println!("\n");
        }
    }
}

fn process_packet(packet: &Packet, ssh_kex_map: &mut HashMap<String, Vec<String>>) {
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
					
					if let Some(kex) = parse_ssh_kexinit(payload) {
						log::debug!("{:#?}", kex);
						
						let key = match &value.net {
							Some(etherparse::NetSlice::Ipv4(ipv4)) => {
								format!("{}:{}",
									ipv4.header().source_addr(),
									tcp.source_port())
							}
							Some(etherparse::NetSlice::Ipv6(ipv6)) => {
								format!("{}:{}",
									ipv6.header().source_addr(),
									tcp.source_port())
							}
							_ => "unknown:0".to_string(),
						};
						
                        log::debug!("Storing SSH KEXINIT for key {}", key);
                        ssh_kex_map.insert(key, kex);
						
					} else {
						log::debug!("Failed to parse SSH_MSG_KEXINIT");
					}
				}
            }
        }
    }	
}


fn parse_ssh_kexinit(payload: &[u8]) -> Option<Vec<String>> {
    // First byte should be 20 (SSH_MSG_KEXINIT)
    if payload.get(5)? != &20 {
        return None;
    }

    let mut data = &payload[6..];

    let _cookie: &[u8; 16] = data.get(..16)?.try_into().ok()?;
    data = &data[16..];

    read_name_list_owned(&mut data)
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