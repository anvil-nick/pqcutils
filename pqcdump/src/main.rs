use pcap::{Capture, Packet};
use etherparse::{SlicedPacket, TransportSlice};
use std::net::SocketAddr;
use std::collections::{BTreeSet, HashSet};
use std::{collections::HashMap, path::PathBuf};
use serde::{Serialize,Deserialize};
use rust_embed::RustEmbed;
use clap::Parser;
use crate::ssh::{FlowKey, SshSession, HostCapabilities};
use crate::tcp::{TcpReassembler, TcpFlowKey};
use crate::tls::TlsSessionKey;
use chrono::{DateTime, TimeZone, Utc};

mod ssh;
mod tls;
mod tcp;
mod report;

#[derive(Parser, Debug)]
#[command(
    name = "pqcdump",
    author = "Anvil Secure Inc",
    version,
    about = "Post-Quantum Cryptography PCAP Scanner",
    long_about = "pqcdump analyzes PCAP files and identifies hosts and established \
sessions to determine whether Post-Quantum Cryptography (PQC) algorithms are used \
or supported in TLS and SSH handshakes.",
    after_help = "pqcdump is free BSD-licensed software by Anvil Secure Inc (https://anvilsecure.com)."
)]
struct Args {
    /// Input PCAP file to analyze
    ///
    /// The PCAP should contain TLS or SSH traffic to analyze for post-quantum cryptographic algorithm support.
    #[arg(
        value_name = "PCAP file"
    )]
    pcap: PathBuf,

    /// Output HTML results file
    ///
    /// The generated file will contain identified hosts, sessions, and detected PQC capabilities.
    #[arg(
        value_name = "Output file path",
        default_value = "results.html"
    )]
    output: PathBuf,
}

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../pqcscan/support"]
#[include = "kex_algos.json"]
#[include = "tls_groups.json"]
#[include = "tls_cipher_suites.json"]
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

#[derive(Debug, Deserialize)]
pub struct TlsCipherSuite {
    #[serde(skip)]
    pub name: String,

    pub cipher_suite_id: u16,

    #[allow(dead_code)]
    pub obsolete: bool,

    #[allow(dead_code)]
    pub insecure: bool,

    #[allow(dead_code)]
    pub desc: String,

    #[allow(dead_code)]
    pub href: String,
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

fn load_cipher_suites() -> HashMap<u16, TlsCipherSuite> {
    let json_file = EmbeddedResources::get("tls_cipher_suites.json").unwrap();
    let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();

    let suites_by_name: HashMap<String, TlsCipherSuite> =
        serde_json::from_str(json_data).unwrap();

    let mut suites_by_id = HashMap::new();

    for (name, mut suite) in suites_by_name {
        suite.name = name;
        suites_by_id.insert(suite.cipher_suite_id, suite);
    }

    suites_by_id
}

fn main() {

    
    let args = Args::parse();

    let file_path = &args.pcap;

    let mut cap = Capture::from_file(file_path).expect("Failed to open pcap file");
    
    let mut ssh_sessions: HashMap<FlowKey, SshSession> = HashMap::new();
    let mut host_caps: HashMap<String, HostCapabilities> = HashMap::new();
    let mut tls_ciphers: HashMap<String, HashSet<u16>> = HashMap::new();
	let mut keyshare_groups: HashMap<String, HashSet<u16>> = HashMap::new();
	let mut tls_sessions: HashMap<TlsSessionKey, u16> = HashMap::new();
    let mut reassembler = TcpReassembler::new();

    let mut packet_count = 1;
    let mut start_time: Option<DateTime<Utc>> = None;
    let mut end_time: DateTime<Utc> = Utc::now();

    
    while let Ok(packet) = cap.next_packet() {
        log::debug!("{}", packet_count);
        process_packet(&packet,  &mut reassembler, &mut ssh_sessions, &mut host_caps, &mut tls_ciphers, &mut keyshare_groups, &mut tls_sessions);
        packet_count += 1;
        if start_time.is_none(){
            start_time = Some(Utc.timestamp_opt(packet.header.ts.tv_sec.into(), (packet.header.ts.tv_usec * 1000).try_into().unwrap()).unwrap());
        }
        end_time = Utc.timestamp_opt(packet.header.ts.tv_sec.into(), (packet.header.ts.tv_usec * 1000).try_into().unwrap()).unwrap();
    }

    let kex_algos = load_kex_algos();
    let groups = load_groups();
    let cipher_suites = load_cipher_suites();

    let mut ssh_hosts = BTreeSet::<String>::new();
    let mut ssh_hosts_pqc = HashMap::<String, String>::new();
    let mut ssh_sessions_results = HashMap::<String, HashSet::<SshSessionResult>>::new();

    let mut hosts = BTreeSet::<String>::new();
    let mut pqc_hosts = BTreeSet::<String>::new();

    log::info!("\n=== Host Capabilities ===");
    for (host, caps) in &host_caps {
        log::info!("{}", host);
        ssh_hosts.insert(host.to_string());
        hosts.insert(host.to_string());
        let mut pqc_supported = false;
        for alg in caps.supported_kex() {
            log::info!("  {}", alg);
            if let Some(algo) =  kex_algos.get(alg) {
                log::info!("{} {}", alg, algo.pqc);
                if algo.pqc {
                    pqc_supported = true;
                }
            } else {
                log::debug!("Algorithm not found ({})", alg);
            }
        }
        let pqc_support;
        if pqc_supported {
            pqc_support = "PQC Supported".to_string();
            pqc_hosts.insert(host.to_string());
        } else {
            pqc_support = "No Support".to_string();
        }
        ssh_hosts_pqc.insert(host.to_string(), pqc_support.to_string());
    }

    log::info!("\n=== Negotiated Sessions ===");
    let mut ssh_pqc_supported_count = 0;
    for (flow, session) in &ssh_sessions {
        if let Some(neg) = &session.negotiated() {
            let source_ip = flow.src().parse::<SocketAddr>().expect("invalid socket address").ip().to_string();
            let source_port = flow.src().parse::<SocketAddr>().expect("invalid socket address").port();
            let destination_ip = flow.dst().parse::<SocketAddr>().expect("invalid socket address").ip().to_string();
            let destination_port = flow.dst().parse::<SocketAddr>().expect("invalid socket address").port();
            
            ssh_sessions_results.insert(source_ip.clone(), HashSet::<SshSessionResult>::new());
            log::info!("{} -> {} : {}", flow.src(), flow.dst(), neg.kex());
            if let Some(algo) =  kex_algos.get(neg.kex()) {
                log::info!("{} {}", neg.kex(), algo.pqc);
                let description;
                if algo.pqc {
                    log::info!("PQC Supported");
                    ssh_pqc_supported_count += 1;
                    description = "PQC Supported";
                } else {
                    log::info!("NOT Supported");
                    description = "PQC NOT Supported";
                } 
                if let Some(set) = ssh_sessions_results.get_mut(&source_ip) {
                    let session_result = SshSessionResult::new(
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        description.to_string(),
                    );
                    set.insert(session_result);
                }
            } else {
                log::debug!("Algorithm not found ({})", &neg.kex());
            }
        }
    }

    let mut tls_hosts = BTreeSet::<String>::new();
    let mut tls_hosts_ciphers = HashMap::<String, BTreeSet::<String>>::new();
    let mut tls_hosts_pqc = HashMap::<String, BTreeSet::<String>>::new();
    let mut tls_sessions_results = HashMap::<String, HashSet::<TlsSessionResult>>::new();

    if !tls_ciphers.is_empty() {
        log::info!("\n=== TLS CIPHERS Map ===");
        for (key, values) in &tls_ciphers {
            log::info!("{}:", key);
            
            let source_ip = key.parse::<SocketAddr>().expect("invalid socket address").ip().to_string();
            tls_hosts.insert(source_ip.to_string());
            tls_hosts_ciphers.insert(source_ip.clone(), BTreeSet::<String>::new());
            for id in values {
                if let Some(cipher) = cipher_suites.get(id) {
                    log::info!("  {}", cipher.name);
                    if let Some(set) = tls_hosts_ciphers.get_mut(&source_ip) {
                        set.insert(format!(
                            "{}",
                            cipher.name)
                        );
                    }
                } else {
                    log::info!("  {} -> UNKNOWN", id);
                    if let Some(set) = tls_hosts_ciphers.get_mut(&source_ip) {
                        set.insert(format!(
                            "{}",
                            id)
                        );
                    }
                }
            }
        }
    }
	
    if !keyshare_groups.is_empty() {
        log::info!("\n=== KeyShare Groups Map ===");
        for (key, values) in &keyshare_groups {
            let source_ip = key.parse::<SocketAddr>().expect("invalid socket address").ip().to_string();            
            hosts.insert(source_ip.to_string());
            tls_hosts_pqc.insert(source_ip.clone(), BTreeSet::<String>::new());
            for value in values {
                if let Some(group) = groups.get(value) {
                    let description;
                    if group.hybrid {
                        description = format!("{} supports {} a hybrid algorithm", key, group.name);
                        pqc_hosts.insert(source_ip.to_string());
                    } else if group.pqc {
                        description = format!("{} supports {} which is pure PQC", key, group.name);
                        pqc_hosts.insert(source_ip.to_string());
                    } else {
                        description = format!("{} supports {} which is not PQC safe", key, group.name);
                    }
                    log::info!("{}", description);
                    if let Some(set) = tls_hosts_pqc.get_mut(&source_ip) {
                        set.insert(description);
                    }
                    
                }
            }
        }
    }

    for (key, set) in &tls_hosts_pqc {
        log::info!("Key: {}", key);

        for value in set {
            log::info!("  {}", value);
        }
    }


    let mut tls_pqc_supported_count = 0; 
    if !tls_sessions.is_empty() {
        log::info!("\n=== Negotiated TLS Sessions ===");
        for (key, value) in &tls_sessions {
            log::info!("{}", key);
            let source_ip = key.src_ip;
            let source_port = key.src_port;
            let destination_ip = key.dst_ip;
            let destination_port = key.dst_port;
            tls_sessions_results
                .entry(source_ip.to_string())
                .or_insert_with(HashSet::<TlsSessionResult>::new);
            if let Some(group) = groups.get(value) {
                log::info!("{} -> {}", key, group.name);
                let description;
                if group.hybrid {
                    description = "hybrid";
                    tls_pqc_supported_count += 1;
                } else if group.pqc {
                    description = "full";
                    tls_pqc_supported_count += 1;
                } else {
                    description = "none";
                }
                log::info!("{}", description);
                if let Some(set) = tls_sessions_results.get_mut(&source_ip.to_string()) {
                    let key = TlsSessionResult::new(
                        source_ip.to_string(),
                        source_port,
                        destination_ip.to_string(),
                        destination_port,
                        description.to_string(),
                    );
                    set.insert(key);
                }
            }
        }
    }

    let results: ReportResults = ReportResults {
        total_count: hosts.len(),
        pqc_count: pqc_hosts.len(),
        ssh_total_count: ssh_sessions.len(),
        ssh_pqc_supported_count: ssh_pqc_supported_count,
        tls_total_count: tls_sessions.len(),
        tls_pqc_supported_count: tls_pqc_supported_count,
        packet_count: packet_count,
        start_time: start_time.unwrap_or(Utc::now()),
        end_time: end_time,
        ssh_host_capabilities: host_caps.clone(),
        ssh_hosts: ssh_hosts,
        ssh_hosts_pqc: ssh_hosts_pqc,
        ssh_sessions_results: ssh_sessions_results,
        tls_hosts: tls_hosts,
        tls_hosts_pqc: tls_hosts_pqc,
        tls_sessions_results: tls_sessions_results,
    };

    if let Err(e) = report::generate_report(&args.output, results) {
        eprintln!("Error generating report: {:#}", e);
    }    
}

#[derive(Serialize)]
struct ReportResults {
    total_count: usize,
    pqc_count: usize,
    ssh_total_count: usize,
    ssh_pqc_supported_count: usize,
    tls_total_count: usize,
    tls_pqc_supported_count: usize,
    packet_count: usize,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    ssh_host_capabilities: HashMap<String, HostCapabilities>,
    ssh_hosts: BTreeSet<String>,
    ssh_hosts_pqc: HashMap<String, String>,
    ssh_sessions_results: HashMap::<String, HashSet::<SshSessionResult>>,
    tls_hosts: BTreeSet<String>,
    tls_hosts_pqc: HashMap::<String, BTreeSet::<String>>,
    tls_sessions_results: HashMap::<String, HashSet::<TlsSessionResult>>,
}

#[derive(Serialize, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct TlsSessionResult {
    source: String,
    source_port: u16,
    destination: String,
    destination_port: u16,
    pqc_status: String,
}

impl TlsSessionResult {
    pub fn new(source: String, source_port: u16, destination: String, port: u16, pqc_status: String ) -> Self {
        Self { source, source_port, destination_port: port, destination, pqc_status }
    }
}

#[derive(Serialize, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct SshSessionResult {
    source: String,
    source_port: u16,
    destination: String,
    destination_port: u16,
    pqc_status: String,
}

impl SshSessionResult {
    pub fn new(source: String, source_port: u16, destination: String, port: u16, pqc_status: String ) -> Self {
        Self { source, source_port, destination_port: port, destination, pqc_status }
    }
}

fn process_packet(packet: &Packet,
    reassembler: &mut TcpReassembler,
    sessions: &mut HashMap<FlowKey, SshSession>,
    ssh_host_caps: &mut HashMap<String, HostCapabilities>,
    tls_ciphers: &mut HashMap<String, HashSet<u16>>,
    keyshare_groups: &mut HashMap<String, HashSet<u16>>,
    tls_sessions: &mut HashMap<TlsSessionKey, u16>) {
    match SlicedPacket::from_ethernet(&packet) {
	    Err(sliced) => log::debug!("Err {:?}", sliced),
	    Ok(sliced) => {
			log::debug!("link: {:?}", sliced.link);
			log::debug!("link_exts: {:?}", sliced.link_exts); // contains vlan & macsec
			log::debug!("net: {:?}", sliced.net); // contains ip & arp
			log::debug!("transport: {:?}", sliced.transport);			

            let (src_ip, dst_ip) = match sliced.net {
                Some(etherparse::NetSlice::Ipv4(ref ipv4)) => (
                    ipv4.header().source_addr().to_string(),
                    ipv4.header().destination_addr().to_string(),
                ),
                Some(etherparse::NetSlice::Ipv6(ref ipv6)) => (
                    ipv6.header().source_addr().to_string(),
                    ipv6.header().destination_addr().to_string(),
                ),
                _ => return,
            };

            let tcp = match sliced.transport {
                Some(TransportSlice::Tcp(ref t)) => t,
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

            process_packet_helper(&sliced, &payload, sessions, ssh_host_caps, &tcp, tls_ciphers, keyshare_groups, tls_sessions);

            // Try a reassembled packet
            if let Some(data) = reassembler.push(key, tcp.sequence_number(), tcp.payload()) { 
                let payload = &data; 
                process_packet_helper(&sliced, &payload, sessions, ssh_host_caps, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
            }   
        }
    }	
}

fn process_packet_helper(sliced: &SlicedPacket, 
        payload: &[u8], 
        ssh_sessions: &mut HashMap<FlowKey, SshSession>,
        ssh_host_capabilities: &mut HashMap<String, HostCapabilities>,
        tcp: &etherparse::TcpSlice<'_>,
        tls_ciphers: &mut HashMap<String, HashSet<u16>>, 
        keyshare_groups: &mut HashMap<String, HashSet<u16>>,
        tls_sessions: &mut HashMap<TlsSessionKey, u16>){
    if payload[5] == 20 {
        log::debug!("This may be an SSH_MSG_KEXINIT message");
        ssh::process_ssh(&sliced, &payload, ssh_sessions, ssh_host_capabilities);
    }

    // Check SSLv3+ ClientHello
    if payload.len() > 5
        && payload[0] == 0x16
        && payload[1] == 0x03
        && (0x00..=0x04).contains(&payload[2])
    {
        tls::process_ssl_hello(&sliced, &payload, &tcp, tls_ciphers, keyshare_groups, tls_sessions);
    }
}