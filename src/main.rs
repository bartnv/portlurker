#![allow(dead_code, unused_must_use)]
use std::io;
use std::error::Error;
use std::os::unix::io::AsRawFd;
use std::net::{ IpAddr, SocketAddr };
use std::process::exit;
use std::sync::{ Arc, RwLock, atomic::Ordering, atomic::AtomicUsize };
use std::time::{ Duration, Instant };
use std::ffi::CString;
use yaml_rust::YamlLoader;
use regex::bytes::{ RegexSet, RegexSetBuilder };
use chrono::{ Local, Utc, DateTime };
use pnet::packet::{ Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket };
use nix::sys::socket::{ setsockopt, sockopt::IpTransparent };
use tokio::{ net::TcpListener, io::AsyncReadExt, io::AsyncWriteExt, sync::mpsc::{channel, Sender, Receiver }, fs::{ File, OpenOptions } };
use tokio_io_timeout::TimeoutStream;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BINARY_MATCHES: [(&str, &str, &str);41] = [ // Global array, so needs an explicit length
    ("ssl3.0", "SSL3.0 Record Protocol", r"^\x16\x03\x00..\x01"),
    ("tls1.0", "TLS1.0 Record Protocol", r"^\x16\x03\x01..\x01"),
    ("tls1.1", "TLS1.1 Record Protocol", r"^\x16\x03\x02..\x01"),
    ("tls1.2", "TLS1.2 Record Protocol", r"^\x16\x03\x03..\x01"),
    ("ssl3.0-hello", "SSL3.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x00"),
    ("tls1.0-hello", "TLS1.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x01"),
    ("tls1.1-hello", "TLS1.1 CLIENT_HELLO", r"^\x16....\x01...\x03\x02"),
    ("tls1.2-hello", "TLS1.2 CLIENT_HELLO", r"^\x16....\x01...\x03\x03"),
    ("tls1.3-preferred", "TLS1.3 preferred", r"^\x16....\x01...\x03\x03.*\x00\x2b...\x03\x04"),
    ("tls-sni-hostname", "TLS SNI hostname", r"^\x16....\x01...\x03\x03.*\x00\x00..\x00\x11\x00"),
    ("smb1-comm-nego", "SMB1 COMMAND NEGOTIATE", r"^....\xffSMB\x72"),
    ("smb1-stat-succ", "SMB1 NT_STATUS Success", r"^....\xffSMB.[\x00-\x0f]"),
    ("smb1-stat-info", "SMB1 NT_STATUS Information", r"^....\xffSMB.[\x40-\x4f]"),
    ("smb1-stat-warn", "SMB1 NT_STATUS Warning", r"^....\xffSMB.[\x80-\x8f]"),
    ("smb1-stat-error", "SMB1 NT_STATUS Error", r"^....\xffSMB.[\xc0-\xcf]"),
    ("smb2-comm-nego", "SMB2 COMMAND NEGOTIATE", r"^\x00...\xfeSMB........\x00\x00"),
    ("smb2-stat-succ", "SMB2 NT_STATUS Success", r"^\x00...\xfeSMB....[\x00-\x0f]"),
    ("smb2-stat-info", "SMB2 NT_STATUS Information", r"^\x00...\xfeSMB....[\x40-\x4f]"),
    ("smb2-stat-warn", "SMB2 NT_STATUS Warning", r"^\x00...\xfeSMB....[\x80-\x8f]"),
    ("smb2-stat-error", "SMB2 NT_STATUS Error", r"^\x00...\xfeSMB....[\xc0-\xcf]"),
    ("mstds-pre-req", "MS-TDS PRELOGIN Request", r"^\x12\x01\x00.\x00\x00"),
    ("mstds-login-req", "MS-TDS LOGIN Request", r"^\x10\x01\x00.\x00\x00"),
    ("socks4-noauth", "SOCKS4 NOAUTH Request", r"^\x04\x01\x00\x50"),
    ("socks5-noauth", "SOCKS5 NOAUTH Request", r"^\x05\x01\x00$"), // Tested ok-ish
    ("socks5-user", "SOCKS5 USER/PASS Request", r"^\x05\x02\x00\x02$"), // possibly broken
    ("bitcoin", "Bitcoin main chain magic number", r"\xf9\xbe\xb4\xd9"),
    ("rfb3", "RFB3 (VNC) protocol handshake", r"^RFB 003\.00."),
    ("http1.0", "HTTP 1.0 request", "^[^ ]+ [^ ]+ HTTP/1.0"),
    ("http1.1", "HTTP 1.1 request", "^[^ ]+ [^ ]+ HTTP/1.1"),
    ("http-get", "HTTP GET request", "^GET [^ ]+ HTTP/"),
    ("http-post", "HTTP POST request", "^POST [^ ]+ HTTP/"),
    ("json-rpc", "JSON RPC", r#"\{.*"jsonrpc".*\}"#),
    ("android-adb", "Android ADB CONNECT", r"^CNXN\x00\x00\x00\x01"),
    ("msrdp-conn-req", "MS-RDP Connection Request", "Cookie: mstshash="),
    ("gen-dropper-curl", "Generic payload dropper", r"curl( |\+|%20)"),
    ("gen-dropper-wget", "Generic payload dropper", r"wget( |\+|%20)"),
    ("squelda1.0", "SQLdict MSSQL brute force tool", r"squelda 1.0"),
    ("mctp-remote", "MCTP REMOTE request", r"^REMOTE .*? MCTP/"),
    ("mctp-kguard-dvr", "Kguard DVR auth bypass", r"^REMOTE HI_SRDK_.*? MCTP/"),
    ("tcp-cgi", "TCP CGI", r"GATEWAY_INTERFACE"),
    ("php-exec", "PHP shell exec", r"<?php .*?shell_exec")
];

#[derive(Clone)]
struct App {
    print_ascii: bool,
    print_binary: bool,
    sql_logging: bool,
    sql_connection: String,
    file_logging: bool,
    nfqueue: Option<u16>,
    bind_ip: String,
    io_timeout: Duration,
    regexset: RegexSet
}

struct LogEntry {
    timestamp: DateTime<Utc>,
    localip: String,
    localport: u16,
    remoteip: String,
    remoteport: u16,
    payloadbytes: u16,
    payloadhash: String,
    detections: String,
    termination: &'static str,
    duration: u32,
}
impl LogEntry {
    fn from(local: SocketAddr, peer: SocketAddr) -> LogEntry {
        LogEntry {
            timestamp: Utc::now(),
            localip: local.ip().to_string(),
            localport: local.port(),
            remoteip: peer.ip().to_string(),
            remoteport: peer.port(),
            payloadbytes: 0,
            payloadhash: String::new(),
            detections: String::new(),
            termination: "",
            duration: 0
        }
    }
}

struct State {
    ports: Vec<u16>,
    logchan: Sender<LogEntry>,
    transparent: bool
}
impl State {
    pub fn new(logchan: Sender<LogEntry>, transparent: bool) -> State {
        State { ports: vec![], logchan, transparent }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut count = 0;
    let mut result = String::with_capacity(67);
    let mut dotline = String::with_capacity(18);

    for byte in bytes.iter() {
        if count != 0 && count%8 == 0 {
            result.push(' ');
            if count%16 == 0 {
                dotline.push('\n');
                result.push_str(&dotline);
                result.reserve(67);
                dotline.truncate(0);
            }
            else { dotline.push(' '); }
        }
        result.push_str(&format!("{:02X} ", byte));
        if *byte > 31 && *byte < 127 { dotline.push(*byte as char) }
        else if *byte == 0 { dotline.push('-'); }
        else { dotline.push('.'); }
        count += 1;
    }
    while count%16 != 0 {
        if count%8 == 0 { result.push(' '); }
        result.push_str("   ");
        count += 1;
    }
    if !dotline.is_empty() {
        result.push(' ');
        result.push_str(&dotline);
    }
    result
}
fn to_dotline(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());

    for byte in bytes.iter() {
        if *byte > 31 && *byte < 127 { result.push(*byte as char) }
        else if *byte == 0 { result.push('-'); }
        else { result.push('.'); }
    }
    result
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Portlurker v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));
    println!("-----------------------------------------");

    let app = Arc::new(RwLock::new(App {
        print_ascii: false,
        print_binary: false,
        sql_logging: false,
        sql_connection: String::new(),
        file_logging: false,
        nfqueue: None,
        bind_ip: String::new(),
        io_timeout: Duration::new(125, 0),
        regexset: RegexSet::new(&[] as &[&str])?
    }));

    let mut config_str = String::new();
    let mut file = match File::open("config.yml").await {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Unable to open configuration file: {}", e.to_string());
            exit(1);
        },
    };

    file.read_to_string(&mut config_str).await?;
    let docs = YamlLoader::load_from_str(&config_str)?;
    let config = &docs[0];

    if config["general"].is_badvalue() {
        eprintln!("No 'general' section found in configuration file");
        exit(1);
    }
    if config["ports"].is_badvalue() {
        eprintln!("No 'ports' section found in configuration file");
        exit(1);
    }
    if config["ports"].as_vec().is_none() {
        eprintln!("'ports' section in configuration file is not a list");
        exit(1);
    }

    {
        let mut app = app.write().unwrap();
        if !config["general"]["bind_ip"].is_badvalue() {
            app.bind_ip = match config["general"]["bind_ip"].as_str() {
                Some(str) => str.to_owned(),
                None => {
                    eprintln!("Configuration item 'bind_ip' is not valid");
                    exit(1);
                }
            };
            println!("Binding to external IP {}", app.bind_ip);
        }
        else { app.bind_ip = String::from("0.0.0.0"); }

        if !config["general"]["print_ascii"].is_badvalue() {
            app.print_ascii = match config["general"]["print_ascii"].as_bool() {
                Some(bool) => bool,
                None => {
                    eprintln!("Configuration item 'print_ascii' is not a valid boolean");
                    exit(1);
                }
            };
            if app.print_ascii { println!("Printing ASCII"); }
        }
        if !config["general"]["print_binary"].is_badvalue() {
            app.print_binary = match config["general"]["print_binary"].as_bool() {
                Some(bool) => bool,
                None => {
                    eprintln!("Configuration item 'print_binary' is not a valid boolean");
                    exit(1);
                }
            };
            if app.print_binary{ println!("Printing binary in hexadecimal"); }
        }
        if !config["general"]["file_logging"].is_badvalue() {
            app.file_logging = match config["general"]["file_logging"].as_bool() {
                Some(bool) => bool,
                None => {
                    eprintln!("Configuration item 'file_logging' is not a valid boolean");
                    exit(1);
                }
            };
            if app.file_logging { println!("Logging to local text file"); }
        }
        if !config["general"]["sql_logging"].is_badvalue() {
            if config["general"]["sql_logging"].as_bool().unwrap() {
                match config["general"]["sql_connection"].as_str() {
                    Some(conn) => {
                        app.sql_logging = true;
                        app.sql_connection = conn.to_owned();
                        println!("Logging to SQL database connection {}", conn);
                    },
                    None => {
                        println!("No valid SQL connection string found; continuing without SQL logging");
                    }
                };
            }
        }
        if !config["general"]["nfqueue"].is_badvalue() {
            match config["general"]["nfqueue"].as_i64() {
                Some(queue) => {
                    app.nfqueue = Some(queue as u16);
                    println!("Receiving SYN packets from nfqueue {}", app.nfqueue.unwrap());
                    println!("Example iptables rule to make this work:");
                    println!("\n  iptables -A INPUT -p tcp --syn -j NFQUEUE --queue-num {} --queue-bypass", app.nfqueue.unwrap());
                },
                None => {
                    eprintln!("Configuration item 'nfqueue' is not a valid integer");
                    exit(1);
                }
            };
        }

        let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
        for &(_, _, pattern) in BINARY_MATCHES.iter() {
            patterns.push(pattern);
        }
        app.regexset = RegexSetBuilder::new(patterns)
        .unicode(false)
        .dot_matches_new_line(false)
        .build()?;
    }

    // Start logging thread
    let (tx, rx) = channel(100);
    {
        let app = app.read().unwrap();
        let params = (app.sql_logging, app.sql_connection.clone(), app.file_logging);
        tokio::spawn(async move { log(rx, params.0, params.1, params.2).await });
    }

    println!("\nStarting listeners on the following ports:");
    let mut tcp_ports: Vec<u16> = vec![];
    let mut transparent: bool = false;
    let count = Arc::new(AtomicUsize::new(0));
    for port in config["ports"].as_vec().unwrap() {
        if let Some(portno) = port["tcp"].as_i64() {
            tcp_ports.push(portno as u16);
            println!("TCP port {}", portno);
            let mut banner = Arc::new(String::new());
            if let Some(x) = port["banner"].as_str() {
                Arc::get_mut(& mut banner).unwrap().push_str(x);
                println!("  with banner: {}", to_dotline(x.as_bytes()));
            }
            let app = app.clone();
            let logchan = tx.clone();
            let bind_ip = app.read().unwrap().bind_ip.clone();
            match TcpListener::bind((bind_ip.as_str(), portno as u16)).await {
                Ok(socket) => {
                    if let Some(bool) = port["transparent"].as_bool() {
                        transparent = bool;
                        println!("  transparent mode: true");
                        let fd = socket.as_raw_fd();
                        let res = setsockopt(fd, IpTransparent, &true);
                        res.expect("ERROR setting sockopt IP_TRANSPARENT on TPROXY socket; this feature requires cap_net_raw or root privilege");
                    }
                    lurk(app, socket, logchan, banner, count.clone())
                },
                Err(e) => { println!("ERROR binding to {}: {}", portno, e.to_string()) }
            };
        }
        else if let Some(udp) = port["udp"].as_i64() {
            println!("UDP port {}", udp);
        }
        else {
            println!("Invalid port specification in configuration file");
        }
    }

    let nfqueue = app.read().unwrap().nfqueue;
    if let Some(qid) = nfqueue {
        tokio::task::spawn_blocking(move || {
            let mut state = State::new(tx, transparent);
            state.ports = tcp_ports.clone();
            let mut q = nfq::Queue::open().expect("Failed to open nfqueue");
            q.bind(qid).expect("ERROR binding nfqueue; this feature requires cap_net_admin or root privilege");
            q.set_copy_range(qid, 64).expect("Failed to set_copy_range on nfqueue"); // 64 bits should be sufficient to look at the TCP header
            loop {
                let mut msg = q.recv().expect("Failed to receive from nfqueue");
                let header = Ipv4Packet::new(msg.get_payload());
                match header {
                    Some(h) => match h.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => match TcpPacket::new(h.payload()) {
                            Some(p) => {
                                let remoteip = IpAddr::V4(h.get_source());
                                let flags = p.get_flags();
                                if flags&2 != 0 {
                                    let mut extra = Vec::new();
                                    if flags&1 != 0 { extra.push("FIN"); }
                                    if flags&4 != 0 { extra.push("RST"); }
                                    if flags&8 != 0 { extra.push("PSH"); }
                                    if flags&16 != 0 { extra.push("ACK"); }
                                    if flags&32 != 0 { extra.push("URG"); }
                                    let text = match extra.len() {
                                        0 => String::new(),
                                        _ => format!(" with extra flags [{}]", extra.join(","))
                                    };
                                    if !state.transparent && !state.ports.contains(&p.get_destination()) { println!("{:>5} = TCP SYN from {}:{} (unmonitored){}", p.get_destination(), remoteip, p.get_source(), text); }
                                    else { println!("{:>5} = TCP SYN from {}:{}{}", p.get_destination(), remoteip, p.get_source(), text); }
                                    // let _ = state.logchan.send(LogEntry { entrytype: LogEntryType::Syn, remoteip: remoteip.to_string(), remoteport: p.get_source(), localport: p.get_destination() });
                                }
                                else if flags&4 != 0 {
                                    let mut extra = Vec::new();
                                    if flags&1 != 0 { extra.push("FIN"); }
                                    if flags&2 != 0 { extra.push("SYN"); }
                                    if flags&8 != 0 { extra.push("PSH"); }
                                    if flags&16 != 0 { extra.push("ACK"); }
                                    if flags&32 != 0 { extra.push("URG"); }
                                    if extra.is_empty() { println!("{:>5} _ TCP RST from {}:{}", p.get_destination(), remoteip, p.get_source()); }
                                    else { println!("{:>5} _ TCP RST from {}:{} with extra flags [{}]", p.get_destination(), remoteip, p.get_source(), extra.join(",")); }
                                }
                            },
                            None => println!("Received malformed TCP packet")
                        },
                        _ => println!("Received a non-TCP packet: {:?}", h)
                    },
                    None => println!("Received malformed IPv4 packet")
                }

                msg.set_verdict(nfq::Verdict::Accept);
                q.verdict(msg).expect("Failed to send verdict on nfqueue");
            }
        });
    }

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if let Ok(title) = CString::new(format!("PortLurker [{}]", count.load(Ordering::Relaxed)).as_bytes()) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, title.as_ptr(), 0, 0, 0)
            };
        }
    }
}

fn lurk(app: Arc<RwLock<App>>, socket: TcpListener, logchan: Sender<LogEntry>, banner: Arc<String>, count: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        let io_timeout = app.read().unwrap().io_timeout;
        loop {
            let mut stream = match socket.accept().await {
                Ok(stream) => Box::pin(TimeoutStream::new(stream.0)),
                Err(e) if e.to_string() == "Too many open files" => {
                    println!("{:>5} ? TCP ERR ACCEPT: {}", match socket.local_addr() { Ok(a) => a.port(), Err(_) => 0 }, e);
                    tokio::time::sleep(Duration::from_secs(1));
                    continue;
                }
                Err(e) => {
                    println!("{:>5} ? TCP ERR ACCEPT: {}", match socket.local_addr() { Ok(a) => a.port(), Err(_) => 0 }, e);
                    continue;
                }
            };
            stream.as_mut().set_read_timeout_pinned(Some(io_timeout));
            stream.as_mut().set_write_timeout_pinned(Some(io_timeout));
            let local = match stream.get_ref().local_addr() { Ok(a) => a, Err(_) => continue };
            let peer = match stream.get_ref().peer_addr() {
                Ok(addr) => addr,
                Err(e) => { println!("{:>5} ? TCP ERR GETADDR: {}", local.port(), e.to_string()); continue; }
            };

            println!("{:>5} + TCP ACK from {}", local.port(), peer);
            count.fetch_add(1, Ordering::Relaxed);
            let mut logentry = LogEntry::from(local, peer);

            let app = app.clone();
            let banner = banner.clone();
            let count = count.clone();
            let logchan = logchan.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                if banner.len() > 0 {
                    match stream.write((*banner).as_bytes()).await {
                        Ok(_) => println!("{:>5} > {}", local.port(), to_dotline((*banner).as_bytes())),
                        Err(e) => {
                            logentry.termination = match e.kind() {
                                io::ErrorKind::TimedOut => {
                                    println!("{:>5} - TCP WRITE TIMEOUT from {}", local.port(), peer);
                                    "write-timeout"
                                }
                                _ => {
                                    println!("{:>5} - TCP ERR WRITE to {}: {}", local.port(), peer, e.to_string());
                                    "write-error"
                                }
                            };
                            logentry.duration = start.elapsed().as_millis() as u32;
                            logchan.send(logentry).await;
                            count.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }
                let mut buf: [u8; 2048] = [0; 2048];
                let mut detections: Vec<&str> = vec![];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(c) => {
                            if c == 0 {
                                println!("{:>5} - TCP FIN from {} after {:.1}s", local.port(), peer, start.elapsed().as_secs_f32());
                                logentry.termination = "closed";
                                break;
                            }
                            logentry.payloadbytes += c as u16;
                            let mut printables = Vec::new();
                            let mut found = false;
                            let mut mbfound = false;
                            let mut mbstring = String::new();
                            let mut start = 0;
                            for i in 0..c {
                                if (buf[i] > 31 && buf[i] < 127) || buf[i] == 10 || buf[i] == 13 {
                                    if !found {
                                        start = i;
                                        found = true;
                                    }
                                }
                                else if found {
                                    if i-start == 1 {
                                        if (start > 0) && (buf[start-1] == 0) {
                                            mbstring.push(buf[i-1] as char);
                                            if !mbfound { mbfound = true; }
                                        }
                                    }
                                    else { printables.push(&buf[start..i]); }
                                    found = false;
                                }
                                else if mbfound {
                                    mbstring.push('\n');
                                    mbfound = false;
                                }
                            }
                            if found { printables.push(&buf[start..c]); }
                            if printables.len() == 1 && printables[0].len() == c {
                                if app.read().unwrap().print_ascii {
                                    let data = String::from_utf8_lossy(printables[0]);
                                    for line in data.lines() {
                                        println!("{:>5} | {}", local.port(), line.replace("\r", ""));
                                    }
                                }
                                else { println!("{:>5} ! Read {} bytes of printable ASCII", local.port(), c); }
                            }
                            else {
                                println!("{:>5} ! Read {} bytes of binary", local.port(), c);
                                for printable in printables {
                                    if printable.len() > 3 {
                                        let data = String::from_utf8_lossy(printable);
                                        for line in data.lines() {
                                            println!("{:>5} $ {}", local.port(), line);
                                        }
                                    }
                                }
                                for line in mbstring.lines() {
                                    if line.len() > 3 { println!("{:>5} % {}", local.port(), line.replace("\r", "")); }
                                }
                                if app.read().unwrap().print_binary {
                                    let hex = to_hex(&buf[..c]);
                                    for line in hex.lines() { println!("{:>5} . {}", local.port(), line); }
                                }
                            }
                            for id in app.read().unwrap().regexset.matches(&buf[..c]).into_iter() {
                                println!("{:>5} ^ Matches pattern {}", local.port(), BINARY_MATCHES[id].1);
                                detections.push(BINARY_MATCHES[id].0);
                            }
                        }
                        Err(e) => {
                            logentry.termination = match e.kind() {
                                io::ErrorKind::TimedOut => {
                                    println!("{:>5} - TCP READ TIMEOUT from {}", local.port(), peer);
                                    "read-timeout"
                                }
                                _ => {
                                    println!("{:>5} - TCP ERR READ from {}: {}", local.port(), peer, e.to_string());
                                    "read-error"
                                }
                            };
                            break;
                        }
                    }
                }
                logentry.duration = start.elapsed().as_millis() as u32;
                detections.sort_unstable();
                detections.dedup();
                logentry.detections = detections.join(",");
                logchan.send(logentry).await;
                count.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
}

async fn log(mut rx: Receiver<LogEntry>, sql_logging: bool, sql_connection: String, file_logging: bool) {
    use sqlx::{ Connection, AnyConnection };

    let mut db = match sql_logging {
        true => match AnyConnection::connect(&sql_connection).await {
            Ok(conn) => Some(conn),
            Err(_) => {
                eprintln!("Failed to connect to SQL database with {}", sql_connection);
                None
            }
        }
        false => None
    };

    loop {
        let conn: LogEntry = rx.recv().await.unwrap();

        if file_logging {
            let log_msg = format!("{} TCP {}:{:<5} from {}:{:<5} {:.1}s {}b {} {}\n", Local::now().format("%Y-%m-%d %H:%M:%S"), conn.localip, conn.localport, conn.remoteip, conn.remoteport, conn.duration as f32/1000.0, conn.payloadbytes, conn.termination, conn.detections);
            let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("portlurker.log").await.expect("Failed to open local log file for writing");
            file.write_all(log_msg.as_bytes()).await.expect("Failed to write to log file");
        }
        if let Some(ref mut db) = db {
            sqlx::query("INSERT INTO connections (timestamp, localip, localport, remoteip, remoteport) VALUES (?, ?, ?, ?, ?)")
                .bind(conn.timestamp.to_string())
                .bind(conn.localip)
                .bind(conn.localport as i32) // Postgres doesn't support unsigned integers so we go from u16 to i32
                .bind(conn.remoteip)
                .bind(conn.remoteport as i32)
                .execute(db).await;
        }
    }
}
