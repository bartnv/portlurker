extern crate yaml_rust;
extern crate regex;
extern crate rusqlite;
extern crate chrono;
extern crate libc;
extern crate nfqueue;
extern crate pnet;
extern crate nix;

use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::os::unix::io::AsRawFd;
use std::net::{TcpListener, IpAddr};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, Instant};
use yaml_rust::YamlLoader;
use regex::bytes::{RegexSet, RegexSetBuilder};
use rusqlite::Connection;
use rusqlite::types::ToSql;
use chrono::Local;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use nix::sys::socket::{setsockopt, sockopt::IpTransparent};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const BINARY_MATCHES: [(&str, &str);34] = [ // Global array, so needs an explicit length
  ("SSL3.0 Record Protocol", r"^\x16\x03\x00..\x01"),
  ("TLS1.0 Record Protocol", r"^\x16\x03\x01..\x01"),
  ("TLS1.1 Record Protocol", r"^\x16\x03\x02..\x01"),
  ("TLS1.2 Record Protocol", r"^\x16\x03\x03..\x01"),
  ("SSL3.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x00"),
  ("TLS1.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x01"),
  ("TLS1.1 CLIENT_HELLO", r"^\x16....\x01...\x03\x02"),
  ("TLS1.2 CLIENT_HELLO", r"^\x16....\x01...\x03\x03"),
  ("SMB1 COMMAND NEGOTIATE", r"^....\xffSMB\x72"),
  ("SMB1 NT_STATUS Success", r"^....\xffSMB.[\x00-\x0f]"),
  ("SMB1 NT_STATUS Information", r"^....\xffSMB.[\x40-\x4f]"),
  ("SMB1 NT_STATUS Warning", r"^....\xffSMB.[\x80-\x8f]"),
  ("SMB1 NT_STATUS Error", r"^....\xffSMB.[\xc0-\xcf]"),
  ("SMB2 COMMAND NEGOTIATE", r"^\x00...\xfeSMB........\x00\x00"),
  ("SMB2 NT_STATUS Success", r"^\x00...\xfeSMB....[\x00-\x0f]"),
  ("SMB2 NT_STATUS Information", r"^\x00...\xfeSMB....[\x40-\x4f]"),
  ("SMB2 NT_STATUS Warning", r"^\x00...\xfeSMB....[\x80-\x8f]"),
  ("SMB2 NT_STATUS Error", r"^\x00...\xfeSMB....[\xc0-\xcf]"),
  ("MS-TDS PRELOGIN Request", r"^\x12\x01\x00.\x00\x00"),
  ("MS-TDS LOGIN Request", r"^\x10\x01\x00.\x00\x00"),
  ("SOCKS4 NOAUTH Request", r"^\x04\x01\x00\x50"),
  ("SOCKS5 NOAUTH Request", r"^\x05\x01\x00$"), // Tested ok-ish
  ("SOCKS5 USER/PASS Request", r"^\x05\x02\x00\x02$"), // possibly broken
  ("Bitcoin main chain magic number", r"\xf9\xbe\xb4\xd9"),
  ("RFB3 (VNC) protocol handshake", r"^RFB 003\.00."),
  ("HTTP1 GET request", "^GET [^ ]+ HTTP/1"),
  ("HTTP1 POST request", "^POST [^ ]+ HTTP/1"),
  ("JSON RPC", r#"\{.*"jsonrpc".*\}"#),
  ("Android ADB CONNECT", r"^CNXN\x00\x00\x00\x01"),
  ("MS-RDP Connection Request", "Cookie: mstshash="),
  ("Generic payload dropper", r"(curl|wget)( |\+|%20)"),
  ("SQLdict MSSQL brute force tool", r"squelda 1.0"),
  ("MCTP REMOTE request", r"^REMOTE .*? MCTP/"),
  ("Kguard DVR auth bypass", r"^REMOTE HI_SRDK_.*? MCTP/")
];

#[derive(Clone)]
struct App {
  print_ascii: bool,
  print_binary: bool,
  sql_logging: bool,
  file_logging: bool,
  nfqueue: Option<u16>,
  bind_ip: String,
  io_timeout: Duration,
  regexset: RegexSet
}

#[derive(PartialEq, Eq)]
enum LogEntryType {
  Syn,
  Ack
}
impl fmt::Display for LogEntryType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      LogEntryType::Syn => write!(f, "SYN"),
      LogEntryType::Ack => write!(f, "CON")
    }
  }
}
struct LogEntry {
  entrytype: LogEntryType,
  remoteip: String,
  remoteport: u16,
  localport: u16
}

#[derive(Clone)]
struct Port {
  number: u16,
  count: u64
}
impl PartialEq for Port {
  fn eq(&self, other: &Port) -> bool {
    self.number == other.number
  }
}

fn setup() -> App {
  let authorstring: String = str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n");
  println!("Portlurker v{}", VERSION);
  println!("{}", authorstring);
  println!("-----------------------------------------");

  let mut app = App {
    print_ascii: false,
    print_binary: false,
    sql_logging: false,
    file_logging: false,
    nfqueue: None,
    bind_ip: String::new(),
    io_timeout: Duration::new(300, 0),
    regexset: RegexSet::new(&[] as &[&str]).unwrap()
  };

  let mut config_str = String::new();
  let mut file = match File::open("config.yml") {
      Ok(file) => file,
      Err(e) => { println!("Unable to open configuration file: {}", e.to_string()); exit(-1); },
  };

  file.read_to_string(&mut config_str).unwrap();
  let docs = YamlLoader::load_from_str(&config_str).unwrap();
  let config = &docs[0];
  //println!("{:?}", config);
  if config["general"].is_badvalue() {
    println!("No 'general' section found in configuration file");
    exit(-1);
  }
  if config["ports"].is_badvalue() {
    println!("No 'ports' section found in configuration file");
    exit(-1);
  }

  if !config["general"]["bind_ip"].is_badvalue() {
    app.bind_ip = config["general"]["bind_ip"].as_str().expect("Configuration item 'bind_ip' is not valid").to_string();
    println!("Binding to external IP {}", app.bind_ip);
  }
  else { app.bind_ip = String::from("0.0.0.0"); }

  if !config["general"]["print_ascii"].is_badvalue() {
    if config["general"]["print_ascii"].as_bool().unwrap() {
      app.print_ascii = true;
      println!("Printing ASCII");
    }
  }
  if !config["general"]["print_binary"].is_badvalue() {
    if config["general"]["print_binary"].as_bool().unwrap() {
      app.print_binary = true;
      println!("Printing binary in hexadecimal");
    }
  }
  if !config["general"]["file_logging"].is_badvalue() {
    if config["general"]["file_logging"].as_bool().unwrap() {
      app.file_logging = true;
      println!("Logging to local text file");
    }
  }
  if !config["general"]["sql_logging"].is_badvalue() {
    if config["general"]["sql_logging"].as_bool().unwrap() {
      match Connection::open("portlurker.sqlite") {
        Ok(conn) => { app.sql_logging = true;
                      println!("Logging to local SQL database file portlurker.sqlite");
                      conn.execute("CREATE TABLE IF NOT EXISTS connections (
                                    id         INTEGER PRIMARY KEY,
                                    time       INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                                    remoteip   TEXT NOT NULL,
                                    remoteport INTEGER NOT NULL,
                                    localport  INTEGER NOT NULL
                                  )", rusqlite::NO_PARAMS).expect("Failed to create table inside database! SQL logging may not function correctly!"); },
        Err(e) => {
          println!("Enabling SQL logging failed because it was not possible to open or create the database: {}\nContinuing without SQL logging", e.to_string());
        },
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
      None => { println!("Configuration item 'nfqueue' is not a valid integer") }
    };
  }

  return app; // send our config to the main function
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
  if dotline.len() != 0 {
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

fn lurk(app: Arc<RwLock<App>>, socket: TcpListener, logchan: Sender<LogEntry>, banner: Arc<String>) {
  thread::spawn(move || {
    for res in socket.incoming() {
      let mut stream = match res {
        Ok(stream) => stream,
        Err(e) => { println!("{:>5} ? TCP ERR ACCEPT: {}", socket.local_addr().unwrap().port(), e.to_string()); continue; }
      };
      stream.set_read_timeout(Some(app.read().unwrap().io_timeout)).expect("Failed to set read timeout on TcpStream");
      stream.set_write_timeout(Some(app.read().unwrap().io_timeout)).expect("Failed to set write timeout on TcpStream");
      let local = stream.local_addr().unwrap();
      let peer = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => { println!("{:>5} ? TCP ERR GETADDR: {}", socket.local_addr().unwrap().port(), e.to_string()); continue; }
      };

      println!("{:>5} + TCP ACK from {}", local.port(), peer);
      if logchan.send(LogEntry { entrytype: LogEntryType::Ack, remoteip: peer.ip().to_string(), remoteport: peer.port(), localport: local.port() }).is_err() {
        println!("Failed to write LogEntry to logging thread");
      }

      let app = app.clone();
      let banner = banner.clone();
      thread::spawn(move || {
        let start = Instant::now();
        if banner.len() > 0 {
          match stream.write((*banner).as_bytes()) {
            Ok(_) => println!("{:>5} > {}", local.port(), to_dotline((*banner).as_bytes())),
            Err(e) => {
              if e.kind() == io::ErrorKind::WouldBlock { println!("{:>5} - TCP WRITE TIMEOUT from {}", local.port(), peer); }
              else { println!("{:>5} - TCP ERR WRITE to {}: {}", local.port(), peer, e.to_string()); }
              return;
            }
          }
        }
        let mut buf: [u8; 2048] = [0; 2048];
        loop {
          match stream.read(&mut buf) {
            Ok(c) => {
              if c == 0 {                                                            // use Duration::as_float_secs() here as soon as it stabilizes
                println!("{:>5} - TCP FIN from {} after {:.1}s", local.port(), peer, start.elapsed().as_secs() as f32 + start.elapsed().subsec_millis() as f32/1000.0);
                break;
              }
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
                else {
                  if found {
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
                println!("{:>5} ^ Matches pattern {}", local.port(), BINARY_MATCHES[id].0);
              }
            }
            Err(e) => {
              if e.kind() == io::ErrorKind::WouldBlock { println!("{:>5} - TCP READ TIMEOUT from {}", local.port(), peer); }
              else { println!("{:>5} - TCP ERR READ from {}: {}", local.port(), peer, e.to_string()); }
              break;
            }
          }
          match stream.take_error() {
            Ok(opt) => {
              if opt.is_some() {
                println!("{:>5} - TCP ERR from {}: {}", local.port(), peer, opt.unwrap().to_string());
                break;
              }
            }
            Err(_) => {
              println!("This shouldn't happen...");
              break;
            }
          }
        }
      });
    }
  });
}

fn main() {
  let app = Arc::new(RwLock::new(setup())); // Print initial UI stuff, then parse the config file, and store the config

  let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
  for &(_, pattern) in BINARY_MATCHES.iter() {
    patterns.push(pattern);
  }
  app.write().unwrap().regexset = RegexSetBuilder::new(patterns)
    .unicode(false)
    .dot_matches_new_line(false)
    .build().unwrap();

  println!("\nStarting listeners on the following ports:");

  // Have to reload config file here - can we improve this?
  let mut config_str = String::new();
  let mut file = match File::open("config.yml") {
      Ok(file) => file,
      Err(e) => { println!("Unable to open configuration file: {}", e.to_string()); exit(-1); },
  };

  file.read_to_string(&mut config_str).unwrap();
  let docs = YamlLoader::load_from_str(&config_str).unwrap();
  let config = &docs[0];

  let (tx, rx) = channel();
  let mut sql_logging = app.read().unwrap().sql_logging;
  let file_logging = app.read().unwrap().file_logging;
  thread::spawn(move|| { // Logging thread
    let mut counter = 0;
    let mut ports = Vec::with_capacity(65536);
    for number in 0..=65535 { ports.push(Port { number, count: 0 }) };
    let mut prevports: Vec<Port> = Vec::new();

    loop {
      let conn: LogEntry = rx.recv().unwrap();

      if conn.entrytype == LogEntryType::Syn {
        ports[conn.localport as usize].count += 1;
        counter += 1;
        if counter%100 == 0 {
          let mut ports = ports.clone();
          ports.sort_unstable_by_key(|k| -(k.count as i64));
          ports.truncate(10);
          ports.shrink_to_fit();
          println!("----- i Top 10 ports:");
          let mut i = 0;
          for port in &ports {
            i += 1;
            println!("----- i No {:>2}: {:>5} with {:>3} SYNs", i, port.number, port.count);
            if !prevports.is_empty() && !prevports.contains(&port) { println!("----- i  Port {:>5} newly entered the top 10", port.number); }
          }
          prevports = ports;
        }
      }

      if file_logging {
        let current_time = Local::now();
        let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
        let log_msg = format!("[{}]: {} TCP {} from {}:{}", formatted_time, conn.entrytype, conn.localport, conn.remoteip, conn.remoteport);
        let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("portlurker.log").expect("Failed to open local log file for writing");
        writeln!(file, "{}", log_msg).unwrap();
      }
      if sql_logging && (conn.entrytype == LogEntryType::Ack) {
        match Connection::open("portlurker.sqlite") {
          Ok(dbh) => { dbh.execute("INSERT INTO connections (
                          remoteip, remoteport, localport) VALUES (
                          ?1, ?2, ?3)", &[&conn.remoteip as &dyn ToSql, &conn.remoteport, &conn.localport]
                        ).expect("Can't write new row into table! Subsequent logging may also fail.");},
          Err(e) => {
            println!("Failed to open database: {} - Continuing without logging", e.to_string());
            sql_logging = false;
          }
        }
      }
    }
  });

  let mut tcp_ports: Vec<u16> = vec![];
  let mut transparent: bool = false;
  for port in config["ports"].as_vec().unwrap() {
    if !port["tcp"].is_badvalue() {
      let portno = port["tcp"].as_i64().unwrap();
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
      match TcpListener::bind((bind_ip.as_str(), portno as u16)) {
          Ok(socket) => {
              if !port["transparent"].is_badvalue() {
                  transparent = true;
                  println!("  transparent mode: true");
                  let fd = socket.as_raw_fd();
                  let res = setsockopt(fd, IpTransparent, &true);
                  res.expect("ERROR setting sockopt IP_TRANSPARENT on PROXY socket; are you running as root?");
              }
              lurk(app, socket, logchan, banner)
          },
        Err(e) => { println!("ERROR binding to {}: {}", portno, e.to_string()) }
      };
    }
    else if !port["udp"].is_badvalue() {
      println!("UDP port {}", port["udp"].as_i64().unwrap());
    }
    else {
      println!("Invalid port specification in configuration file");
    }
  }

  let nfqueue = app.read().unwrap().nfqueue;
  if let Some(qid) = nfqueue {
    let logchan = tx.clone();
    let mut state = State::new(logchan, transparent);
    state.ports = tcp_ports.clone();
    let mut q = nfqueue::Queue::new(state);
    q.open();
    q.unbind(libc::AF_INET);

    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.create_queue(qid, nfq_callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0x00df); // 64 bits should be sufficient to look at the TCP header

    q.run_loop(); // Infinite loop
    q.close();
  }
  else {
    loop { thread::sleep(Duration::new(60, 0)); } // Nothing to do in the main thread
  }
}

fn nfq_callback(msg: &nfqueue::Message, state: &mut State) {
   let header = Ipv4Packet::new(msg.get_payload());
   match header {
     Some(h) => match h.get_next_level_protocol() {
       IpNextHeaderProtocols::Tcp => match TcpPacket::new(h.payload()) {
         Some(p) => {
           let remoteip = IpAddr::V4(h.get_source());
           if !state.ports.contains(&p.get_destination()) { println!("{:>5} = TCP SYN from {}:{} (unmonitored)", p.get_destination(), remoteip, p.get_source()); }
           else { println!("{:>5} = TCP SYN from {}:{}", p.get_destination(), remoteip, p.get_source()); }
           let _ = state.logchan.send(LogEntry { entrytype: LogEntryType::Syn, remoteip: remoteip.to_string(), remoteport: p.get_source(), localport: p.get_destination() });
         },
         None => println!("Received malformed TCP packet")
       },
       _ => println!("Received a non-TCP packet")
     },
     None => println!("Received malformed IPv4 packet")
   }

   msg.set_verdict(nfqueue::Verdict::Accept);
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
