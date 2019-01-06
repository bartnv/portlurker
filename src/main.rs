extern crate yaml_rust;
extern crate regex;
extern crate rusqlite;
extern crate chrono;
extern crate libc;
extern crate nfqueue;
extern crate pnet;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::net::{TcpListener, IpAddr};
use std::time::Duration;
use std::sync::{Arc, RwLock};
use std::thread;
use std::process::exit;
use yaml_rust::YamlLoader;
use regex::bytes::{RegexSet, RegexSetBuilder};
use rusqlite::Connection;
use rusqlite::types::ToSql;
use chrono::Local;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const BINARY_MATCHES: [(&str, &str);24] = [ // Global array, so needs an explicit length
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
  ("Bitcoin main chain magic number", r"\xf9\xbe\xb4\xd9")
];

#[derive(Clone)]
struct App {
  print_ascii: bool,
  print_binary: bool,
  sql_logging: bool,
  file_logging: bool,
  io_timeout: Duration,
  regexset: RegexSet
}

#[derive(Debug)]
struct LoggedConnection {
  remoteip: String,
  remoteport: u16,
  localport: i64
}

fn setup() -> App {
  let authorstring: String = str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n");
  println!("Portlurker v{}", VERSION);
  println!("{}", authorstring);
  println!("-----------------------------------------");

  let mut app = App { print_ascii: false, print_binary: false, sql_logging: false, file_logging: false, io_timeout: Duration::new(300, 0), regexset: RegexSet::new(&[] as &[&str]).unwrap() };

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
                                  )", rusqlite::NO_PARAMS).expect("Failed to create table inside database! Logging may not function correctly!"); },
        Err(e) => {
          println!("Enabling SQL logging failed because it was not possible to open or create the database: {}\nContinuing without SQL logging", e.to_string());
        },
      };
    }
  }
  return app; // send our config to the main function
}

fn log_to_file(msg: String) {
  let mut file = OpenOptions::new()
              .append(true)
              .create(true)
              .open("portlurker.log").expect("Failed to open local log file for writing");;
  writeln!(file, "{}", msg).unwrap();

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

fn lurk(app: Arc<RwLock<App>>, socket: TcpListener, banner: Arc<String>) {
  thread::spawn(move || {
    for res in socket.incoming() {
      let mut stream = match res {
        Ok(stream) => stream,
        Err(e) => { println!("ACCEPT ERROR TCP {}: {}", socket.local_addr().unwrap().port(), e.to_string()); continue; }
      };
      stream.set_read_timeout(Some(app.read().unwrap().io_timeout)).expect("Failed to set read timeout on TcpStream");
      stream.set_write_timeout(Some(app.read().unwrap().io_timeout)).expect("Failed to set write timeout on TcpStream");
      let local = stream.local_addr().unwrap();
      let peer = stream.peer_addr().unwrap();

      let current_time = Local::now();
      let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));

      let log_msg = format!("[{}]: CONNECT TCP {} from {}", formatted_time, local.port(), peer);
      println!("{}", log_msg);
      if app.read().unwrap().file_logging {
        log_to_file(log_msg.to_string());
      }
      if app.read().unwrap().sql_logging {
        let newdbentry = LoggedConnection {
          remoteip: peer.ip().to_string(),
          remoteport: peer.port(),
          localport: local.port() as i64
        };
        match Connection::open("portlurker.sqlite") {
          Ok(conn) => { conn.execute("INSERT INTO connections (
                          remoteip, remoteport, localport) VALUES (
                          ?1, ?2, ?3)", &[&newdbentry.remoteip as &ToSql, &newdbentry.remoteport, &newdbentry.localport]
                        ).expect("Can't write new row into table! Subsequent logging may also fail.");},
          Err(e) => {
            println!("Failed to open database: {} - Continuing without logging", e.to_string());
            app.write().unwrap().sql_logging = false;
          },
        }
      }

      let app = app.clone();
      let banner = banner.clone();
      thread::spawn(move || {
        if banner.len() > 0 {
          match stream.write((*banner).as_bytes()) {
            Ok(_) => println!("> {}", to_dotline((*banner).as_bytes())),
            Err(e) => {
              if e.kind() == io::ErrorKind::WouldBlock { println!("WRITE TIMEOUT TCP {} from {}", local.port(), peer); }
              else { println!("WRITE ERROR TCP {} from {}: {}", local.port(), peer, e.to_string()); }
              return;
            }
          }
        }
        let mut buf: [u8; 2048] = [0; 2048];
        loop {
          match stream.read(&mut buf) {
            Ok(c) => {
              if c == 0 {
                println!("CLOSE TCP {} from {}", local.port(), peer);
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
                    println!("| {}", line);
                  }
                }
                else { println!("! Read {} bytes of printable ASCII", c); }
              }
              else {
                println!("! Read {} bytes of binary", c);
                for id in app.read().unwrap().regexset.matches(&buf[..c]).into_iter() {
                  println!("^ Matches pattern {}", BINARY_MATCHES[id].0);
                }
                for printable in printables {
                  if printable.len() > 3 {
                    let data = String::from_utf8_lossy(printable);
                    for line in data.lines() {
                      println!("$ {}", line);
                    }
                  }
                }
                for line in mbstring.lines() {
                  if line.len() > 3 { println!("% {}", line); }
                }
                if app.read().unwrap().print_binary {
                  let hex = to_hex(&buf[..c]);
                  for line in hex.lines() { println!(". {}", line); }
                }
              }
            }
            Err(e) => {
              if e.kind() == io::ErrorKind::WouldBlock { println!("READ TIMEOUT TCP {} from {}", local.port(), peer); }
              else { println!("READ ERROR TCP {} from {}: {}", local.port(), peer, e.to_string()); }
              break;
            }
          }
          match stream.take_error() {
            Ok(opt) => {
              if opt.is_some() {
                println!("ERROR TCP {} from {}: {}", local.port(), peer, opt.unwrap().to_string());
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
  let bind_ip;

  let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
  for &(_, pattern) in BINARY_MATCHES.into_iter() {
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

  if !config["general"]["bind_ip"].is_badvalue() {
    bind_ip = config["general"]["bind_ip"].as_str().expect("Configuration item 'bind_ip' is not valid").to_string();
    println!("Binding to external IP {}", bind_ip);
  }
  else { bind_ip = String::from("0.0.0.0"); }

  let mut tcp_ports: Vec<u16> = vec![];
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
      let bind_ip = bind_ip.clone();
      match TcpListener::bind((bind_ip.as_str(), portno as u16)) {
        Ok(socket) => lurk(app, socket, banner),
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

  let mut state = State::new();
  state.ports = tcp_ports.clone();
  let mut q = nfqueue::Queue::new(state);
  q.open();
  q.unbind(libc::AF_INET);

  let rc = q.bind(libc::AF_INET);
  assert!(rc == 0);

  q.create_queue(0, nfq_callback);
  q.set_mode(nfqueue::CopyMode::CopyPacket, 0x00df); // 64 bits should be sufficient to look at the TCP header

  q.run_loop(); // Infinite loop
  q.close();
}

fn nfq_callback(msg: &nfqueue::Message, state: &mut State) {
   let header = Ipv4Packet::new(msg.get_payload());
   match header {
     Some(h) => match h.get_next_level_protocol() {
       IpNextHeaderProtocols::Tcp => match TcpPacket::new(h.payload()) {
         Some(p) => {
           if !state.ports.contains(&p.get_destination()) { println!("TCP SYN from {} to unmonitored port {}", IpAddr::V4(h.get_source()), p.get_destination()) }
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
    ports: Vec<u16>
}
impl State {
    pub fn new() -> State {
        State { ports: vec![] }
    }
}
