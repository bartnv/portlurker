extern crate yaml_rust;
extern crate regex;
extern crate rusqlite;
extern crate chrono;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::net::TcpListener;
use std::time::Duration;
use std::sync::Arc;
use std::thread;
use std::process::exit;
use yaml_rust::YamlLoader;
use regex::bytes::RegexSetBuilder;
use rusqlite::Connection;
use chrono::Local;

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

#[derive(Copy, Clone)]
struct App {
  print_ascii: bool,
  print_binary: bool,
  sql_logging: bool,
  file_logging: bool
}

#[derive(Debug)]
struct LoggedConnection {
  remoteip: String,
  remoteport: u16,
  localport: i64
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

fn setup() -> App {
  let authorstring: String = str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n");
  println!("Portlurker v{}", VERSION);
  println!("{}", authorstring);
  println!("-----------------------------------------");

  let mut app = App { print_ascii: false, print_binary: false, sql_logging: false, file_logging: false };

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
      println!("Logging events to portlurker.sqlite");
      match Connection::open("portlurker.sqlite") {
        Ok(conn) => { app.sql_logging = true;
                      println!("Logging to local SQL database file");
                      conn.execute("CREATE TABLE IF NOT EXISTS connections (
                                    id         INTEGER PRIMARY KEY,
                                    time       INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                                    remoteip   TEXT NOT NULL,
                                    remoteport INTEGER NOT NULL,
                                    localport  INTEGER NOT NULL
                                  )", &[]).expect("Failed to create table inside database! Logging may not function correctly!"); },
        Err(e) => {
          println!("Failed to open or create database: {}\nContinuing without logging", e.to_string());
        },
      };
    }
  }
  return app; // send our config to the main function
}

fn main() {
  let app: App = setup(); // Print initial UI stuff, then parse the config file, and store the config
  let io_timeout = Duration::new(300, 0); // 5 minutes

  let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
  for &(_, pattern) in BINARY_MATCHES.into_iter() {
    patterns.push(pattern);
  }
  let regexset = RegexSetBuilder::new(patterns)
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
  for port in config["ports"].as_vec().unwrap() {
    if !port["tcp"].is_badvalue() {
      let portno = port["tcp"].as_i64().unwrap();
      println!("TCP port {}", portno);
      let mut banner = Arc::new(String::new());
      if let Some(x) = port["banner"].as_str() {
        Arc::get_mut(& mut banner).unwrap().push_str(x);
        println!("  with banner: {}", *banner);
      }
      let regexset = regexset.clone();
      thread::spawn(move || {
        let server = TcpListener::bind(("0.0.0.0", portno as u16)).expect("Port can't be bound (is it in use?)"); // Add more error checking here
        for res in server.incoming() {
          let mut stream = match res {
            Ok(stream) => stream,
            Err(e) => { println!("ACCEPT ERROR TCP {}: {}", portno, e.to_string()); continue; }
          };
          stream.set_read_timeout(Some(io_timeout)).expect("Failed to set read timeout on TcpStream");
          stream.set_write_timeout(Some(io_timeout)).expect("Failed to set write timeout on TcpStream");
          let addr = stream.peer_addr().unwrap();

          let current_time = Local::now();
          let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));

          let log_msg = format!("[{}]: CONNECT TCP {} from {}", formatted_time, portno, addr);
          println!("{}", log_msg);
          if app.file_logging {
            log_to_file(log_msg.to_string());
          }
          if app.sql_logging {
            let newdbentry = LoggedConnection {
              remoteip: addr.ip().to_string(),
              remoteport: addr.port(),
              localport: portno
            };
            match Connection::open("portlurker.sqlite") {
              Ok(conn) => { conn.execute("INSERT INTO connections (
                              remoteip, remoteport, localport) VALUES (
                              ?1, ?2, ?3)", &[&newdbentry.remoteip, &newdbentry.remoteport, &newdbentry.localport]
                            ).expect("Can't write new row into table! Subsequent logging may also fail.");},
              Err(e) => {
                println!("Failed to open database: {} - Continuing without logging", e.to_string());
                let mut app = app;
                app.sql_logging = false;
              },
            }
          }

          let regexset = regexset.clone();
          let banner = banner.clone();
          thread::spawn(move || {
            if banner.len() > 0 {
              match stream.write((*banner).as_bytes()) {
                Ok(_) => {
                  for line in (*banner).lines() {
                    println!("> {}", line);
                  }
                }
                Err(e) => {
                  if e.kind() == io::ErrorKind::WouldBlock { println!("WRITE TIMEOUT TCP {} from {}", portno, addr); }
                  else { println!("WRITE ERROR TCP {} from {}: {}", portno, addr, e.to_string()); }
                  return;
                }
              }
            }
            let mut buf: [u8; 2048] = [0; 2048];
            loop {
              match stream.read(&mut buf) {
                Ok(c) => {
                  if c == 0 {
                    println!("CLOSE TCP {} from {}", portno, addr);
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
                    if app.print_ascii {
                      let data = String::from_utf8_lossy(printables[0]);
                      for line in data.lines() {
                        println!("| {}", line);
                      }
                    }
                    else { println!("! Read {} bytes of printable ASCII", c); }
                  }
                  else {
                    println!("! Read {} bytes of binary", c);
                    for id in regexset.matches(&buf[..c]).into_iter() {
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
                    if app.print_binary {
                      let hex = to_hex(&buf[..c]);
                      for line in hex.lines() { println!(". {}", line); }
                    }
                  }
                }
                Err(e) => {
                  if e.kind() == io::ErrorKind::WouldBlock { println!("READ TIMEOUT TCP {} from {}", portno, addr); }
                  else { println!("READ ERROR TCP {} from {}: {}", portno, addr, e.to_string()); }
                  break;
                }
              }
              match stream.take_error() {
                Ok(opt) => {
                  if opt.is_some() {
                    println!("ERROR TCP {} from {}: {}", portno, addr, opt.unwrap().to_string());
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
    else if !port["udp"].is_badvalue() {
      println!("UDP port {}", port["udp"].as_i64().unwrap());
    }
    else {
      println!("Invalid port specification in configuration file");
    }
  }

  loop { thread::sleep(Duration::new(60, 0)); }
}
