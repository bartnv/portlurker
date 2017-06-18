extern crate yaml_rust;
extern crate regex;

use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::net::TcpListener;
use std::time::Duration;
use std::sync::Arc;
use std::thread;
use std::process::exit;
use yaml_rust::YamlLoader;
use regex::bytes::RegexSetBuilder;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHORS: &'static str = env!("CARGO_PKG_AUTHORS");

#[derive(Copy, Clone)]
struct App {
  print_ascii: bool,
  print_binary: bool
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
  if dotline.len() != 0 { result.push_str(&dotline); }
  result
}

fn main() {
  println!("Portlurker v{}", VERSION);
  println!("{}", AUTHORS);
  println!("-----------------------------------------");
  
  let mut app = App { print_ascii: false, print_binary: false };
  let binary_matches = [
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
    ("SOCKS5 NOAUTH Request", r"^\x05\x01\x00$"),
    ("SOCKS5 NOAUTH,USER/PASS Request", r"^\x05\x02\x00\x02$")
  ];
  let io_timeout = Duration::new(300, 0); // 5 minutes

  let mut file = File::open("config.yml").unwrap();
  let mut config_str = String::new();
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
  let app = app; // Revert to immutable

  let mut patterns = Vec::with_capacity(binary_matches.len());
  for &(_, pattern) in binary_matches.into_iter() {
    patterns.push(pattern);
  }
  let regexset = RegexSetBuilder::new(patterns)
    .unicode(false)
    .dot_matches_new_line(false)
    .build().unwrap();

  println!("\nStarting listeners on the following ports:");
  
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
        let server = TcpListener::bind(("0.0.0.0", portno as u16)).unwrap();
        for res in server.incoming() {
          let mut stream = match res {
            Ok(stream) => stream,
            Err(e) => { println!("ACCEPT ERROR TCP {}: {}", portno, e.to_string()); continue; }
          };
          stream.set_read_timeout(Some(io_timeout)).expect("Failed to set read timeout on TcpStream");
          stream.set_write_timeout(Some(io_timeout)).expect("Failed to set write timeout on TcpStream");
          let addr = stream.peer_addr().unwrap();
          println!("CONNECT TCP {} from {}", portno, addr);
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
                        if (i-start == 1) {
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
                      println!("^ Matches pattern {}", binary_matches[id].0);
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
