extern crate yaml_rust;
extern crate regex;

use std::fs::File;
use std::io::prelude::*;
use std::net::TcpListener;
use std::time::Duration;
use std::sync::Arc;
use std::thread;
use std::process::exit;
use yaml_rust::YamlLoader;
use regex::bytes::RegexSetBuilder;

#[derive(Copy, Clone)]
struct App {
  print_ascii: bool,
  print_binary: bool
}

fn main() {
  let mut app = App { print_ascii: false, print_binary: false };
  let binary_matches = [
    ("SSL3.0 Record Protocol", r"^\x16\x03\x00..\x01"),
    ("TLS1.0 Record Protocol", r"^\x16\x03\x01..\x01"),
    ("TLS1.1 Record Protocol", r"^\x16\x03\x02..\x01"),
    ("TLS1.2 Record Protocol", r"^\x16\x03\x03..\x01"),
    ("SSL3.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x00"),
    ("TLS1.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x01"),
    ("TLS1.1 CLIENT_HELLO", r"^\x16....\x01...\x03\x02"),
    ("TLS1.2 CLIENT_HELLO", r"^\x16....\x01...\x03\x03")
  ];

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
      println!("Printing ascii");
    }
  }
  if !config["general"]["print_binary"].is_badvalue() {
    if config["general"]["print_binary"].as_bool().unwrap() {
      app.print_binary = true;
      println!("Printing binary");
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
          let mut stream = res.unwrap();
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
                  println!("WRITE ERROR TCP {} from {}: {}", portno, addr, e.to_string());
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
                  let mut start = 0;
                  for i in 0..buf.len() {
                    if (buf[i] > 31 && buf[i] < 127) || buf[i] == 10 || buf[i] == 13 {
                      if !found {
                        start = i;
                        found = true;
                      }
                    }
                    else {
                      if found {
                        printables.push(&buf[start..i]);
                        found = false;
                      }
                    }
                  }
                  if printables.len() == 1 && printables[0].len() == c {
                    if app.print_ascii {
                      let data = String::from_utf8_lossy(printables[0]);
                      for line in data.lines() {
                        println!("| {}", line);
                      }
                    }
                    else { println!("! Read {} bytes of printable ascii", c); }
                    if app.print_binary { println!("! {:?}", &buf[..c]); }
                  }
                  else {
                    println!("! Read {} bytes of binary", c);
                    if app.print_binary { println!("! {:?}", &buf[..c]); }
                    for id in regexset.matches(&buf[..c]).into_iter() {
                      println!("! Matches pattern {}", binary_matches[id].0);
                    }
                    for printable in printables {
                      if printable.len() > 3 {
                        let data = String::from_utf8_lossy(printable);
                        for line in data.lines() {
                          println!("$ {}", line);
                        }
                      }
                    }
                  }
                }
                Err(e) => {
                  println!("READ ERROR TCP {} from {}: {}", portno, addr, e.to_string());
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
