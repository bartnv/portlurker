# portlurker
Port listener / honeypot in Rust with protocol guessing, safe string display and rudimentary SQLite logging

## Installation
To start, first install the latest stable version of rustc & Cargo by following the instructions at: https://www.rustup.rs/

For SQLite logging support you will need to run 'sudo apt-get install libsqlite3-dev' - this is compulsory right now (sorry!) but is disabled by default.

You'll also need to rename the config file to remove the -default suffix. This was done to prevent overwriting of config files when upgrading.

Running `cargo build` will build the project and `cargo run` will run it - you may need to execute these commands as root for reasons of file permissions and to enable access to lower ports.

## Configuration
Configuration is done in the config.yml file, which as the extension hints at is a YAML-formatted file. It should have two top-level keys called "general" and "ports".

The general section has subkeys for the different options you can set in the file. Currently these are:
 - print_ascii (boolean): show printable ascii found in the received data
 - print_binary (boolean): show all received data as a series of integer byte values
 - sql_logging (boolean): enable logging to an sqlite3 database file (portlurker.sqlite) - Fields available right now are: id, time (since UNIX epoch), remoteip, remoteport & localport. Connections are logged, but not disconnections.
 - file_logging (boolean): enable logging to a local text file (portlurker.log). As with SQL logging only connections are logged, not disconnections.
 - bind_ip (ip-address): configure the ip-address to bind the listening ports to; without this portlurker will bind to all available interfaces.
 - nfqueue (integer): the nfqueue number to listen on to register SYN packets to unmonitored ports; see the Advanced section below.

The ports section contains a list of listening-port specifications. Each item in the list is itself a key-value collection. At a minimum it should have either a "tcp" key (integer) or a "udp" key (integer). Additional keys can be:
 - banner (string): send this string to each new connection on the port (often you'll need to send carriage-return and linefeed after this string; you can do that in YAML by enclosing the string in double quotes and adding \r\n at the end)

A very basic config might look like this:
```
general:
 print_ascii: true
 print_binary: false
 sql_logging: true
 file_logging: false
ports:
 - tcp: 22
   banner: "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3\r\n"
 - tcp: 80
 - tcp: 2443
 - udp: 53
```

## Advanced
It's possible to use iptables to send a copy of each SYN packet to portlurker, to register which unmonitored ports are seeing connection attempts. For this you need to add an iptables rule such as the one below *before* any reject rules.
```
iptables -A INPUT -p tcp -m tcp ! --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j NFQUEUE --queue-num 0 --queue-bypass
```
I've exempted the SSH port here to prevent you from locking yourself out of the system. This is prudent because in principle this rule requires portlurker to be running at all times. The '--queue-bypass' option is also a safeguard,
but I think it only kicks in once the queue is full.
