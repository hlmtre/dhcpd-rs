mod options;

use crate::options::DhcpMessage;
use std::net::Ipv4Addr;
use std::{env, net::UdpSocket};

fn main() -> std::io::Result<()> {
  let mut listening_address = "0.0.0.0:67";
  let mut debug = false;
  let mut dhcp_range: Vec<Ipv4Addr> = Vec::new();
  let mut dns_servers: Vec<Ipv4Addr> = Vec::new();
  let mut domain = String::new();
  let mut lease_time = String::new();

  let args: Vec<String> = env::args().collect();
  let mut counter: usize = 0;
  for e in &args {
    match e.as_str() {
      "--address" | "-a" => {
        listening_address = args[counter + 1].as_str();
      }
      "--debug" | "-d" => {
        debug = true;
      }
      "--help" | "-h" => {
        help();
      }
      "--range" | "-r" => {
        let l: Vec<&str> = args[counter + 1].split(",").collect();
        for x in l {
          if x.len() > 0 {
            dhcp_range.push(match x.parse() {
              Ok(a) => a,
              _ => {
                error("IP range parse error!");
                break;
              }
            });
          }
        }
      }
      "--dns" => {
        let l: Vec<&str> = args[counter + 1].split(",").collect();
        for x in l {
          if x.len() > 0 {
            dns_servers.push(match x.parse() {
              Ok(a) => a,
              _ => {
                error("DNS servers parse error!");
                break;
              }
            });
          }
        }
      }
      _ => {}
    }
    counter += 1;
  }
  if debug {
    eprintln!(
      "listen: {:?} debug: {:?} dhcp_range: {:?} dns_servers: {:?} domain: {:?} lease: {:?}",
      listening_address, debug, dhcp_range, dns_servers, domain, lease_time
    );
  }
  let socket = UdpSocket::bind(listening_address)?;
  socket.set_nonblocking(true).unwrap();
  let _ = socket.set_broadcast(true);
  if debug {
    println!("listening on {}", listening_address);
  }
  /*
  The 'options' field is now variable length. A DHCP client must be
  prepared to receive DHCP messages with an 'options' field of at least
  length 312 octets.  This requirement implies that a DHCP client must
  be prepared to receive a message of up to 576 octets, the minimum IP
  datagram size an IP host must be prepared to accept [3].  DHCP
  clients may negotiate the use of larger DHCP messages through the
  'maximum DHCP message size' option.  The options field may be further
  extended into the 'file' and 'sname' fields.

  creates an array of length 64 u8s and pre-sets each to 0
  */
  //this is equivalent to vec![0, 576];
  let mut buf = [0 as u8; 576];
  loop {
    match socket.recv_from(&mut buf) {
      Ok((l, _n)) => {
        let mut d: DhcpMessage = DhcpMessage::default();
        let filled_buf: &mut [u8] = &mut buf[..l];
        println!("received bytes {:02x?}", filled_buf);
        d.parse(filled_buf);
        println!("from {} ", d.format_mac());
        println!("DhcpMessage: {:02x?}", d);
        println!("would respond on {}", _n);
      }
      Err(_) => {}
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
  }
  Ok(())
}

fn error(e: &str) {
  eprintln!("{}", e);
  std::process::exit(1);
}

fn help() {
  let help_string = r#"
  usage: dhcpd-rs <flags>
  -h, --help : this help message
  --address : <address> (address to bind to).
  --debug : debug (don't background, prints debugging output).
  --range : range to assign to clients (<192.168.5.50, 192.168.5.150>, for example).
  --dns : dns servers to advertise (<192.168.5.4, 192.168.5.5>, for example).
  --domain : domain to advertise (for clients to append to otherwise-unqualified dns queries)
  --leasetime : lease time to advertise. specify in hours (12h, 24h, 72h, etc).
"#;
  println!("{}", help_string);
  std::process::exit(0);
}
