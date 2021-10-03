#![allow(clippy::many_single_char_names)]

use pool::Pool;
use socket2::{Domain, Protocol, Socket, Type};

mod config;
mod dhcpmessage;
mod options;
#[path = "ping/lib.rs"]
mod ping;
mod pool;

use crate::{
  config::Config,
  dhcpmessage::{DhcpMessage, DhcpOption},
  options::SERVER_IDENTIFIER,
};

use std::{
  env,
  ffi::CString,
  net::{IpAddr, Ipv4Addr, SocketAddrV4},
};

fn main() -> Result<(), ArgumentError> {
  let c: Config = parse_args(env::args().collect())?;
  if c.debug {
    eprintln!("==> {:?}", c);
  }

  let mut p = Pool::new(
    c.dhcp_range.first().unwrap().to_owned(),
    c.dhcp_range.last().unwrap().to_owned(),
  );
  let socket = match Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())) {
    Ok(a) => a,
    _ => panic!("couldn't create socket :("),
  };
  if !c.interface.clone().is_empty() {
    socket
      .bind_device(Some(&CString::new(c.interface.clone()).unwrap()))
      .unwrap_or_else(|_| panic!("couldn't bind to {}", c.interface));
  }
  socket
    .bind(&c.listening_address.into())
    .unwrap_or_else(|_| panic!("couldn't bind to {}", c.listening_address));
  socket.set_broadcast(true).expect("couldn't broadcast! :(");
  if c.debug {
    if !c.interface.is_empty() {
      println!("==> bound to {} on {:?}", c.bind_address, socket.device());
    } else {
      println!("==> bound to {}", c.bind_address);
    }
    println!("==> listening on {}", c.listening_address);
  }
  /*
  reachable(
    &c.interface,
    &c.listening_address,
    "192.168.122.1".parse::<Ipv4Addr>().unwrap(),
  );
  */
  /*
  The 'options' field is now variable length. A DHCP client must be
  prepared to receive DHCP messages with an 'options' field of at least
  length 312 octets.  This requirement implies that a DHCP client must
  be prepared to receive a message of up to 576 octets, the minimum IP
  datagram size an IP host must be prepared to accept [3].  DHCP
  clients may negotiate the use of larger DHCP messages through the
  'maximum DHCP message size' option.  The options field may be further
  extended into the 'file' and 'sname' fields.

  creates an array of length 576 u8s and pre-sets each to 0
  this is equivalent to vec![0, 576];
  */
  let mut buf = [0_u8; 576];
  loop {
    if let Ok((l, _n)) = socket.recv_from(&mut buf) {
      let mut d: DhcpMessage = DhcpMessage::default();
      let filled_buf: &mut [u8] = &mut buf[..l];
      d.parse(filled_buf);
      // if the dest address is us or broadcast
      let _f = d.options.get(&SERVER_IDENTIFIER);
      match _f {
        Some(_g) => match _g {
          DhcpOption::ServerIdentifier(a) => {
            println!("server identifier: {:?}", _g);
            if IpAddr::V4(a.clone()) != c.bind_address.ip() && !a.is_broadcast() {
              println!("{} != {}", c.bind_address.ip(), a);
              continue;
            }
          }
          _ => {
            println!("default: {:?}", _g);
          }
        },
        None => {
          println!(
            "no server identifier. peer address: {:?}",
            socket.peer_addr()
          );
        }
      }
      let x = d.construct_response(&c, &mut p);
      //let u = UdpSocket::bind(c.bind_address)?;
      let source = Ipv4Addr::from(d.ciaddr);
      // if the client specifies an IP (renewing), unicast to that
      // otherwise we have to broadcast (DHCPDISCOVER, DHCPREQUEST)
      let target = if !source.is_unspecified() {
        source
      } else {
        Ipv4Addr::BROADCAST
      };
      // we've already set_broadcast, so that's fine
      // but we gotta also allow reuse of the port
      let _ = socket.set_reuse_port(true);
      //let _ = socket.set_reuse_address(true);
      let n = socket.send_to(&x, &SocketAddrV4::new(target, 68).into());
      match n {
        Ok(_) => {}
        Err(e) => {
          println!("error sending on socket {:?}. error: {}", socket, e);
        }
      }
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
  }
  #[allow(unreachable_code)]
  Ok(())
}

fn error(e: &str) {
  eprintln!("{}", e);
}

#[derive(Debug, Clone, Default)]
struct ArgumentError {
  pub errors: Vec<String>,
}

impl From<std::io::Error> for ArgumentError {
  fn from(error: std::io::Error) -> Self {
    ArgumentError {
      errors: vec![error.to_string()],
    }
  }
}

fn parse_args(args: Vec<String>) -> Result<Config, ArgumentError> {
  let mut c = Config::new();
  let mut ae = ArgumentError::default();
  // so we can get the next arg AFTER our flag
  if args.len() < 2 {
    help();
    std::process::exit(1);
  }
  for (counter, e) in args.iter().enumerate() {
    match e.as_str() {
      "--address" | "-a" => {
        c.bind_address.set_ip(std::net::IpAddr::V4(
          match args[counter + 1].as_str().parse::<Ipv4Addr>() {
            Ok(a) => a,
            Err(e) => {
              ae.errors.push(e.to_string());
              "0.0.0.0".parse::<Ipv4Addr>().unwrap()
            }
          },
        ));
      }
      "--interface" | "-i" => {
        c.interface = args[counter + 1].clone();
      }
      "--debug" | "-d" => {
        c.debug = true;
      }
      "--help" | "-h" => {
        help();
      }
      "--domain" => {
        c.domain = args[counter + 1].clone();
      }
      "--leasetime" | "--lease" => {
        c.set_lease(args[counter + 1].clone());
      }
      "--range" | "-r" => {
        let l: Vec<&str> = args[counter + 1].split(',').collect();
        for x in l {
          if !x.is_empty() {
            c.dhcp_range.push(match x.parse::<Ipv4Addr>() {
              Ok(a) => a,
              Err(e) => {
                ae.errors.push(e.to_string());
                error("IP range parse error!");
                "0.0.0.0".parse::<Ipv4Addr>().unwrap()
              }
            });
          }
        }
      }
      "--routers" | "--router" => {
        let l: Vec<&str> = args[counter + 1].split(',').collect();
        for x in l {
          if !x.is_empty() {
            c.routers.push(match x.parse::<Ipv4Addr>() {
              Ok(a) => a,
              Err(e) => {
                ae.errors.push(e.to_string());
                error("router parse error!");
                "0.0.0.0".parse::<Ipv4Addr>().unwrap()
              }
            });
          }
        }
      }
      "--dns" => {
        let l: Vec<&str> = args[counter + 1].split(',').collect();
        for x in l {
          if !x.is_empty() {
            c.dns_servers.push(match x.parse::<Ipv4Addr>() {
              Ok(a) => a,
              Err(e) => {
                ae.errors.push(e.to_string());
                error("DNS servers parse error!");
                "0.0.0.0".parse::<Ipv4Addr>().unwrap()
              }
            });
          }
        }
      }
      _ => {}
    }
    //counter += 1;
  }
  if !ae.errors.is_empty() {
    return Err(ae); // i still think explicit is clearer
  }
  Ok(c)
}

fn help() {
  let help_string = r#"
  [usage]
    dhcpd-rs <flags>

  [remarks]
    Flags can appear in any order, but MUST be space delimited. Range and DNS servers MUST NOT
    have spaces between them.

  [flags]
    -h, --help : this help message
    --address : <address> (address to bind to).
    --debug : debug (don't background, prints debugging output).
    --dns : dns servers to advertise (<192.168.5.4,192.168.5.5>, for example). NO SPACES.
    --domain : domain to advertise (for clients to append to otherwise-unqualified dns queries).
    --leasetime : lease time to advertise. specify in hours (12h, 24h, 72h, etc).
    --interface : interface to bind to. if unspecified, binds to all interfaces.
    --subnet : subnet mask to give to clients (255.255.255.0, for example).
    --routers : routers to give to clients (in order of preference; <192.168.122.1,192.168.6.1>, for example). NO SPACES.
    --range : range to assign to clients (<192.168.5.50,192.168.5.150>, for example). NO SPACES.
"#;
  println!("{}", help_string);
  std::process::exit(0);
}
