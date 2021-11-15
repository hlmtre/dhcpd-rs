use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug)]
pub(crate) struct Config {
  /*
  let listening_address = "0.0.0.0:67";
  let mut bind_address: SocketAddr = "0.0.0.0:68".parse::<SocketAddr>().unwrap();
  let mut debug = false;
  let mut dhcp_range: Vec<Ipv4Addr> = Vec::new();
  let mut dns_servers: Vec<Ipv4Addr> = Vec::new();
  let mut domain = String::new();
  let mut lease_time = String::new();
  */
  pub debug: bool,
  pub listening_address: SocketAddr,
  pub interface: String,
  pub bind_address: SocketAddr,
  pub routers: Vec<Ipv4Addr>,
  pub subnet: Ipv4Addr,
  pub dhcp_range: Vec<Ipv4Addr>,
  pub dns_servers: Vec<Ipv4Addr>,
  pub domain: String,
  pub lease_time: u32,
}

fn lease_to_seconds(s: &str) -> u32 {
  let mut digits = String::new();
  for c in s.chars() {
    if c.is_digit(10) {
      digits.push(c);
    }
  }
  let units_as_int = digits.parse::<u32>().unwrap_or(12);
  // get the last char to check our units
  match s.chars().last() {
    Some(c) => match c {
      'h' => {
        return 60 * 60 * units_as_int;
      }
      'm' => {
        return 60 * units_as_int;
      }
      _ => {
        return units_as_int;
      }
    },
    None => {
      // let's just default to 12h (in seconds, durr)
      return 28800;
    }
  }
}

impl Config {
  pub(crate) fn new() -> Config {
    Config {
      debug: true,
      listening_address: "0.0.0.0:67".parse::<SocketAddr>().unwrap(),
      bind_address: "0.0.0.0:68".parse::<SocketAddr>().unwrap(),
      interface: "".to_string(),
      routers: Vec::new(),
      subnet: "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
      dhcp_range: Vec::new(),
      dns_servers: Vec::new(),
      domain: "some.fake.lan".to_string(),
      lease_time: lease_to_seconds("12h"),
    }
  }

  pub(crate) fn set_lease(&mut self, s: &str) {
    self.lease_time = lease_to_seconds(s);
  }
}
