use std::{
  net::{Ipv4Addr, SocketAddr},
  time::Duration,
};

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
  pub bind_address: SocketAddr,
  pub routers: Vec<Ipv4Addr>,
  pub subnet: Ipv4Addr,
  pub dhcp_range: Vec<Ipv4Addr>,
  pub dns_servers: Vec<Ipv4Addr>,
  pub domain: String,
  pub lease_time: String,
}

impl Default for Config {
  fn default() -> Self {
    Config {
      debug: true,
      listening_address: "0.0.0.0:67".parse::<SocketAddr>().unwrap(),
      bind_address: "0.0.0.0:68".parse::<SocketAddr>().unwrap(),
      routers: Vec::new(),
      subnet: "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
      dhcp_range: Vec::new(),
      dns_servers: Vec::new(),
      domain: "some.fake.lan".to_string(),
      lease_time: "12h".to_string(),
    }
  }
}

impl Config {
  pub(crate) fn lease_to_seconds(&self) -> u32 {
    if self.lease_time.ends_with("h") {
      let mut hours = String::new();
      for c in self.lease_time.chars() {
        if !c.is_digit(10) {
          hours.push(c);
        }
      }
      let hours_as_int = match hours.parse::<u32>() {
        Ok(h) => h,
        Err(_) => 12,
      };
      return 60 * hours_as_int;
    }
    return 28800;
  }
}
