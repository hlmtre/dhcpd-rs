use std::{
  collections::HashMap, convert::TryInto, fmt::Formatter, net::Ipv4Addr, time::SystemTime,
};
use std::{fmt, net::IpAddr};

use crate::{
  config::Config,
  options::{byte_serialize::BEByteSerializable, *},
  pool::{LeaseStatus, LeaseUnique, Pool},
};

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
*/
///
///  op (1 byte): 1 indicates a request, 2 a reply
///  htype (1 byte): ethernet is 1, 6 is IEEE 802 networks, 7 ARCNET. generally 1.
///  hlen (1): hardware address length. MAC address length; generally 6.
///  hops (1): generally 1. used by DHCP relays to go beyond subnet boundaries.
///  xid (4 bytes): transaction identifier. 32-bit identifier field generated by client, to match with replies from DHCP server.
///  secs (2): seconds elapsed since client began attempting to get an address. used by DHCP servers to prioritize responses.
///  flags (2): mostly unused flags area. subfield first bit is the Broadcast flag - client doesn't know its own IP yet, so respond by broadcast.
///  ciadrr (4): client puts is own address here. used only for RENEW, REBINDING, BOUND; otherwise 0. cuz it doesn't have one yet.
///  yiaddrr (4): 'your' ip address. take this, assign it to yourself. from dhcp server to client.
///  siaddr: (4): server ip address. usually the server's own.
///  giaddr (4): gateway ip (NOT DHCP DEFAULT GATEWAY. THAT'S ITS OWN DHCP OPTION.)
///  chaddr (16): the client's mac address, used for making this a converation.
///  sname (64): server name.
///  file (128): boot filename.
///  options (variable): dhcp options, variable length.
///
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct DhcpMessage {
  op: u8,
  htype: u8,
  hlen: u8,
  hops: u8,
  xid: u32,
  secs: u16,
  flags: u16,
  pub ciaddr: u32,
  yiaddr: u32,
  siaddr: u32,
  giaddr: u32,
  pub chaddr: Vec<u8>,
  sname: usize,
  file: usize,
  pub options: HashMap<u8, DhcpOption>,
}

#[derive(Debug, Clone)]
struct DhcpMessageParseError {
  raw_byte_array: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawDhcpOption {
  code: u8,
  data: Vec<u8>, // just a string of bytes we don't have to understand
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DhcpOption {
  MessageType(DhcpMessageType),
  ServerIdentifier(Ipv4Addr),
  ParameterRequestList(Vec<u8>),
  RequestedIpAddress(Ipv4Addr),
  Hostname(String),
  Router(Vec<Ipv4Addr>),
  DomainNameServer(Vec<Ipv4Addr>),
  #[allow(dead_code)]
  IpAddressLeaseTime(u32),
  SubnetMask(Ipv4Addr),
  #[allow(dead_code)]
  Message(String),
  #[allow(dead_code)]
  Unrecognized(RawDhcpOption),
}

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub(crate) enum DhcpMessageType {
  UNKNOWN = 0,
  DHCPDISCOVER = 1,
  DHCPOFFER = 2,
  DHCPREQUEST = 3,
  DHCPDECLINE = 4,
  DHCPACK = 5,
  DHCPNAK = 6,
  DHCPRELEASE = 7,
  DHCPINFORM = 8,
}

impl From<DhcpMessageType> for u8 {
  fn from(orig: DhcpMessageType) -> Self {
    match orig {
      DhcpMessageType::UNKNOWN => return 0,
      DhcpMessageType::DHCPDISCOVER => return 1,
      DhcpMessageType::DHCPOFFER => return 2,
      DhcpMessageType::DHCPREQUEST => return 3,
      DhcpMessageType::DHCPDECLINE => return 4,
      DhcpMessageType::DHCPACK => return 5,
      DhcpMessageType::DHCPNAK => return 6,
      DhcpMessageType::DHCPRELEASE => return 7,
      DhcpMessageType::DHCPINFORM => return 8,
    }
  }
}

impl From<u8> for DhcpMessageType {
  fn from(orig: u8) -> Self {
    match orig {
      1 => return DhcpMessageType::DHCPDISCOVER,
      2 => return DhcpMessageType::DHCPOFFER,
      3 => return DhcpMessageType::DHCPREQUEST,
      4 => return DhcpMessageType::DHCPDECLINE,
      5 => return DhcpMessageType::DHCPACK,
      6 => return DhcpMessageType::DHCPNAK,
      7 => return DhcpMessageType::DHCPRELEASE,
      8 => return DhcpMessageType::DHCPINFORM,
      0 | _ => return DhcpMessageType::UNKNOWN,
    }
  }
}

pub(crate) fn format_mac(mac: &Vec<u8>) -> String {
  format!(
    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
  )
}

impl fmt::Display for DhcpMessage {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    let s: &str = if self.op == 1 { "request" } else { "reply" };
    write!(
      f,
      "op: {}, xid: {:02x?}, ciaddr: {:02x?}, chaddr: {:02x?}, options: {:02x?}",
      s,
      self.xid,
      self.ciaddr,
      format_mac(&self.chaddr),
      self.options
    )
  }
}

impl DhcpMessage {
  pub(crate) fn parse(&mut self, buf: &[u8]) {
    // first do the known-size parts
    self.op = buf[0];
    self.htype = buf[1];
    self.hlen = buf[2];
    self.hops = buf[3];
    self.xid = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    self.secs = u16::from_be_bytes(buf[8..10].try_into().unwrap());
    self.flags = u16::from_be_bytes(buf[10..12].try_into().unwrap());
    self.ciaddr = u32::from_be_bytes(buf[12..16].try_into().unwrap());
    self.yiaddr = u32::from_be_bytes(buf[16..20].try_into().unwrap());
    if self.hlen == 6 {
      self.chaddr = buf[28..34].to_vec();
    } else {
      self.chaddr = buf[28..36].to_vec();
    }
    // then the parts that are actually DHCP, not just bootp
    // these parts are variable length, so we have to
    // get past the four-byte magic cookie to the next option
    let mut current_index = Self::get_options_index(&self, buf) + 4;
    loop {
      // this gets the next u8 byte off the array, AND increments our index by 1
      let next: Result<Vec<u8>, DhcpMessageParseError> =
        Self::take_next(&self, buf, &mut current_index, 1);
      match next {
        // check the first byte of the returned byte array - this tells us the dhcp option
        // and then we just match each possible dhcp option with its length, grabbing
        // the data and advancing to the end of it
        Ok(n) => match n[0] {
          DOMAIN_NAME_SERVER => {
            let len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let b = Self::take_next(&self, buf, &mut current_index, len.into()).unwrap();
            match Self::get_ipv4_array(&self, len.into(), b) {
              Ok(a) => {
                self
                  .options
                  .insert(DOMAIN_NAME_SERVER, DhcpOption::DomainNameServer(a));
              }
              Err(e) => {
                eprintln!("{:#?}", e);
                continue;
              }
            }
          }
          ROUTER => {
            let len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let b = Self::take_next(&self, buf, &mut current_index, len.into()).unwrap();
            match Self::get_ipv4_array(&self, len.into(), b) {
              Ok(a) => {
                self.options.insert(ROUTER, DhcpOption::Router(a));
              }
              Err(e) => {
                eprintln!("{:#?}", e);
                continue;
              }
            }
          }
          // dec54: server identifier
          SERVER_IDENTIFIER => {
            let len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let b = Self::take_next(&self, buf, &mut current_index, len.into()).unwrap();
            match Self::get_ipv4_array(&self, len.into(), b) {
              Ok(a) => {
                self
                  .options
                  .insert(SERVER_IDENTIFIER, DhcpOption::ServerIdentifier(a[0]));
              }
              Err(e) => {
                eprintln!("{:#?}", e);
                continue;
              }
            }
          }
          DHCP_MESSAGE_TYPE => {
            let dhcp_message_type_len =
              Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let dhcp_message_type =
              Self::take_next(&self, buf, &mut current_index, dhcp_message_type_len.into())
                .unwrap()[0];
            self.options.insert(
              DHCP_MESSAGE_TYPE,
              DhcpOption::MessageType(dhcp_message_type.into()),
            );
          }
          // dec55: parameter request list
          PARAMETER_REQUEST_LIST => {
            let prl_len: usize =
              Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0].into();
            let mut prl_vec: Vec<u8> = Vec::new();
            for _x in current_index..current_index + prl_len {
              prl_vec.push(buf[_x]);
            }
            self.options.insert(
              PARAMETER_REQUEST_LIST,
              DhcpOption::ParameterRequestList(prl_vec),
            );
            current_index = current_index + prl_len;
          }
          SUBNET_MASK => {
            let subnet_mask_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let fb =
              Self::take_next(&self, buf, &mut current_index, subnet_mask_len.into()).unwrap();
            let subnet_mask: Ipv4Addr = Ipv4Addr::new(fb[0], fb[1], fb[2], fb[3]);
            self
              .options
              .insert(SUBNET_MASK, DhcpOption::SubnetMask(subnet_mask));
          }
          REQUESTED_IP_ADDRESS => {
            let request_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let four_bee =
              Self::take_next(&self, buf, &mut current_index, request_len.into()).unwrap();
            let i = self.get_ipv4_array(4, four_bee);
            match i {
              Ok(mut ip) => {
                self.options.insert(
                  REQUESTED_IP_ADDRESS,
                  DhcpOption::RequestedIpAddress(ip.pop().unwrap()),
                );
              }
              Err(e) => {
                eprintln!("Bad ipv4 address requested.");
                eprintln!("Error: {:?}", e);
              }
            }
          }
          HOST_NAME => {
            let hostname_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let hostname =
              Self::take_next(&self, buf, &mut current_index, hostname_len.into()).unwrap();
            self.options.insert(
              HOST_NAME,
              DhcpOption::Hostname(std::str::from_utf8(&hostname).unwrap().to_string()),
            );
          }
          _ => {
            break;
          }
        },
        Err(_) => {}
      }
    }
  }

  /// take a reference to the dhcp message buffer, read everything to jump length,
  /// and increment our current index by jump length.
  /// returns the byte array read as a vector.
  fn take_next(
    &self,
    buf: &[u8],
    current_index: &mut usize,
    jump: usize,
  ) -> Result<Vec<u8>, DhcpMessageParseError> {
    let ret = buf[*current_index..*current_index + jump].to_vec();
    *current_index += jump;
    Ok(ret)
  }

  pub(crate) fn construct_response(&self, c: &Config, p: &mut Pool) -> Vec<u8> {
    let mut response = self.build_bootp_packet(p, c);
    let offer_len: u8 = 1;
    let mut offer_value: u8 = 0;
    let dhcp_server_id_len: u8 = 4;
    let a = c.bind_address.ip();
    let dhcp_server_id_value: [u8; 4] = match a {
      IpAddr::V4(ip4) => ip4.octets(),
      IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED.octets(),
    };
    let lease_time_len: u8 = 4;
    let lease_time: u32 = c.lease_time;
    let subnet_mask_len: u8 = 4;
    let subnet_mask: [u8; 4] = c.subnet.octets();
    let router_option_len: u8 = 4;
    let mut b = c.routers.clone();
    // so we can pop and get the first one specified
    b.reverse();
    let router_option_value: [u8; 4] = b.pop().unwrap_or_else(|| Ipv4Addr::UNSPECIFIED).octets();
    let option_end: u8 = 255;
    let mut y: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut message: String = String::new();

    match *self.options.get(&DHCP_MESSAGE_TYPE).unwrap() {
      // a DISCOVER! a-WOOOGAH! a-WOOOGAH!
      DhcpOption::MessageType(DhcpMessageType::DHCPDISCOVER) => {
        // DHCPOFFER
        y = self.get_client_ip();
        if y.is_unspecified() {
          y = match self.options.get(&REQUESTED_IP_ADDRESS) {
            Some(i) => match i {
              DhcpOption::RequestedIpAddress(x) => *x,
              _ => y,
            },
            _ => y,
          };
        }
        if !y.is_unspecified() && p.available(y, &c.interface) {
          offer_value = DhcpMessageType::DHCPOFFER.into();
        } else {
          offer_value = DhcpMessageType::DHCPOFFER.into();
          y = match p.ip_for_mac(self.chaddr.clone()) {
            // did we already give out an IP to this mac?
            Ok(m) => *m,
            Err(e) => {
              println!("{:?}", e);
              let l = p.allocate_address(self.chaddr.clone(), c.lease_time);
              match l {
                Ok(x) => x.ip,
                Err(_) => {
                  offer_value = DhcpMessageType::DHCPNAK.into();
                  Ipv4Addr::LOCALHOST
                }
              }
            }
          }
        }
      }
      DhcpOption::MessageType(DhcpMessageType::DHCPREQUEST) => {
        // client is requesting an IP
        y = match self.options.get(&REQUESTED_IP_ADDRESS) {
          Some(i) => match i {
            DhcpOption::RequestedIpAddress(x) => *x,
            _ => {
              eprintln!("{:?}", self);
              Ipv4Addr::UNSPECIFIED
            }
          },
          _ => Ipv4Addr::from(self.ciaddr),
        };
        // if it's available or this client had it before...
        if p.available(y, &c.interface) {
          if c.debug {
            println!(
              "Received DHCPREQUEST for {} from {}, issuing lease. ACKing...",
              y,
              format_mac(&self.chaddr),
            );
            offer_value = DhcpMessageType::DHCPACK.into();
          }
        } else if let Some(kv) = p.leases.get(&LeaseUnique {
          ip: y.clone(),
          hwaddr: Box::new(self.chaddr.clone()),
        }) {
          if kv.hwaddr == self.chaddr {
            if c.debug {
              println!(
                "Received DHCPREQUEST for {} from {}, re-issuing. ACKing...",
                y,
                format_mac(&self.chaddr),
              );
            }
            offer_value = DhcpMessageType::DHCPACK.into();
            p.update_lease(self.chaddr.clone(), SystemTime::now());
          }
        } else {
          // no IP for you
          if c.debug {
            println!(
              "Received DHCPREQUEST for {} from {}, available?: {}. NAKed.",
              y,
              format_mac(&self.chaddr),
              p.available(y, &c.interface)
            );
          }
          offer_value = DhcpMessageType::DHCPNAK.into();
          message = format!("IP address {} is unavailable.", y);
        }
      }
      _ => {}
    }
    response[16] = y.octets()[0];
    response[17] = y.octets()[1];
    response[18] = y.octets()[2];
    response[19] = y.octets()[3];
    response.append(&mut MAGIC_COOKIE.to_vec());
    assert_eq!(response.len(), 240);
    response.push(DHCP_MESSAGE_TYPE);
    response.push(offer_len);
    response.push(offer_value);
    // parse our requested parameters to determine what to stick
    // into the dhcp response portion of our reply
    let prl = self.get_prl();
    for x in prl {
      match x {
        SUBNET_MASK => {
          response.push(SUBNET_MASK);
          response.push(subnet_mask_len);
          response.append(&mut subnet_mask.to_vec());
        }
        ROUTER => {
          response.push(ROUTER);
          response.push(router_option_len);
          response.append(&mut router_option_value.to_vec());
        }
        DOMAIN_NAME_SERVER => {
          response.push(DOMAIN_NAME_SERVER);
          response.push((c.dns_servers.len() * 4).try_into().unwrap());
          c.dns_servers.clone().into_iter().for_each(|i| {
            i.octets().iter().for_each(|o| {
              response.push(*o);
            });
          });
        }
        DOMAIN_NAME => {
          if c.domain.len() > 0 {
            {
              response.push(DOMAIN_NAME);
              response.push(c.domain.chars().count().try_into().unwrap());
              response.append(&mut c.domain.as_bytes().to_vec());
            }
          }
        }
        _ => {}
      }
    }
    response.push(SERVER_IDENTIFIER);
    response.push(dhcp_server_id_len);
    response.append(&mut dhcp_server_id_value.to_vec());
    response.push(IP_ADDRESS_LEASE_TIME);
    response.push(lease_time_len);
    response.append(&mut lease_time.to_be_bytes().to_vec());
    if message.chars().count() > 0 {
      response.push(MESSAGE);
      response.push(message.chars().count().try_into().unwrap());
      let m = message.as_bytes();
      response.append(&mut m.to_vec());
    }
    response.push(option_end);
    if response.len() < 276 {
      loop {
        response.push(0);
        if response.len() >= 276 {
          break;
        }
      }
    }
    p.prune_leases();
    return response;
  }

  fn build_bootp_packet(&self, p: &mut Pool, c: &Config) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::new();
    let op: u8 = 0x02; // response
    let htype: u8 = self.htype; // ethernet
    let hlen: u8 = self.hlen; // hardware len
    let hops: u8 = 0;
    let xid = self.xid;
    let secs: u16 = 0;
    let flags: u16 = 0b0000_0001_0000_0000;
    let ciaddr: [u8; 4] = self.ciaddr.to_be_bytes();
    let mut yiaddr: [u8; 4] = [0, 0, 0, 0];
    let mut chaddr = self.chaddr.clone();
    // TODO some stuff in here so we understand the 'conversation' part of the dhcp conversation
    // remember the xid
    match self.options.get(&DHCP_MESSAGE_TYPE) {
      Some(i) => match i {
        DhcpOption::MessageType(x) => match x {
          DhcpMessageType::DHCPDISCOVER | DhcpMessageType::DHCPREQUEST => {
            match self.options.get(&REQUESTED_IP_ADDRESS) {
              Some(i) => match i {
                DhcpOption::RequestedIpAddress(x) => {
                  if p.valid_lease(*x) {
                    // just ACK the client their requested address
                    yiaddr = x.octets();
                    if c.debug {
                      println!("acking client {}", Ipv4Addr::from(yiaddr));
                    }
                  }
                }
                _ => {}
              },
              None => {
                // client isn't requesting one specifically here, let's generate one and give it to em
                let mut found: bool = false;
                for (_k, l) in p.leases.iter_mut() {
                  if l.hwaddr == chaddr {
                    // a lease already exists
                    match l.lease_status() {
                      LeaseStatus::Fresh => {
                        yiaddr = l.ip.octets();
                        found = true;
                        break;
                      }
                      LeaseStatus::Decaying => {
                        l.update_lease(SystemTime::now());
                        yiaddr = l.ip.octets();
                        found = true;
                        break;
                      }
                      LeaseStatus::Expired => {
                        break;
                      }
                    }
                  }
                }
                if found {
                  if c.debug {
                    println!(
                      "found existing lease for {}; re-issuing lease to {}",
                      Ipv4Addr::from(yiaddr),
                      format_mac(&chaddr)
                    );
                  }
                }
                if !found {
                  yiaddr = match p.allocate_address(chaddr.clone(), c.lease_time) {
                    Ok(l) => l.ip.octets(),
                    Err(e) => {
                      if c.debug {
                        println!("Error allocating address: {:?}", e);
                      }
                      [0, 0, 0, 0]
                    }
                  };
                  if c.debug {
                    println!(
                      "new address requested for {}; issuing new lease to {}",
                      Ipv4Addr::from(yiaddr),
                      format_mac(&chaddr)
                    );
                  }
                }
              }
            }
          }
          DhcpMessageType::DHCPACK => {}
          DhcpMessageType::DHCPNAK => {}
          DhcpMessageType::DHCPRELEASE => {
            if c.debug {
              println!("RELEASE {}", self);
            }
          }
          DhcpMessageType::DHCPINFORM => {}
          _ => {}
        },
        _ => {}
      },
      None => {}
    }
    let siaddr: [u8; 4] = self.siaddr.to_be_bytes();
    let giaddr: [u8; 4] = Ipv4Addr::new(0, 0, 0, 0).octets();
    let sname: &str = "dhcpd-rs.lan.zero9f9.com";
    let file: [u8; 128] = [0; 128];
    response.push(op);
    response.push(htype);
    response.push(hlen);
    response.push(hops);
    BEByteSerializable::to_be_bytes(&xid, &mut response);
    BEByteSerializable::to_be_bytes(&secs, &mut response);
    BEByteSerializable::to_be_bytes(&flags, &mut response);
    response.append(&mut ciaddr.to_vec());
    response.append(&mut yiaddr.to_vec());
    response.append(&mut siaddr.to_vec());
    response.append(&mut giaddr.to_vec());
    let mut chaddr_paddr = Vec::with_capacity(16 - chaddr.len());
    // they gotta be padded out to fill expected bootp field size ...
    // chaddr should be 16 bytes...
    for _i in 0..chaddr_paddr.capacity() {
      chaddr_paddr.push(0);
    }
    response.append(&mut chaddr);
    response.append(&mut chaddr_paddr);
    let mut e = sname.as_bytes().to_vec();
    // and server name 64 bytes...
    let mut pad = Vec::with_capacity(64 - e.len());
    for _i in 0..pad.capacity() {
      pad.push(0);
    }
    response.append(&mut e);
    response.append(&mut pad);
    response.append(&mut file.to_vec());
    if response.len() < 236 {
      loop {
        response.push(0);
        if response.len() >= 236 {
          break;
        }
      }
    }
    response
  }

  fn get_ipv4_array(
    &self,
    total_len: usize,
    ipv4_octets: Vec<u8>,
  ) -> Result<Vec<Ipv4Addr>, DhcpMessageParseError> {
    if total_len % 4 != 0 {
      let dmpe: DhcpMessageParseError = DhcpMessageParseError {
        raw_byte_array: ipv4_octets,
      };
      return Err(dmpe);
    }
    let mut ovec: Vec<Ipv4Addr> = Vec::new();
    for x in 0..total_len {
      if x % 4 == 0 || x == 0 {
        let r: Ipv4Addr = Ipv4Addr::new(
          ipv4_octets[usize::from(x)],
          ipv4_octets[usize::from(x) + 1],
          ipv4_octets[usize::from(x) + 2],
          ipv4_octets[usize::from(x) + 3],
        );
        ovec.push(r);
      }
    }
    Ok(ovec)
  }

  pub(crate) fn get_client_ip(&self) -> Ipv4Addr {
    return Ipv4Addr::from(self.ciaddr);
  }

  pub(crate) fn get_options_index(&self, ba: &[u8]) -> usize {
    // examine each four bytes - are they our magic cookie?
    // they have to start at the end of the base bootp data
    let mut start: usize = 200;
    let mut end: usize = 204;
    let ba_len = ba.len();
    for _b in 0..=ba_len {
      if ba[start..end] == MAGIC_COOKIE {
        return start;
      }
      start += 1;
      end += 1;
      // if we run out of bits, it can't be here
      if end >= ba_len {
        return 0;
      }
    }
    // if we didn't find it already
    0
  }

  fn get_yiaddr(&self) -> Ipv4Addr {
    Ipv4Addr::from(self.yiaddr)
  }

  fn get_prl(&self) -> Vec<u8> {
    match self.options.get(&PARAMETER_REQUEST_LIST) {
      Some(d) => match d {
        DhcpOption::ParameterRequestList(a) => return a.clone(),
        _ => return Vec::new(),
      },
      None => return Vec::new(),
    }
  }
}
