use std::fmt;
use std::{collections::HashMap, convert::TryInto, net::Ipv4Addr};

// for reference: the magic cookie marks the start of DHCP options.
// otherwise you'd never know where the options start after the fixed length of the base bootp message
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

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
///  htype (1 byte): ethernet is 1, 6 is IEEE 802 networks, 7 ARCNET. generally 6.
///  hlen (1): hardware address length. MAC address length; generally 6.
///  hops (1): generally 1. used by DHCP relays to go beyond subnet boundaries.
///  xid (4 bytes): transaction identifier. 32-bit identifier field generated by client, to match with replies from DHCP server.
///  secs (2): seconds elapsed since client began attempting to get an address. used by DHCP servers to prioritize responses.
///  flags (2): mostly unused flags area. subfield first bit is the Broadcast flag - client doesn't know its own IP yet, so respond by broadcast.
///  ciadrr (4): client puts is own address here. used only for RENEW, REBINDING, BOUND; otherwise 0. cuz it doesn't have one yet.
///  yiaddrr (4): 'your' ip address. take this, assign it to yourself. from dhcp server to client.
///  siaddr: (4): server ip address. usually the server's own.
///  giaddr (4): gateway ip (NOT DHCP DEFAULT GATEWAY. THAT'S ITS OWN DHCP OPTION.)
///  chwaddr (16): the client's mac address, used for making this a converation.
///  sname (64): server name.
///  file (128): boot filename.
///  options (variable): dhcp options, variable length.
///
#[derive(Default, Debug, Clone)]
pub(crate) struct DhcpMessage {
  pub op: u8,
  htype: u8,
  hlen: u8,
  hops: u8,
  xid: u32,
  secs: u16,
  flags: u16,
  ciaddr: u32,
  yiaddr: u32,
  siaddr: u32,
  giaddr: u32,
  chaddr: Vec<u8>,
  sname: usize,
  file: usize,
  options: HashMap<String, DhcpOption>,
}

#[derive(Debug, Clone)]
struct DhcpMessageParseError {
  raw_byte_array: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RawDhcpOption {
  code: u8,
  data: Vec<u8>, // just a string of bytes we don't have to understand
}

#[derive(Debug, Clone)]
pub(crate) enum DhcpOption {
  MessageType(DhcpMessageType),
  ServerIdentifier(Ipv4Addr),
  ParameterRequestList(Vec<u8>),
  RequestedIpAddress(Ipv4Addr),
  Hostname(String),
  Router(Vec<Ipv4Addr>),
  DomainNameServer(Vec<Ipv4Addr>),
  IpAddressLeaseTime(u32),
  SubnetMask(Ipv4Addr),
  Message(String),
  Unrecognized(RawDhcpOption),
}

#[derive(Debug, Clone)]
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

impl DhcpMessageType {
  pub(crate) fn from_u8(value: u8) -> DhcpMessageType {
    match value {
      1 => DhcpMessageType::DHCPDISCOVER,
      2 => DhcpMessageType::DHCPOFFER,
      3 => DhcpMessageType::DHCPREQUEST,
      4 => DhcpMessageType::DHCPDECLINE,
      5 => DhcpMessageType::DHCPACK,
      6 => DhcpMessageType::DHCPNAK,
      7 => DhcpMessageType::DHCPRELEASE,
      8 => DhcpMessageType::DHCPINFORM,
      _ => DhcpMessageType::UNKNOWN,
    }
  }
}

impl fmt::Display for DhcpMessage {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let s: &str = if self.op == 1 { "request" } else { "reply" };
    write!(
      f,
      "
       message type: {}
       mac address:  {}",
      s,
      self.format_mac()
    )
  }
}

impl DhcpMessage {
  pub(crate) fn format_mac(&self) -> String {
    format!(
      "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
      self.chaddr[0],
      self.chaddr[1],
      self.chaddr[2],
      self.chaddr[3],
      self.chaddr[4],
      self.chaddr[5]
    )
  }

  pub(crate) fn parse(&mut self, buf: &[u8]) {
    // first do the known-size parts
    self.op = buf[0];
    self.htype = buf[1];
    self.hlen = buf[2];
    self.hops = buf[3];
    self.xid = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    self.secs = u16::from_be_bytes(buf[9..11].try_into().unwrap());
    self.flags = u16::from_be_bytes(buf[11..13].try_into().unwrap());
    self.ciaddr = u32::from_be_bytes(buf[13..17].try_into().unwrap());
    self.yiaddr = u32::from_be_bytes(buf[17..21].try_into().unwrap());
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
      // println!("current index: {}", current_index);
      // println!("next: {:#?}", next);
      // println!(
      //   "buf near current_index: {:#?}",
      //   buf[current_index - 3..current_index + 3].to_vec()
      // );
      match next {
        // check the first byte of the returned byte array - this tells us the dhcp option
        // and then we just match each possible dhcp option with its length, grabbing
        // the data and advancing to the end of it
        Ok(n) => match n[0] {
          // specified dns servers, r >= 1
          0x05 => {
            let len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let b = Self::take_next(&self, buf, &mut current_index, len.into()).unwrap();
            match Self::get_ipv4_array(&self, len.into(), b) {
              Ok(a) => {
                self
                  .options
                  .insert("DNS_SERVERS".to_string(), DhcpOption::DomainNameServer(a));
              }
              Err(e) => {
                eprintln!("{:#?}", e);
                continue;
              }
            }
          }
          0x03 => {
            let len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let b = Self::take_next(&self, buf, &mut current_index, len.into()).unwrap();
            match Self::get_ipv4_array(&self, len.into(), b) {
              Ok(a) => {
                self
                  .options
                  .insert("ROUTERS".to_string(), DhcpOption::Router(a));
              }
              Err(e) => {
                eprintln!("{:#?}", e);
                continue;
              }
            }
          }
          // dec53: dhcp message type
          0x35 => {
            let dhcp_message_type_len =
              Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let dhcp_message_type =
              Self::take_next(&self, buf, &mut current_index, dhcp_message_type_len.into())
                .unwrap()[0];
            self.options.insert(
              "MESSAGETYPE".to_string(),
              DhcpOption::MessageType(DhcpMessageType::from_u8(dhcp_message_type)),
            );
          }
          // subnet mask
          0x01 => {
            let subnet_mask_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let fb =
              Self::take_next(&self, buf, &mut current_index, subnet_mask_len.into()).unwrap();
            let subnet_mask: Ipv4Addr = Ipv4Addr::new(fb[0], fb[1], fb[2], fb[3]);
            self.options.insert(
              "SUBNET_MASK".to_string(),
              DhcpOption::SubnetMask(subnet_mask),
            );
          }
          // requested IP address
          // dec50
          0x32 => {
            let request_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let four_bee =
              Self::take_next(&self, buf, &mut current_index, request_len.into()).unwrap();
            let ip: Ipv4Addr = Ipv4Addr::new(four_bee[0], four_bee[1], four_bee[2], four_bee[3]);
            self.options.insert(
              "REQUESTED_IP".to_string(),
              DhcpOption::RequestedIpAddress(ip),
            );
          }
          // dec12 hostname
          0x0c => {
            let hostname_len = Self::take_next(&self, buf, &mut current_index, 1).unwrap()[0];
            let hostname =
              Self::take_next(&self, buf, &mut current_index, hostname_len.into()).unwrap();
            self.options.insert(
              "HOSTNAME".to_string(),
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

  // look but don't mess with current index
  fn peek_next(&self, buf: &[u8], current_index: usize) -> u8 {
    buf[current_index]
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

  pub(crate) fn construct_response(&self) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::new();
    // self request! a-WOOOGAH! a-WOOOGAH!
    if self.op == 1 {
      let op: u8 = 0x02; // response
      let htype: u8 = self.htype; // ethernet
      let hlen: u8 = self.hlen; // hardware len
      let hops: u8 = 0;
      let xid = self.xid;
      let secs: u16 = 0;
      let flags: u16 = 0b0000_0001_0000_0000;
      let ciaddr: [u8; 4] = Ipv4Addr::new(0, 0, 0, 0).octets();
      let yiaddr: [u8; 4] = Ipv4Addr::new(192, 168, 122, 12).octets();
      let siaddr: [u8; 4] = Ipv4Addr::new(0, 0, 0, 0).octets();
      let giaddr: [u8; 4] = Ipv4Addr::new(0, 0, 0, 0).octets();
      let mut chaddr = self.chaddr.clone();
      let sname: &str = "dhcpd-rs.lan.zero9f9.com";
      let file: [u8; 128] = [0; 128];
      let magic_cookie = MAGIC_COOKIE;
      let offer: u8 = 53;
      let offer_len: u8 = 1;
      let offer_value: u8 = 2;
      let dhcp_server_id: u8 = 54;
      let dhcp_server_id_len: u8 = 4;
      let dhcp_server_id_value: [u8; 4] = Ipv4Addr::new(192, 168, 122, 1).octets();
      let lease_time_option: u8 = 51;
      let lease_time_len: u8 = 2;
      let mut lease_time: u16 = 0x7080;
      let subnet_mask_option: u8 = 0x01;
      let subnet_mask_len: u8 = 4;
      let subnet_mask: [u8; 4] = Ipv4Addr::new(255, 255, 255, 0).octets();
      let router_option: u8 = 3;
      let router_option_len: u8 = 4;
      let router_option_value: [u8; 4] = Ipv4Addr::new(192, 168, 122, 1).octets();
      let option_end: u8 = 255;
      response.push(op);
      response.push(htype);
      response.push(hlen);
      response.push(hops);
      Self::push_byte_vec_from_u32(&self, &mut response, xid);
      Self::push_byte_vec_from_u16(&self, &mut response, secs);
      Self::push_byte_vec_from_u16(&self, &mut response, flags);
      response.append(&mut ciaddr.to_vec());
      response.append(&mut yiaddr.to_vec());
      response.append(&mut siaddr.to_vec());
      response.append(&mut giaddr.to_vec());
      response.append(&mut chaddr);
      let mut e = sname.as_bytes().to_vec();
      response.append(&mut e);
      response.append(&mut file.to_vec());
      if response.len() < 236 {
        loop {
          response.push(0);
          if response.len() >= 236 {
            break;
          }
        }
      }
      // whew, we're done with bootp. on to dhcp!
      response.append(&mut magic_cookie.to_vec());
      assert_eq!(response.len(), 240);
      response.push(offer);
      response.push(offer_len);
      response.push(offer_value);
      response.push(dhcp_server_id);
      response.push(dhcp_server_id_len);
      response.append(&mut dhcp_server_id_value.to_vec());
      response.push(lease_time_option);
      response.push(lease_time_len);
      response.append(&mut lease_time.to_be_bytes().to_vec());
      response.push(subnet_mask_option);
      response.push(subnet_mask_len);
      response.append(&mut subnet_mask.to_vec());
      response.push(router_option);
      response.push(router_option_len);
      response.append(&mut router_option_value.to_vec());
      response.push(option_end);
      if response.len() < 276 {
        loop {
          response.push(0);
          if response.len() >= 276 {
            break;
          }
        }
      }
      return response;
    }
    return response;
  }

  fn push_byte_vec_from_u32(&self, vec: &mut Vec<u8>, obj: u32) {
    for b in &obj.to_be_bytes() {
      vec.push(*b);
    }
  }

  fn push_byte_vec_from_u16(&self, vec: &mut Vec<u8>, obj: u16) {
    for b in &obj.to_be_bytes() {
      vec.push(*b);
    }
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

  pub(crate) fn get_options_index(&self, ba: &[u8]) -> usize {
    let mmc = MAGIC_COOKIE;
    // examine each four bytes - are they our magic cookie?
    // they have to start at the end of the base bootp data
    let mut start: usize = 200;
    let mut end: usize = 204;
    let ba_len = ba.len();
    for _b in 0..=ba_len {
      if ba[start..end] == mmc {
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
}
