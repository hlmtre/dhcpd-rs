#![allow(dead_code)]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
  ffi::CString,
  fmt,
  net::{Ipv4Addr, SocketAddrV4},
};

use crate::arp::{self, MacAddress};
use crate::ping::ipv4::Ipv4IcmpPacket;

mod ipv4;

/*
 * welp you figured out why this appears as type 69
 * this an IPV4 AND ICMP packet.
 * you want just from the 20th packet - appears below as the fifth 0x08 (echo request is 0x08)
const ICMP_PACKET: [u8; 84] = [
  0x45, 0x00, 0x00, 0x00, 0xee, 0x96, 0x40, 0x00, 0x40, 0x01, 0x79, 0xf0, 0xc0, 0xa8, 0x01, 0x6a,
  0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x2f, 0x08, 0x66, 0xc2, 0x00, 0x12, 0x82, 0xaa, 0xcc, 0x5c,
  0x00, 0x00, 0x00, 0x00, 0x51, 0x49, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37,
];
*/

const ICMP_PACKET: [u8; 64] = [
  0x08, 0x00, 0xa4, 0x3c, 0x37, 0xb8, 0x00, 0x01, 0x18, 0x3a, 0x62, 0x61, 0x00, 0x00, 0x00, 0x00,
  0xd9, 0x9b, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];

#[repr(u8)]
enum IcmpPacketDataIndex {
  Type = 0,
  Code = 1,
  Checksum = 2,
  Identifier = 4,
  SequenceNumber = 6,
}

#[derive(Debug, Default)]
struct IcmpPacket {
  r#type: u8,
  code: u8,
  checksum: u16,
  seq_number: u16,
  raw_representation: Vec<u8>,
}

#[repr(u8)]
enum IcmpType {
  Reply = 0,
  DestinationUnreachable = 3,
  SourceQuence = 4,
  RedirectMessage = 5,
  AlternateHostAddress = 6,
  EchoRequest = 8,
}

#[repr(u8)]
enum IcmpCode {
  Reply = 0,
  DestinationHostUnreachable = 1,
  DestinationProtocolUnreachable = 2,
  DestinationPortUnreachabel = 3,
  NetworkAdministrativelyProhibited = 9,
}

impl fmt::Display for IcmpPacket {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "
      IcmpPacket
      ==========
       type:       {}
       code:       {}
       checksum:   {}
       seq_number: {}
       raw representation
         {:x?}",
      self.r#type, self.code, self.checksum, self.seq_number, self.raw_representation
    )
  }
}

impl IcmpPacket {
  pub fn new(buf: &[u8]) -> IcmpPacket {
    let mut raw = Vec::new();
    for e in buf {
      raw.push(*e);
    }
    IcmpPacket {
      r#type: buf[0],
      code: buf[1],
      // baller. https://stackoverflow.com/a/50244328/462430
      checksum: ((buf[2] as u16) << 8) | buf[3] as u16,
      seq_number: 0,
      raw_representation: raw,
    }
  }

  pub fn set_checksum(&mut self, checksum: u16) {
    replace_region(
      &mut self.raw_representation,
      &checksum.to_be_bytes(),
      IcmpPacketDataIndex::Checksum as usize,
    );
    self.checksum = checksum;
  }
}

/*
internet datagram header:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ICMP packet goes in here                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *

icmp packet:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data ...
+-+-+-+-+-


tcpdump:

11:19:24.169673 IP 192.168.122.149 > 192.168.122.1: ICMP echo request, id 27041, seq 1, length 64
                                               [192][168][122][149]
         total len -> |--| |--| < ident         c0   a8   7a    95
        0x0000:  4500 0054 e338 4000 4001 e188 c0a8 7a95  E..T.8@.@.....z.
                   ^^
                   \|__ type of service
              echo request ||__ code |--| ip checksum
        0x0010:  c0a8 7a01 0800 d263 69a1 0001 a5a2 5861  ..z....ci.....Xa
        0x0020:  0000 0000 f622 0900 0000 0000 1011 1213  ....."..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
11:19:24.169762 IP 192.168.122.1 > 192.168.122.149: ICMP echo reply, id 27041, seq 1, length 64
                 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
        0x0000:  45 00 00 54 d1 87 00 00 40 01 33 3a c0 a8 7a 01  E..T....@.3:..z.
        0x0010:  c0a8 7a95 0000 da63 69a1 0001 a5a2 5861          ..z....ci.....Xa
        0x0020:  0000 0000 f622 0900 0000 0000 1011 1213          ....."..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223          .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233          $%&'()*+,-./0123
        0x0050:  3435 3637                                        4567
*/

// Checksum algorithms

/// Calculates a checksum. Used by ipv4 and icmp. The two bytes starting at `skipword * 2` will be
/// ignored. Supposed to be the checksum field, which is regarded as zero during calculation.
fn checksum(data: &[u8], skipword: usize) -> u16 {
  finalize_checksum(sum_be_words(data, skipword))
}

/// Finalises a checksum by making sure it's 16 bits, then returning its 1's compliment
#[inline]
fn finalize_checksum(mut cs: u32) -> u16 {
  while cs >> 16 != 0 {
    cs = (cs >> 16) + (cs & 0xFFFF);
  }
  !cs as u16
}

/// Return the sum of the data as 16-bit words (assumes big endian)
fn sum_be_words(d: &[u8], mut skipword: usize) -> u32 {
  let len = d.len();
  let word_data: &[u16] = unsafe { std::slice::from_raw_parts(d.as_ptr() as *const u16, len / 2) };
  let word_data_length = word_data.len();
  skipword = ::std::cmp::min(skipword, word_data_length);

  let mut sum = 0u32;
  let mut i = 0;
  while i < word_data_length {
    if i == skipword && i != 0 {
      i += 1;
      continue;
    }
    sum += u16::from_be(unsafe { *word_data.get_unchecked(i) }) as u32;
    i += 1;
  }
  // If the length is odd, make sure to checksum the final byte
  if len & 1 != 0 {
    sum += (unsafe { *d.get_unchecked(len - 1) } as u32) << 8;
  }

  sum
}

/// Replaces the region in the target array with the data in the src array,
/// starting at position index and continuing til the end of src array.
/// Does nothing if the src array length + the index is longer than the target array.
#[inline(always)]
fn replace_region(target_arr: &mut [u8], src_arr: &[u8], index: usize) {
  // index + len would extend beyond the length of target_arr
  // just bail
  if src_arr.len() + index > target_arr.len() {
    return;
  }
  target_arr[index..(src_arr.len() + index)].clone_from_slice(src_arr);
}

#[inline(always)]
fn print_packet(p: Vec<u8>) {
  for (counter, elem) in p.iter().enumerate() {
    if counter % 8 == 0 {
      println!();
    }
    print!("{:#04x} ", elem);
  }
  println!();
}

/// Check if the specified dst address is reachable from our given
/// source address and interface.
/// returns: bool; false is good, basically. false means the address didn't respond
/// to ping, and we can safely hand it out.
///
/// Example:
/// ```no_run
/// let saddr = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
/// let daddr = "8.8.8.8".parse::<Ipv4Addr>().unwrap();
/// let i = reachable(saddr, "eth0", daddr);
///
/// assert_eq!(i, false);
/// ```
pub fn reachable(src_addr: Ipv4Addr, iface: &str, dst: Ipv4Addr) -> (bool, MacAddress) {
  let listener = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
  listener
    .bind_device(Some(&CString::new(iface).unwrap()))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", iface));

  let sender = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
  sender
    .bind_device(Some(&CString::new(iface).unwrap()))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", iface));
  let saddr = SocketAddrV4::new(src_addr, 0);
  sender
    .bind(&SockAddr::from(saddr))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", saddr));

  let our_icmp_packet = ICMP_PACKET;

  let mut i = IcmpPacket::new(&our_icmp_packet);
  i.set_checksum(checksum(
    &i.raw_representation,
    IcmpPacketDataIndex::Checksum as usize,
  ));

  //println!("{:#?}", i);
  let mut recv_buf = [0_u8; 84];

  let _ = sender.set_reuse_port(true);
  let _ = sender.set_nonblocking(true);
  let dsaddr = std::net::SocketAddrV4::new(dst, 0);
  let b = sender
    .send_to(&our_icmp_packet, &SockAddr::from(dsaddr))
    .unwrap();
  println!("Successfully sent {} bytes", b);

  let _ = listener.set_read_timeout(Some(core::time::Duration::new(2, 0)));
  let resp = listener.recv(&mut recv_buf);
  match resp {
    Ok(r) => {
      println!("==> Received {} bytes.", r);
      let resp_packet = Ipv4IcmpPacket::new(&recv_buf.clone());
      let resp_icmp = IcmpPacket::new(&recv_buf[19..84]);
      println!("{}", resp_packet);
      println!("{}", resp_icmp);
      let _m = arp::get_mac_for_ip(resp_packet.src_address);
      println!("{:?}", _m);
      return (true, _m);
    }
    Err(e) => {
      println!("Error: {:#?}", e);
      return (
        false,
        MacAddress {
          bytes: [0, 0, 0, 0, 0, 0].to_vec(),
        },
      );
    }
  }
}
