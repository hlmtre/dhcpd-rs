use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{ffi::CString, net::Ipv4Addr};

// TODO:
// this appears in tcpdump as icmp type 69 (69420l33t_topkek)
//
const ICMP_PACKET: [u8; 84] = [
  0x45, 0x00, 0x00, 0x00, 0xee, 0x96, 0x40, 0x00, 0x40, 0x01, 0x79, 0xf0, 0xc0, 0xa8, 0x01, 0x6a,
  0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x2f, 0x08, 0x66, 0xc2, 0x00, 0x12, 0x82, 0xaa, 0xcc, 0x5c,
  0x00, 0x00, 0x00, 0x00, 0x51, 0x49, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37,
];

/*
const SECOND_ICMP_PACKET: [u8; 84] = [
  0x45, 0x00, 0x00, 0x54, 0x13, 0x53, 0x40, 0x00, 0x40, 0x01, 0xb1, 0x6d, 0xc0, 0xa8, 0x7a, 0x0,
  0xc0, 0xa8, 0x7a, 0x96, 0x08, 0x00, 0x89, 0xeb, 0xca, 0xe3, 0x00, 0x01, 0xf8, 0x06, 0x5d, 0x61,
  0x00, 0x00, 0x00, 0x00, 0x80, 0xf4, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37,
];
*/

#[derive(Debug)]
struct Ipv4IcmpPacket {
  version: u8, // really a nibble - most significant half of first byte
  ihl: u8,     // really a nibble - second half of first byte
  src_address: Ipv4Addr,
  dst_address: Ipv4Addr,
  ttl: u8,
  protocol: u8,
  ipv4_checksum: u16,
  icmp_type: u8,
  icmp_code: u8,
  icmp_checksum: u16,
  identifier: u16,
  sequence_number: u16,
}

impl Ipv4IcmpPacket {
  // TODO
  // write more helper functions to tease out the data from each byte in the packet
  pub fn new(buf: &[u8]) -> Ipv4IcmpPacket {
    let (v, l) = Ipv4IcmpPacket::get_version_ihl(buf[Ipv4DataIndex::IpType_HeaderLen as usize]);
    Ipv4IcmpPacket {
      version: v,
      ihl: l,
      src_address: Ipv4Addr::from(vec_as_u8_array(Ipv4IcmpPacket::retrieve_bytes(
        buf,
        4,
        Ipv4DataIndex::SrcAddress as usize,
      ))),
      dst_address: Ipv4Addr::from(vec_as_u8_array(Ipv4IcmpPacket::retrieve_bytes(
        buf,
        4,
        Ipv4DataIndex::DstAddress as usize,
      ))),
      ttl: 0,
      protocol: 1,
      ipv4_checksum: 0,
      icmp_type: 0,
      icmp_code: 8,
      icmp_checksum: 0,
      identifier: 0,
      sequence_number: 0,
    }
  }

  #[inline(always)]
  fn get_version_ihl(byte: u8) -> (u8, u8) {
    let version = (byte & 0xf0) >> 4;
    let ihl = byte & 0x0f;
    (version, ihl)
  }

  fn retrieve_bytes(target_arr: &[u8], num_bytes: usize, index: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for counter in 0..num_bytes {
      v.push(target_arr[index + counter]);
    }
    return v;
  }
  // this is, in this case, only ever going to be 1
  // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  fn get_protocol(&self) -> u8 {
    return self.protocol;
  }
}

fn vec_as_u8_array(v: Vec<u8>) -> [u8; 4] {
  if v.len() > 4 {
    return [0x0, 0x0, 0x0, 0x0];
  }
  let mut arr = [0u8; 4];
  for (place, element) in arr.iter_mut().zip(v.iter()) {
    *place = *element;
  }
  arr
}

// indices of the chunks of data in the packet, by byte
enum Ipv4DataIndex {
  IpType_HeaderLen = 0,
  TOS = 1,
  TotalLen = 2,
  Identification = 4,
  Flags_FragmentOffset = 6,
  TTL = 8,
  Protocol = 9,
  HeaderChecksum = 10,
  SrcAddress = 12,
  DstAddress = 16,
  Data = 20,
}

enum IcmpPacketDataIndex {
  Type = 0,
  Code = 1,
  Checksum = 2,
  Identifier = 4,
  SequenceNumber = 6,
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

// Checksum algorithms:

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

#[inline(always)]
fn replace_region(target_arr: &mut [u8], src_arr: &[u8], index: usize) {
  for counter in 0..src_arr.len() {
    target_arr[index + counter] = src_arr[counter];
  }
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

pub fn reachable(src_addr: Ipv4Addr, iface: &str, dst: Ipv4Addr) -> bool {
  let mut recv_buf = [0_u8; 84];

  let listener = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
  listener
    .bind_device(Some(&CString::new(iface).unwrap()))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", iface));

  let sender = Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap();
  sender
    .bind_device(Some(&CString::new(iface).unwrap()))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", iface));

  let mut our_icmp_packet = ICMP_PACKET.clone();

  println!("Before:");
  print_packet(our_icmp_packet.to_vec());
  replace_region(
    &mut our_icmp_packet,
    &dst.octets(),
    Ipv4DataIndex::DstAddress as usize,
  );
  replace_region(
    &mut our_icmp_packet,
    &dst.octets(),
    Ipv4DataIndex::DstAddress as usize,
  );

  let i: Ipv4IcmpPacket = Ipv4IcmpPacket::new(&our_icmp_packet);
  println!("{:#?}", i);
  println!("local addr: {:#?}", src_addr);
  return false;

  let cksum = checksum(&our_icmp_packet, IcmpPacketDataIndex::Checksum as usize);
  println!("checksum: {:#04x}", cksum);
  replace_region(
    &mut our_icmp_packet.to_vec(),
    &checksum(&our_icmp_packet, IcmpPacketDataIndex::Checksum as usize).to_be_bytes(),
    IcmpPacketDataIndex::Checksum as usize,
  );
  println!("After:");
  print_packet(our_icmp_packet.to_vec());

  let _ = sender.set_reuse_port(true);
  let _ = sender.set_nonblocking(true);
  let saddr = std::net::SocketAddrV4::new(dst, 0);
  let b = sender
    .send_to(&our_icmp_packet, &SockAddr::from(saddr))
    .unwrap();
  println!("Successfully sent {} bytes", b);
  print_packet(our_icmp_packet.to_vec());

  let _ = listener.set_read_timeout(Some(core::time::Duration::new(2, 0)));
  let resp = listener.recv(&mut recv_buf);
  match resp {
    Ok(r) => {
      println!("{:#?}", r);
      return true;
    }
    Err(e) => {
      println!("Error: {:#?}", e);
      return false;
    }
  }

  /*
  let (tx, rx) = std::sync::mpsc::sync_channel(84);
  std::thread::spawn(|| {
    if let Ok(a) = socket.recv(*recv_buf) {
      tx.send(a);
    }
  });
  loop {
    match rx.try_recv() {
      Ok(resp) => {
        println!("{:#?}", resp);
        let saddr = std::net::SocketAddrV4::new(dst, 0);
        let b = socket
          .send_to(&our_icmp_packet, &SockAddr::from(saddr))
          .unwrap();
        //println!("{:#04x?}", recv_buf);
        println!("sent {} bytes", b);
        return false;
      }
      Err(_) => return true,
    }
  }
  */

  /*
  use fastping_rs::{
    PingResult::{Idle, Receive},
    Pinger,
  };
  let (pinger, results) = match Pinger::new(None, Some(56)) {
    Ok((pinger, results)) => (pinger, results),
    Err(e) => panic!("Error creating pinger: {}", e),
  };

  pinger.add_ipaddr(&dst.to_string());
  pinger.ping_once();

  loop {
    match results.recv() {
      Ok(result) => match result {
        Idle { addr } => {
          println!("address {} did not respond! hooray!", addr);
          return false;
        }
        Receive { addr, .. } => {
          println!("address {} did respond! awwwww", addr);
          return true;
        }
      },
      Err(_) => panic!("Worker threads disconnected before the solution was found!"),
    }
  }
  */
}
