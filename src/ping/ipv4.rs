#![allow(dead_code)]
use crate::ping::replace_region;
use crate::ping::IcmpPacketDataIndex;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Ipv4IcmpPacket {
  pub version: u8, // really a nibble - most significant half of first byte
  pub ihl: u8,     // really a nibble - second half of first byte
  pub src_address: Ipv4Addr,
  pub dst_address: Ipv4Addr,
  pub ttl: u8,
  pub protocol: u8,
  pub ipv4_checksum: u16,
  pub icmp_type: u8,
  pub icmp_code: u8,
  pub icmp_checksum: u16,
  pub identifier: u16,
  pub sequence_number: u16,
  pub raw_rep: Vec<u8>,
}

impl fmt::Display for Ipv4IcmpPacket {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "
      Ipv4IcmpPacket
      ===============
       version       {}
       header len    {}
       src address   {}
       dst address   {}
       ttl           {}
       protocol      {}
       ipv4 checksum {}
       raw representation
         {:x?}",
      self.version,
      self.ihl,
      self.src_address,
      self.dst_address,
      self.ttl,
      self.protocol,
      self.ipv4_checksum,
      self.raw_rep
    )
  }
}

impl Ipv4IcmpPacket {
  pub fn new(buf: &[u8]) -> Ipv4IcmpPacket {
    let (v, l) = Ipv4IcmpPacket::get_version_ihl(buf[Ipv4DataIndex::IpType_HeaderLen as usize]);
    let mut raw = Vec::new();
    for e in buf {
      raw.push(*e);
    }
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
      ttl: 64,
      protocol: *Ipv4IcmpPacket::retrieve_bytes(buf, 1, Ipv4DataIndex::Protocol as usize)
        .get(0)
        .unwrap(),
      // the ipv4 header is 5x32-bits long - 20 bytes .. well, normally. perhaps TODO
      // start as zero, we calculate the checksum after the data's been sent
      ipv4_checksum: 0,
      icmp_type: 0,
      icmp_code: 8,
      icmp_checksum: 0,
      identifier: 0,
      sequence_number: 0,
      raw_rep: raw,
    }
  }

  fn set_ipv4_checksum(&mut self, checksum: u16) {
    replace_region(
      &mut self.raw_rep,
      &checksum.to_be_bytes(),
      Ipv4DataIndex::HeaderChecksum as usize,
    );
    self.ipv4_checksum = checksum;
  }

  fn set_icmp_checksum(&mut self, checksum: u16) {
    replace_region(
      &mut self.raw_rep,
      &checksum.to_be_bytes(),
      IcmpPacketDataIndex::Checksum as usize,
    );
    self.icmp_checksum = checksum;
  }

  fn set_src_ip(&mut self, src: Ipv4Addr) {
    replace_region(
      &mut self.raw_rep,
      &src.octets(),
      Ipv4DataIndex::SrcAddress as usize,
    );
  }

  fn set_dst_ip(&mut self, dst: Ipv4Addr) {
    replace_region(
      &mut self.raw_rep,
      &dst.octets(),
      Ipv4DataIndex::DstAddress as usize,
    );
  }

  #[inline(always)]
  fn get_version_ihl(byte: u8) -> (u8, u8) {
    // zero out the last four bytes, then shift all to the right
    // this: 1010 1010 -> 1010 0000, then 0000 1010
    let version = (byte & 0xf0) >> 4;
    // zero out the FIRST four bytes (no shifting needed - already least significant bits)
    // 1010 1010 -> 0000 1010 - done
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
