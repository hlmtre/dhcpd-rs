use std::convert::TryInto;
use std::io::prelude::*;
use std::{fs::File, net::Ipv4Addr};

#[derive(Debug)]
pub struct MacAddress {
  pub bytes: Vec<u8>,
}

// /proc/net/arp looks like this:
/*
 * IP address       HW type     Flags       HW address            Mask     Device
 * 192.168.122.147  0x1         0x0         00:00:00:00:00:00     *        ens19
 * 192.168.122.149  0x1         0x0         52:4a:15:0e:fd:42     *        ens19
 * 192.168.122.148  0x1         0x0         00:00:00:00:00:00     *        ens19
 * 192.168.122.150  0x1         0x2         52:4a:15:0e:fd:42     *        ens19
 */

pub fn get_mac_for_ip(i: Ipv4Addr) -> MacAddress {
  let mut f = File::open("/proc/net/arp").unwrap();
  let mut contents = String::new();
  let _ = f.read_to_string(&mut contents);
  let mut v: Vec<u8> = Vec::new();
  for line in contents.split('\n') {
    if line.starts_with(&i.to_string()) {
      let mut parts = line.split(' ').collect::<Vec<&str>>();
      parts.retain(|l| !l.is_empty());
      let a = parts[3];
      // it's always gonna be valid from /proc/net/arp
      // i mean
      // right?
      a.split(':')
        .for_each(|x| v.push(usize::from_str_radix(x, 16).unwrap().try_into().unwrap()));
      let m = MacAddress { bytes: v };
      return m;
    }
  }
  let m = MacAddress {
    bytes: [0, 0, 0, 0, 0, 0].to_vec(),
  };
  return m;
}
