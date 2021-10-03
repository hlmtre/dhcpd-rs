use std::net::Ipv4Addr;

/* icmp packet:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data ...
+-+-+-+-+-

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
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

tcpdump:

11:19:24.169673 IP 192.168.122.149 > 192.168.122.1: ICMP echo request, id 27041, seq 1, length 64
        0x0000:  4500 0054 e338 4000 4001 e188 c0a8 7a95  E..T.8@.@.....z.
        0x0010:  c0a8 7a01 0800 d263 69a1 0001 a5a2 5861  ..z....ci.....Xa
        0x0020:  0000 0000 f622 0900 0000 0000 1011 1213  ....."..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
11:19:24.169762 IP 192.168.122.1 > 192.168.122.149: ICMP echo reply, id 27041, seq 1, length 64
        0x0000:  4500 0054 d187 0000 4001 333a c0a8 7a01  E..T....@.3:..z.
        0x0010:  c0a8 7a95 0000 da63 69a1 0001 a5a2 5861  ..z....ci.....Xa
        0x0020:  0000 0000 f622 0900 0000 0000 1011 1213  ....."..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
*/
pub fn reachable(dst: Ipv4Addr) -> bool {
  use fastping_rs::PingResult::{Idle, Receive};
  use fastping_rs::Pinger;
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
}
