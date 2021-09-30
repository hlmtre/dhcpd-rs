use socket2::SockAddr;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
  ffi::CString,
  net::{Ipv4Addr, SocketAddr},
  thread,
};

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

07:00:07.090463 IP localhost > localhost: ICMP echo request, id 40234, seq 1, length 64
        0x0000:  4500 0054 d2f2 4000 4001 69b4 7f00 0001  E..T..@.@.i.....
        0x0010:  7f00 0001 0800 307c 9d2a 0001 e7c2 5561  ......0|.*....Ua
        0x0020:  0000 0000 2d61 0100 0000 0000 1011 1213  ....-a..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567
07:00:07.090483 IP localhost > localhost: ICMP echo reply, id 40234, seq 1, length 64
        0x0000:  4500 0054 d2f3 0000 4001 a9b3 7f00 0001  E..T....@.......
        0x0010:  7f00 0001 0000 387c 9d2a 0001 e7c2 5561  ......8|.*....Ua
        0x0020:  0000 0000 2d61 0100 0000 0000 1011 1213  ....-a..........
        0x0030:  1415 1617 1819 1a1b 1c1d 1e1f 2021 2223  .............!"#
        0x0040:  2425 2627 2829 2a2b 2c2d 2e2f 3031 3233  $%&'()*+,-./0123
        0x0050:  3435 3637                                4567

*/

pub fn reachable(iface: &String, listening_address: &SocketAddr, dst: Ipv4Addr) -> bool {
  // construct our own socket so we can ping from our own thread
  let socket = match Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())) {
    Ok(a) => a,
    _ => panic!("couldn't create socket :("),
  };
  socket
    .bind_device(Some(&CString::new(iface.clone()).unwrap()))
    .unwrap_or_else(|_| panic!("couldn't bind to {}", iface));
  socket
    .bind(&Into::<SockAddr>::into(*listening_address))
    .unwrap_or_else(|_| panic!("ping error: couldn't bind to {}", listening_address));
  let child = thread::spawn(move || {
    let mut buf = [0u8; 1500]; // standard packet size

    // first let's construct the ipv4 header
    let version_ihl_tos: u16 = 0x4500;
    eprintln!("{:?}", version_ihl_tos);
  });
  true
}
