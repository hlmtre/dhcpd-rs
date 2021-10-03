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
// TODO
// modify the ICMP packet's src and dst fields
// so .. they're actually ours, instead of this one stolen from rust-rawsock
const ICMP_PACKET: [u8; 84] = [
  0x45, 0x00, 0x00, 0x54, 0xee, 0x96, 0x40, 0x00, 0x40, 0x01, 0x79, 0xf0, 0xc0, 0xa8, 0x01, 0x6a,
  0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x2f, 0x08, 0x66, 0xc2, 0x00, 0x12, 0x82, 0xaa, 0xcc, 0x5c,
  0x00, 0x00, 0x00, 0x00, 0x51, 0x49, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37,
];

// indices of the chunks of data in the packet, by byte
enum DataIndex {
  IpType_HeaderLen = 0,
  TOS = 1,
  TotalLen = 3,
  Identification = 5,
  Flags_FragmentOffset = 7,
  TTL = 9,
  Protocol = 10,
  HeaderChecksum = 11,
  SrcAddress = 13,
  DstAddress = 17,
  Options = 21,
}

// modify the icmp packet in place
// with the updated dst IP
fn replace_region(target_arr: &mut Vec<u8>, src_arr: &[u8], index: usize) {
  for counter in 0..src_arr.len() {
    target_arr[index + counter] = src_arr[counter];
  }
}

pub fn reachable(iface: &String, dst: Ipv4Addr) -> bool {
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
          //error!("Idle Address {}.", addr);
          println!("address {} did not respond! hooray!", addr);
          return false;
        }
        Receive { addr, .. } => {
          //info!("Receive from Address {} in {:?}.", addr, rtt);
          println!("address {} did respond! awwwww", addr);
          return true;
        }
      },
      Err(_) => panic!("Worker threads disconnected before the solution was found!"),
    }
  }
  //println!("{:?}", a);
  // ye olde doublefork
  /*
  let _ = std::thread::spawn(move || {
    let _ = std::thread::spawn(move || {
      /*
      //send some packets
      println!("Sending 5 packets:");
      for i in 0..5 {
        println!("Sending ICMP ping packet no {}", i);
        interf.send(&ICMP_PACKET).expect("Could not send packet");
      }
      */

      /*
       * first let's construct the ipv4 header
       * 0x4 is the ip type (ipv4)
       * 0x5 is the IHL - internet header length. 5, in this case, times 32-bit words
       *   Internet Header Length (IHL)
       *   |
       *   --> The IHL field is used to specify the total length of the header and is represented in 32 bit words.
       *       The minimum valid value for the IHL field is 5 (5 x 32 = 160 bits) which accounts for the Version, IHL,
       *       TOS, Length, Identification, Flags, Fragment Offset, TTL, Protocol, Checksum, and
       *       the Source and Destination Addresses, which are all mandatory.
       */
      let mut our_icmp_packet = ICMP_PACKET.clone();
      // first set the dst address in our packet
      // rawsock interface sending sets our src address for us, it appears
      replace_region(
        &mut our_icmp_packet.to_vec(),
        &d.octets(),
        DataIndex::DstAddress as usize,
      );
      let lib = open_best_library().expect("Could not open any packet capturing library");
      let interf_name = i.as_str();
      let mut interf = lib
        .open_interface(&interf_name)
        .expect("Could not open network interface");
      println!("pinging {} on {}... ", &d, &interf_name);
      crossbeam::thread::scope(|s| {
        s.spawn(|_| {
          interf
            .loop_infinite_dyn(&|packet| {
              println!("Received packet: {}", packet);
            })
            .expect("Error when running receiving loop");
        });
      })
      .unwrap();
      for _ in 0..3 {
        interf
          .send(&our_icmp_packet)
          .expect("couldn't send packet :(");
      }
      // receive our echo replies
      for _ in 0..5 {
        let packet = interf.receive().expect("couldn't receive packet :(");
        println!("received packet: {}", packet);
      }
    });
  });
      */
}
