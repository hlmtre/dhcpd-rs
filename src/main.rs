mod options;

use crate::options::DhcpMessage;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
  let socket = UdpSocket::bind("0.0.0.0:67")?;
  socket.set_nonblocking(true).unwrap();
  let _ = socket.set_broadcast(true);
  /*
  The 'options' field is now variable length. A DHCP client must be
  prepared to receive DHCP messages with an 'options' field of at least
  length 312 octets.  This requirement implies that a DHCP client must
  be prepared to receive a message of up to 576 octets, the minimum IP
  datagram size an IP host must be prepared to accept [3].  DHCP
  clients may negotiate the use of larger DHCP messages through the
  'maximum DHCP message size' option.  The options field may be further
  extended into the 'file' and 'sname' fields.

  this is equivalent to vec![0, 64];
  creates an array of length 64 u8s and pre-sets each to 0
  */
  let mut buf = [0 as u8; 576];
  loop {
    match socket.recv_from(&mut buf) {
      Ok((l, _n)) => {
        let mut d: DhcpMessage = DhcpMessage::default();
        let filled_buf: &mut [u8] = &mut buf[..l];
        d.parse(filled_buf);
        println!(
          "received bytes {:02X?} from {:02x?}",
          filled_buf,
          d.format_mac()
        );
        println!("DhcpMessage: {}", d);
        let magic_cookie_index = d.get_options_index(filled_buf);
        println!("magic cookie index: {}", magic_cookie_index);
        println!("would respond on {}", _n);
      }
      Err(_) => {}
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
  }
  Ok(())
}
