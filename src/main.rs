mod options;

use crate::options::DhcpMessage;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
  let socket = UdpSocket::bind("0.0.0.0:67")?;
  socket.set_nonblocking(true).unwrap();
  let _ = socket.set_broadcast(true);
  /* for future you edification:
  this is equivalent to vec![0, 64];
  creates an array of length 64 u8s and pre-sets each to 0
   */
  let mut buf = [0 as u8; 64];
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
        println!("would respond on {}", _n);
      }
      Err(_) => {}
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
  }
  Ok(())
}
