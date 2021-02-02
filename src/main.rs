mod options;

use crate::options::DhcpMessage;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
  let mut socket = UdpSocket::bind("0.0.0.0:67")?;
  socket.set_nonblocking(true).unwrap();
  let _ = socket.set_broadcast(true);
  /* for future you edification:
  this is equivalent to vec![0, 64];
  creates an array of length 64 u8s and pre-sets each to 0
   */
  let mut buf = [0 as u8; 64];
  loop {
    match socket.recv_from(&mut buf) {
      Ok((l, n)) => {
        let mut d: DhcpMessage = DhcpMessage::default();
        let filled_buf: &mut [u8] = &mut buf[..l];
        d.parse(filled_buf);
        println!("received bytes {:02X?} from {:#?}", filled_buf, n);
        eprintln!("{:02X?}", d);
        std::thread::sleep(std::time::Duration::from_millis(1000));
      }
      Err(_) => {}
    }
  }
  Ok(())
}
