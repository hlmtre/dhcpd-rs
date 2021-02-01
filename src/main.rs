use std::net::UdpSocket;
use std::{io, net::Ipv4Addr, net::SocketAddr};

fn main() -> std::io::Result<()> {
  let mut socket = UdpSocket::bind("0.0.0.0:67")?;
  socket.set_nonblocking(true).unwrap();
  let _ = socket.set_broadcast(true);
  /* for future you edification:
  this is equivalent to vec![0, 64];
  creates an array of length 64 u8s and pre-sets each to 0
  */
  let mut buf = [0; 64];
  let mut src_addr: SocketAddr = "0.0.0.0:68".parse().unwrap();
  loop {
    match socket.recv_from(&mut buf) {
      Ok((l, n)) => {
        let filled_buf: &mut [u8] = &mut buf[..l];
        println!("{:02X?}", filled_buf);
        std::thread::sleep(std::time::Duration::from_millis(1000));
      }
      Err(_) => {}
    }
  }
  Ok(())
}
