extern crate packet;

use std::net::UdpSocket;
use std::{io, net::Ipv4Addr, net::SocketAddr};

fn main() -> std::io::Result<()> {
  let mut socket = UdpSocket::bind("255.255.255.255:67")?;
  socket.set_nonblocking(true).unwrap();
  //let _ = socket.set_broadcast(true);
  let mut buf = [0; 128];
  let mut src_addr: SocketAddr = "0.0.0.0:68".parse().unwrap();
  loop {
    let (num_bytes_read, _) = loop {
      match socket.recv_from(&mut buf) {
        Ok(n) => break n,
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
          // wait until network socket is ready, typically implemented
          // via platform-specific APIs such as epoll or IOCP
          std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err(e) => panic!("IO ERROR {}", e),
      }
    };
    let filled_buf = &mut buf[..num_bytes_read];
    eprintln!("{:#?}, {:#?}", filled_buf, src_addr);
    std::thread::sleep(std::time::Duration::from_millis(1000));
  }
  Ok(())
}
