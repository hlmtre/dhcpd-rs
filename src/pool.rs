use std::{net::Ipv4Addr, time::SystemTime};

#[derive(Debug, Clone)]
pub struct Pool {
  range: Vec<Ipv4Addr>,
  leases: Vec<Lease>,
  exclusions: Vec<Ipv4Addr>,
  reservations: Vec<Lease>,
}

#[derive(Debug, Clone)]
pub struct Lease {
  pub ip: Ipv4Addr,
  pub hwaddr: Vec<u8>,
  pub lease_timestamp: SystemTime,
  pub lease_len: u32,
}

#[derive(Debug, Clone)]
pub enum PoolError {
  PoolExhausted,
  RequestedAddressOutOfRange,
  RequestedAddressAlreadyAssigned,
}

impl Pool {
  pub fn new(s: Ipv4Addr, e: Ipv4Addr) -> Self {
    Pool {
      range: Self::enumerate_range(s, e),
      exclusions: Vec::new(),
      leases: Vec::new(),
      reservations: Vec::new(),
    }
  }

  pub(crate) fn allocate_address(
    &mut self,
    hwaddr: Vec<u8>,
    lease_len: u32,
  ) -> Result<Lease, PoolError> {
    let ip: Ipv4Addr = match self.range.pop() {
      Some(i) => i,
      None => {
        return Err(PoolError::PoolExhausted);
      }
    };
    let lease_timestamp = SystemTime::now();
    let l: Lease = Lease {
      ip,
      hwaddr,
      lease_timestamp,
      lease_len,
    };
    self.leases.push(l.clone());
    Ok(l)
  }

  fn enumerate_range(s: Ipv4Addr, e: Ipv4Addr) -> Vec<Ipv4Addr> {
    let high_end = e.octets()[3];
    let low_end = s.octets()[3];
    let mut a = Vec::<Ipv4Addr>::new();
    for i in low_end..=high_end {
      a.push(Ipv4Addr::new(
        e.octets()[0],
        e.octets()[1],
        e.octets()[2],
        i,
      ));
    }
    return a;
  }
}
