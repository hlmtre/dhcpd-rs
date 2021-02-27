use std::{net::Ipv4Addr, time::Duration, time::SystemTime};

#[derive(Debug, Clone)]
pub struct Pool {
  range: Vec<Ipv4Addr>,
  pub(crate) leases: Vec<Lease>,
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

#[derive(Debug, PartialEq, Eq)]
pub enum LeaseStatus {
  Fresh,
  Expired,
  Decaying,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum PoolError {
  PoolExhausted,
  RequestedAddressOutOfRange,
  RequestedAddressAlreadyAssigned,
}

impl PartialEq for Lease {
  fn eq(&self, other: &Self) -> bool {
    println!(
      "comparing {} to {} and {:02x?} to {:02x?}",
      self.ip, other.ip, self.hwaddr, other.hwaddr,
    );
    if self.ip == other.ip && self.hwaddr == other.hwaddr {
      return true;
    }
    return false;
  }
}

impl Lease {
  pub(crate) fn lease_status(&self) -> LeaseStatus {
    if self.lease_timestamp.elapsed().unwrap() > Duration::from_secs(self.lease_len.into()) {
      return LeaseStatus::Expired;
    } else if self.lease_timestamp.elapsed().unwrap()
      < Duration::from_secs((self.lease_len / 2).into())
    {
      return LeaseStatus::Fresh;
    } else {
      return LeaseStatus::Decaying;
    }
  }

  pub(crate) fn update_lease(&mut self, lt: SystemTime) {
    self.lease_timestamp = lt;
  }
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
    if self.range.len() < 1 {
      return Err(PoolError::PoolExhausted);
    }
    let i = self.range.pop();
    let ip = match i {
      Some(x) => x,
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

  pub(crate) fn available(&self, i: Ipv4Addr) -> bool {
    if self.range.contains(&i) {
      return true;
    }
    false
  }

  pub(crate) fn delete_lease(&mut self, a: Ipv4Addr) -> Result<(), PoolError> {
    let mut i: usize = 0;
    let mut in_leases: bool = false;
    for l in self.leases.iter() {
      if l.ip == a {
        in_leases = true;
        break;
      }
      i += 1;
    }
    self.leases.remove(i);
    if in_leases {
      ()
    }
    Err(PoolError::RequestedAddressOutOfRange)
  }

  pub(crate) fn ip_for_mac(&self, mac: Vec<u8>) -> Result<Ipv4Addr, PoolError> {
    for l in self.leases.iter() {
      if l.hwaddr == mac {
        return Ok(l.ip.clone());
      }
    }
    return Err(PoolError::RequestedAddressAlreadyAssigned);
  }

  pub(crate) fn valid_lease(&self, a: Ipv4Addr) -> bool {
    for l in self.leases.iter() {
      if l.ip == a {
        if l.lease_status() != LeaseStatus::Expired {
          return true;
        }
      }
    }
    false
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
