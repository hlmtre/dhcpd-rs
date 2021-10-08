use crate::ping::reachable;
use std::{collections::HashMap, net::Ipv4Addr, time::Duration, time::SystemTime};

#[derive(Debug, Clone)]
pub struct Pool {
  range: Vec<Ipv4Addr>,
  pub(crate) leases: HashMap<LeaseUnique, Lease>,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseUnique {
  pub(crate) ip: Ipv4Addr,
  pub(crate) hwaddr: Box<Vec<u8>>,
}

impl PartialEq for Lease {
  fn eq(&self, other: &Self) -> bool {
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
      leases: HashMap::new(),
      reservations: Vec::new(),
    }
  }

  pub(crate) fn prune_leases(&mut self) {
    let mut expired_leases: Vec<LeaseUnique> = Vec::new();
    for (k, l) in &self.leases {
      match l.lease_status() {
        LeaseStatus::Fresh => {}
        LeaseStatus::Expired => {
          expired_leases.push(k.clone());
        }
        LeaseStatus::Decaying => {}
      }
    }
    for position in expired_leases {
      println!("pruning lease {:?}", self.leases.get(&position));
      self.leases.remove(&position);
    }
  }

  pub(crate) fn allocate_address(
    &mut self,
    hwaddr: Vec<u8>,
    lease_len: u32,
    iface: &str,
    src_addr: Ipv4Addr,
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
    if reachable(src_addr, iface, ip) {
      println!("requested address {} already assigned!", ip);
      return Err(PoolError::RequestedAddressAlreadyAssigned);
    }
    let lease_timestamp = SystemTime::now();
    let l: Lease = Lease {
      ip,
      hwaddr: hwaddr.clone(),
      lease_timestamp,
      lease_len,
    };
    let k: LeaseUnique = LeaseUnique {
      ip,
      hwaddr: Box::new(hwaddr),
    };
    self.leases.insert(k, l.clone());
    Ok(l)
  }

  pub(crate) fn available(&self, src_addr: Ipv4Addr, i: Ipv4Addr, iface: &str) -> bool {
    if self.range.contains(&i) && !reachable(src_addr, iface, i) {
      return true;
    }
    false
  }

  pub(crate) fn update_lease(&mut self, hwaddr: Vec<u8>, lt: SystemTime) {
    self.leases.iter_mut().for_each(|(_, k)| {
      if k.hwaddr == hwaddr {
        k.update_lease(lt);
      }
    });
  }

  pub(crate) fn delete_lease(&mut self, ip: Ipv4Addr, hwaddr: Vec<u8>) -> Result<(), PoolError> {
    let lu = LeaseUnique {
      ip,
      hwaddr: Box::new(hwaddr),
    };
    match self.leases.remove(&lu) {
      Some(_) => return Ok(()),
      None => return Err(PoolError::RequestedAddressOutOfRange),
    }
  }

  pub(crate) fn ip_for_mac(&self, mac: Vec<u8>) -> Result<&Ipv4Addr, PoolError> {
    for (_, l) in self.leases.iter() {
      if l.hwaddr == mac {
        return Ok(&l.ip);
      }
    }
    return Err(PoolError::RequestedAddressAlreadyAssigned);
  }

  pub(crate) fn valid_lease(&self, a: Ipv4Addr) -> bool {
    for l in self.leases.values() {
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
