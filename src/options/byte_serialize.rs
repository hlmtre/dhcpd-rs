pub(crate) trait BEByteSerializable {
  fn to_be_bytes(&self, vec: &mut Vec<u8>);
}

impl BEByteSerializable for u32 {
  fn to_be_bytes(&self, vec: &mut Vec<u8>) {
    for b in &u32::to_be_bytes(*self) {
      vec.push(*b);
    }
  }
}

impl BEByteSerializable for u16 {
  fn to_be_bytes(&self, vec: &mut Vec<u8>) {
    for b in &u16::to_be_bytes(*self) {
      vec.push(*b);
    }
  }
}

impl BEByteSerializable for u64 {
  fn to_be_bytes(&self, vec: &mut Vec<u8>) {
    for b in &u64::to_be_bytes(*self) {
      vec.push(*b);
    }
  }
}

impl BEByteSerializable for u128 {
  fn to_be_bytes(&self, vec: &mut Vec<u8>) {
    for b in &u128::to_be_bytes(*self) {
      vec.push(*b);
    }
  }
}
