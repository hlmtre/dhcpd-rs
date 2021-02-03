pub(crate) fn format_mac(macvec: Vec<u8>) -> String {
  format!(
    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    macvec[0], macvec[1], macvec[2], macvec[3], macvec[4], macvec[5]
  )
}
