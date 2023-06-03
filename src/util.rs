pub(crate) fn format_mac(mac: &[u8]) -> String {
  format!(
    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
  )
}
