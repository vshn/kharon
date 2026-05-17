function FindProxyForURL(url, host) {
  // Allow direct access to the vshn.net sign-in page and the Lieutenant API
  // Fallback in case the proxy is not available due to incompatible or corrupted jumphost
  // mapping rules.
  if (shExpMatch(host, "*.vshn.net")) {
    return "DIRECT";
  }
  return "SOCKS5 localhost:12000";
}
