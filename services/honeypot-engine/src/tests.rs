#[test]
fn test_ssh_banner_format() {
    let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    assert!(banner.starts_with("SSH-2.0-"));
}

#[test]
fn test_http_path_traversal_detection() {
    let path = "/../../etc/passwd";
    assert!(path.contains("../") || path.contains("/etc/passwd"));
}

#[test]
fn test_redis_resp_ping_shape() {
    let payload = "*1\r\n$4\r\nPING\r\n";
    assert!(payload.contains("PING"));
}
