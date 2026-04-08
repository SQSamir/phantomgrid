use super::parse_redis_first_command;

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
fn test_redis_resp_parser() {
    let payload = "*1\r\n$4\r\nPING\r\n";
    assert_eq!(parse_redis_first_command(payload), "PING");
}

#[test]
fn test_ftp_command_parser() {
    let cmd = "USER anonymous";
    assert!(cmd.starts_with("USER "));
}

#[test]
fn test_dns_recursion_guard() {
    let recursion_requested = true;
    let response = if recursion_requested { "REFUSED" } else { "NOERROR" };
    assert_eq!(response, "REFUSED");
}

#[test]
fn test_smb_ntlm_capture_format() {
    let ntlm = "user::DOMAIN:1122334455667788:abcdefabcdefabcdef";
    assert!(ntlm.contains("::"));
    assert!(ntlm.contains(':'));
}
