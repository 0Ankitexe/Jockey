//! Until admission exists, every entry point fails closed without touching sources.
use jocky_native_linux::{BootstrapError, bootstrap};
use std::process::Command;

#[test]
fn library_is_explicitly_unavailable() {
    let expected = if cfg!(target_os = "linux") {
        BootstrapError::NotImplemented
    } else {
        BootstrapError::Unsupported
    };
    assert_eq!(bootstrap(), Err(expected));
}

#[test]
fn binary_rejects_even_apparent_live_opt_in() {
    for (args, expected_exit, expected_code) in [
        (vec![], 3, "InvalidInput"),
        (vec!["collect", "--allow-live-lab"], 3, "InvalidInput"),
        (vec!["__worker"], 4, "NotImplemented"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(if cfg!(target_os = "linux") {
                expected_exit
            } else {
                4
            })
        );
        assert!(result.stdout.is_empty());
        if cfg!(target_os = "linux") {
            let status: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
            assert_eq!(status["code"], expected_code);
            assert!(status.get("collection_id").is_none());
        } else {
            assert_eq!(result.stderr, b"Unsupported\n");
        }
    }
}

#[cfg(unix)]
#[test]
fn failed_error_delivery_is_not_an_unsupported_success() {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    let (closed, writer) = UnixStream::pair().unwrap();
    drop(closed);
    let mut result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .stderr(Stdio::from(OwnedFd::from(writer)))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut bytes = Vec::new();
    result
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.is_empty());
    assert_eq!(result.wait().unwrap().code(), Some(5));
}
