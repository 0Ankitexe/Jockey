//! Owned offline signal test. Signals target only this test's child process.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../src/worker/signals.rs"]
mod signals;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("WorkerSignalsUnsupported");
}

#[cfg(target_os = "linux")]
fn main() {
    use rustix::process::{Pid, Signal, kill_process};
    use std::{
        io::{BufRead, BufReader, Write},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if std::env::args().nth(1).as_deref() == Some("--watch") {
        let expect_interrupt = std::env::args().nth(2).as_deref() == Some("int");
        let watch = signals::SignalWatch::start().unwrap();
        println!("ready");
        std::io::stdout().flush().unwrap();
        let began = Instant::now();
        while !watch.cancelled() {
            assert!(began.elapsed() < Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(watch.interrupted(), expect_interrupt);
        assert_eq!(signals::was_interrupted(), expect_interrupt);
        println!("cancelled");
        return;
    }
    for signal in [Signal::INT, Signal::TERM] {
        let (parent, child_out) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--watch")
            .arg(if signal == Signal::INT { "int" } else { "term" })
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(child_out)))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(parent);
        let mut ready = String::new();
        lines.read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        kill_process(Pid::from_raw(child.id() as i32).unwrap(), signal).unwrap();
        let mut reply = String::new();
        lines.read_line(&mut reply).unwrap();
        assert_eq!(reply, "cancelled\n");
        let began = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(began.elapsed() < Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    println!("WorkerSignalsPassed: owned SIGINT and SIGTERM cancellation");
}
