//! Bootstrap only: no implemented command can collect or claim a successful result.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let args: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|arg| arg.into_string())
            .collect::<Result<_, _>>()
            .unwrap_or_default();
        if args.as_slice() == ["__worker"]
            && let Some(exit) = jocky_native_linux::private_worker_entry()
        {
            return ExitCode::from(exit);
        }
        let reply = jocky_native_linux::cli::status::run(&args);
        let delivered = if reply.stderr {
            std::io::stderr().lock().write_all(&reply.bytes)
        } else {
            std::io::stdout().lock().write_all(&reply.bytes)
        };
        ExitCode::from(if delivered.is_ok() { reply.exit } else { 5 })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let code = match jocky_native_linux::bootstrap() {
            Err(jocky_native_linux::BootstrapError::NotImplemented) => "NotImplemented\n",
            Err(jocky_native_linux::BootstrapError::Unsupported) => "Unsupported\n",
            Ok(()) => return ExitCode::from(5),
        };
        if std::io::stderr().lock().write_all(code.as_bytes()).is_err() {
            return ExitCode::from(5);
        }
        ExitCode::from(4)
    }
}
