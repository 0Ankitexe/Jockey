//! Local process cancellation for the standalone collector parent. Tokio owns
//! the signal registrations; no project signal handler or unsafe code is used.
use jocky_shared::collection::Code;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn was_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub(crate) struct SignalWatch {
    cancelled: Arc<AtomicBool>,
    interrupted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SignalWatch {
    pub fn start() -> Result<Self, Code> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let interrupted = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let signal = cancelled.clone();
        let interrupt_flag = interrupted.clone();
        let ending = stop.clone();
        let thread = thread::Builder::new()
            .name("jocky-signal-watch".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| Code::Unsupported)?;
                    let _entered = runtime.enter();
                    let mut interrupt =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                            .map_err(|_| Code::Unsupported)?;
                    let mut terminate =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .map_err(|_| Code::Unsupported)?;
                    ready_tx.send(Ok(())).map_err(|_| Code::WorkerFailed)?;
                    runtime.block_on(async {
                        loop {
                            if tokio::time::timeout(Duration::from_millis(20), interrupt.recv())
                                .await
                                .is_ok()
                            {
                                interrupt_flag.store(true, Ordering::SeqCst);
                                INTERRUPTED.store(true, Ordering::SeqCst);
                                signal.store(true, Ordering::SeqCst);
                            }
                            if tokio::time::timeout(Duration::from_millis(20), terminate.recv())
                                .await
                                .is_ok()
                            {
                                signal.store(true, Ordering::SeqCst);
                            }
                            if ending.load(Ordering::SeqCst) {
                                break;
                            }
                        }
                    });
                    Ok::<(), Code>(())
                })();
                if let Err(code) = result {
                    let _ = ready_tx.send(Err(code));
                }
            })
            .map_err(|_| Code::ResourceLimit)?;
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or(Err(Code::WorkerFailed));
        if let Err(code) = ready {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
            return Err(code);
        }
        Ok(Self {
            cancelled,
            interrupted,
            stop,
            thread: Some(thread),
        })
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    pub fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

impl jocky_forensic::collection::cancellation::Cancellation for SignalWatch {
    fn cancelled(&self) -> bool {
        self.cancelled()
    }
}

impl Drop for SignalWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
