use anyhow::Result;
use crossbeam_channel::{bounded, Sender};
use std::io::Write;
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs::File,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};



pub(crate) struct HookLogger {
    tx: Arc<Sender<String>>,
    shutdown: Arc<AtomicBool>,
}

impl HookLogger {
    pub(crate) fn new(path: String) -> Result<Self> {
        let (tx, rx) = bounded::<String>(1000);
        let mut storage = File::create(path)?;
        let shutdown = Arc::new(AtomicBool::new(true));
        let shutdown_clone = Arc::clone(&shutdown);

        thread::spawn(move || {
            while shutdown_clone.load(Ordering::Relaxed) {
                if let Ok(s) = rx.recv_timeout(Duration::from_millis(100)) {
                    if let Err(e) = writeln!(&mut storage, "{}", s) {
                        eprintln!("Writer error: {e}");
                    }
                }
                sleep(Duration::from_millis(200))
            }
        });
        Ok(Self { tx: Arc::new(tx), shutdown })
    }

    pub(crate) fn append(&self) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let s = format!("{:?}", timestamp);
        
        if let Err(e) = self.tx.send(s) {
            eprintln!("Send error: {e}")
        }
    }
}

impl Drop for HookLogger {
    fn drop(&mut self) {
        self.shutdown.store(false, Ordering::Relaxed);
    }
}
