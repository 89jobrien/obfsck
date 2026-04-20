//! Conformance tests: LogClient port boundary.
//!
//! LogClient has no public production adapter, so we verify the trait is
//! object-safe by implementing a minimal mock.

use obfsck::ports::{LogClient, LogEntry};
use std::sync::{Arc, Mutex};

// --- Mock adapter -----------------------------------------------------------

struct MockLogClient {
    entries: Arc<Mutex<Vec<String>>>,
}

impl MockLogClient {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let store = Arc::new(Mutex::new(Vec::new()));
        (Self { entries: Arc::clone(&store) }, store)
    }
}

impl LogClient for MockLogClient {
    fn send(&self, entry: &LogEntry) -> obfsck::ports::Result<()> {
        self.entries.lock().unwrap().push(entry.message.clone());
        Ok(())
    }
}

// Trait object safety.
#[test]
fn log_client_is_object_safe() {
    let (mock, _store) = MockLogClient::new();
    let _dyn_ref: &dyn LogClient = &mock;
}

// Contract: send() delivers the entry message.
#[test]
fn mock_log_client_delivers_entry() {
    let (mock, store) = MockLogClient::new();
    let entry = LogEntry { message: "hello world".to_string() };
    mock.send(&entry).expect("send must succeed");
    let captured = store.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], "hello world");
}

// Contract: multiple sends accumulate in order.
#[test]
fn mock_log_client_accumulates_entries() {
    let (mock, store) = MockLogClient::new();
    for i in 0..5u32 {
        let entry = LogEntry { message: format!("msg-{i}") };
        mock.send(&entry).unwrap();
    }
    let captured = store.lock().unwrap();
    assert_eq!(captured.len(), 5);
    for i in 0..5usize {
        assert_eq!(captured[i], format!("msg-{i}"));
    }
}

// Trait requires Send + Sync — mock must satisfy those bounds.
#[test]
fn log_client_send_sync_bounds() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockLogClient>();
}

// dyn LogClient can be boxed and sent across threads.
#[test]
fn log_client_boxed_dyn_is_send() {
    let (mock, store) = MockLogClient::new();
    let boxed: Box<dyn LogClient> = Box::new(mock);
    let handle = std::thread::spawn(move || {
        let entry = LogEntry { message: "from thread".to_string() };
        boxed.send(&entry).unwrap();
    });
    handle.join().unwrap();
    let captured = store.lock().unwrap();
    assert_eq!(captured[0], "from thread");
}
