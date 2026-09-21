use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::thread;

pub const PIPE_NAME: &str = "firaw-ssh-bridge-v1.sock";

pub fn start<F>(handler: F)
where
    F: Fn(Value) -> Value + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    thread::spawn(move || {
        let Ok(name) = PIPE_NAME.to_ns_name::<GenericNamespaced>() else {
            return;
        };
        let Ok(listener) = ListenerOptions::new().name(name).create_sync() else {
            return;
        };
        for connection in listener.incoming().flatten() {
            let handler = Arc::clone(&handler);
            thread::spawn(move || handle_connection(connection, handler));
        }
    });
}

fn handle_connection<F>(mut connection: interprocess::local_socket::Stream, handler: Arc<F>)
where
    F: Fn(Value) -> Value,
{
    let mut line = String::new();
    let read = {
        let mut reader = BufReader::new(&mut connection);
        reader.read_line(&mut line)
    };
    let response = match read {
        Ok(0) => json!({"ok": false, "error": "empty_request"}),
        Ok(_) => match serde_json::from_str::<Value>(&line) {
            Ok(request) => handler(request),
            Err(error) => {
                json!({"ok": false, "error": "invalid_json", "message": error.to_string()})
            }
        },
        Err(error) => json!({"ok": false, "error": "read_failed", "message": error.to_string()}),
    };
    if let Ok(mut serialized) = serde_json::to_vec(&response) {
        serialized.push(b'\n');
        let _ = connection.write_all(&serialized);
        let _ = connection.flush();
    }
}
