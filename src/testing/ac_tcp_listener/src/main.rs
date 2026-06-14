// Minimal listener for AC<->AC arbitration testing. Binds to
// 127.0.0.1:<port>, accepts one connection, sends an HTTP/1.1 200
// response with a fixed body, and exits. Designed to run inside an
// AppContainer launched by wxc-exec.

use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(19443);
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("ac-tcp-listener: bound 127.0.0.1:{port}");

    listener.set_nonblocking(false)?;
    // Stop ourselves after 30s so wxc-exec's timeout always wins.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        std::process::exit(0);
    });

    let (mut sock, peer) = listener.accept()?;
    eprintln!("ac-tcp-listener: accepted from {peer}");
    let body = b"OK\n";
    let mut resp = Vec::new();
    write!(
        &mut resp,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    resp.extend_from_slice(body);
    sock.write_all(&resp)?;
    sock.flush()?;
    Ok(())
}
