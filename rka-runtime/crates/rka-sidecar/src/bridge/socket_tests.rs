use std::{
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket,
    sockopt::set_socket_send_buffer_size,
};

use super::{
    BridgeError, BridgeMessage, ExchangeRole, NetworkHandle, PublicBytes, RequestId,
    deadline::{Control, Deadline},
    encode_frame,
    socket::{accept_peer, connect_path, read_message, write_message},
};

fn deadline(duration: Duration) -> Result<Deadline, BridgeError> {
    Deadline::new(duration, Control::new()?)
}

struct SocketPath(PathBuf);

impl SocketPath {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!("rka-task8-socket-{name}-{}", std::process::id())))
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

#[test]
fn blocked_accept_uses_absolute_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let path = SocketPath::new("accept");
    let listener = UnixListener::bind(&path.0)?;
    let started = Instant::now();
    assert!(matches!(
        accept_peer(&listener, &deadline(Duration::from_millis(20))?),
        Err(BridgeError::Deadline)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn blocked_connect_checks_completion_and_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let path = SocketPath::new("connect");
    let descriptor = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    bind(&descriptor, &SocketAddrUnix::new(&path.0)?)?;
    listen(&descriptor, 0)?;
    let listener = UnixListener::from(descriptor);
    let mut connected = Vec::new();
    let started = Instant::now();
    let terminal = loop {
        match connect_path(&path.0, &deadline(Duration::from_millis(20))?) {
            Ok(stream) => connected.push(stream),
            Err(error) => break error,
        }
        if connected.len() > 8 {
            return Err("Unix backlog did not saturate".into());
        }
    };
    assert_eq!(terminal, BridgeError::Deadline);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(listener);
    Ok(())
}

#[test]
fn blocked_read_wakes_on_deadline_and_close() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, _writer) = UnixStream::pair()?;
    let control = Control::new()?;
    control.attach(&reader)?;
    let deadline = Deadline::new(Duration::from_millis(20), Arc::clone(&control))?;
    assert_eq!(
        read_message(&reader, ExchangeRole::DonorResponse, &deadline),
        Err(BridgeError::Deadline)
    );
    let (reader, _writer) = UnixStream::pair()?;
    let control = Control::new()?;
    control.attach(&reader)?;
    let closer = Arc::clone(&control);
    let worker = thread::spawn(move || {
        read_message(
            &reader,
            ExchangeRole::DonorResponse,
            &Deadline::new(Duration::from_secs(1), control)?,
        )
    });
    closer.close();
    assert!(
        worker
            .join()
            .is_ok_and(|result| result == Err(BridgeError::PeerDied))
    );
    Ok(())
}

#[test]
fn blocked_write_returns_and_wipes_frame() -> Result<(), Box<dyn std::error::Error>> {
    let (writer, _reader) = UnixStream::pair()?;
    writer.set_nonblocking(true)?;
    set_socket_send_buffer_size(&writer, 1024)?;
    let certificates = (0..10)
        .map(|_| PublicBytes::bounded(&vec![7; 64 * 1024], 1, 64 * 1024))
        .collect::<Result<Vec<_>, _>>()?;
    let message = BridgeMessage::PublicResult(
        RequestId::new(1),
        NetworkHandle::new([1; 16]),
        PublicBytes::bounded(&[2], 1, 1)?,
        certificates,
    );
    let frame = encode_frame(&message, ExchangeRole::DonorResponse)?;
    let started = Instant::now();
    assert_eq!(
        write_message(&writer, &frame, &deadline(Duration::from_millis(20))?),
        Err(BridgeError::Deadline)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn one_deadline_is_not_reset_between_phases() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = UnixStream::pair()?;
    let deadline = deadline(Duration::from_millis(30))?;
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        let _first = std::io::Write::write_all(&mut writer, &[1]);
        thread::sleep(Duration::from_millis(20));
        let _second = std::io::Write::write_all(&mut writer, &[2]);
    });
    let mut byte = [0_u8; 1];
    super::socket::read_exact(&reader, &mut byte, &deadline)?;
    assert_eq!(
        super::socket::read_exact(&reader, &mut byte, &deadline),
        Err(BridgeError::Deadline)
    );
    assert!(sender.join().is_ok());
    Ok(())
}
