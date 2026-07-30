use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use rka_protocol::MAX_FRAME_BYTES;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::TlsError;

#[doc(hidden)]
pub trait TlsStream: Read + Write {
    fn socket(&self) -> &TcpStream;
}

impl TlsStream for StreamOwned<ClientConnection, TcpStream> {
    fn socket(&self) -> &TcpStream {
        &self.sock
    }
}

impl TlsStream for StreamOwned<ServerConnection, TcpStream> {
    fn socket(&self) -> &TcpStream {
        &self.sock
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct Deadline(Instant);

impl Deadline {
    #[doc(hidden)]
    pub fn new(budget: Duration) -> Result<Self, TlsError> {
        Instant::now()
            .checked_add(budget)
            .map(Self)
            .ok_or(TlsError::Deadline)
    }

    fn remaining(&self) -> Result<Duration, TlsError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TlsError::Deadline)
    }
}

#[doc(hidden)]
pub fn write_frame<S: TlsStream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: &Deadline,
) -> Result<(), TlsError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(TlsError::Frame);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| TlsError::Frame)?;
    set_timeout(stream.socket(), deadline)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .and_then(|()| stream.flush())
        .map_err(|error| map_io(&error))
}

#[doc(hidden)]
pub fn read_frame<S: TlsStream>(stream: &mut S, deadline: &Deadline) -> Result<Vec<u8>, TlsError> {
    let mut header = [0_u8; 4];
    set_timeout(stream.socket(), deadline)?;
    stream
        .read_exact(&mut header)
        .map_err(|error| map_io(&error))?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| TlsError::Frame)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TlsError::Frame);
    }
    let mut bytes = vec![0_u8; length];
    set_timeout(stream.socket(), deadline)?;
    stream
        .read_exact(&mut bytes)
        .map_err(|error| map_io(&error))?;
    Ok(bytes)
}

#[doc(hidden)]
pub fn set_timeout(socket: &TcpStream, deadline: &Deadline) -> Result<(), TlsError> {
    let remaining = deadline.remaining()?;
    socket
        .set_read_timeout(Some(remaining))
        .and_then(|()| socket.set_write_timeout(Some(remaining)))
        .map_err(|error| map_io(&error))
}

pub(crate) fn map_io(error: &std::io::Error) -> TlsError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        TlsError::Deadline
    } else {
        TlsError::Io
    }
}
