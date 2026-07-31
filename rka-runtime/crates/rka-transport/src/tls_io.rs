use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use rka_protocol::MAX_FRAME_BYTES;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::TlsError;

#[doc(hidden)]
pub trait TlsStream {
    fn socket(&self) -> &TcpStream;
    fn read_once(&mut self, output: &mut [u8]) -> io::Result<usize>;
    fn write_once(&mut self, input: &[u8]) -> io::Result<usize>;
    fn wants_flush(&self) -> bool;
    fn flush_once(&mut self) -> io::Result<usize>;
}

impl TlsStream for StreamOwned<ClientConnection, TcpStream> {
    fn socket(&self) -> &TcpStream {
        &self.sock
    }

    fn read_once(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self.conn.reader().read(output) {
            Ok(length) if length > 0 => return Ok(length),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if self.conn.read_tls(&mut self.sock)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.conn
            .process_new_packets()
            .map_err(|_| io::Error::other("TLS processing failed"))?;
        match self.conn.reader().read(output) {
            Ok(0) => Err(io::Error::from(io::ErrorKind::Interrupted)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
            result => result,
        }
    }

    fn write_once(&mut self, input: &[u8]) -> io::Result<usize> {
        self.conn.writer().write(input)
    }

    fn wants_flush(&self) -> bool {
        self.conn.wants_write()
    }

    fn flush_once(&mut self) -> io::Result<usize> {
        self.conn.write_tls(&mut self.sock)
    }
}

impl TlsStream for StreamOwned<ServerConnection, TcpStream> {
    fn socket(&self) -> &TcpStream {
        &self.sock
    }

    fn read_once(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self.conn.reader().read(output) {
            Ok(length) if length > 0 => return Ok(length),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if self.conn.read_tls(&mut self.sock)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.conn
            .process_new_packets()
            .map_err(|_| io::Error::other("TLS processing failed"))?;
        match self.conn.reader().read(output) {
            Ok(0) => Err(io::Error::from(io::ErrorKind::Interrupted)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
            result => result,
        }
    }

    fn write_once(&mut self, input: &[u8]) -> io::Result<usize> {
        self.conn.writer().write(input)
    }

    fn wants_flush(&self) -> bool {
        self.conn.wants_write()
    }

    fn flush_once(&mut self) -> io::Result<usize> {
        self.conn.write_tls(&mut self.sock)
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

    pub(crate) fn remaining(&self) -> Result<Duration, TlsError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TlsError::Deadline)
    }

    pub(crate) fn check(&self) -> Result<(), TlsError> {
        self.remaining().map(|_| ())
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
    write_bytes(stream, &length.to_be_bytes(), deadline)?;
    write_bytes(stream, bytes, deadline)?;
    flush_bytes(stream, deadline)
}

#[doc(hidden)]
pub fn read_frame<S: TlsStream>(stream: &mut S, deadline: &Deadline) -> Result<Vec<u8>, TlsError> {
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| TlsError::Frame)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TlsError::Frame);
    }
    let mut bytes = vec![0_u8; length];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

#[doc(hidden)]
pub fn read_exact<S: TlsStream>(
    stream: &mut S,
    mut output: &mut [u8],
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while !output.is_empty() {
        flush_bytes(stream, deadline)?;
        set_timeout(stream.socket(), deadline)?;
        let length = match stream.read_once(output) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                deadline.check()?;
                continue;
            }
            result => result.map_err(|error| map_io(&error))?,
        };
        deadline.check()?;
        if length == 0 {
            return Err(TlsError::Io);
        }
        output = output.get_mut(length..).ok_or(TlsError::Io)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn write_bytes<S: TlsStream>(
    stream: &mut S,
    mut input: &[u8],
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while !input.is_empty() {
        set_timeout(stream.socket(), deadline)?;
        let length = stream.write_once(input).map_err(|error| map_io(&error))?;
        deadline.check()?;
        if length == 0 {
            return Err(TlsError::Io);
        }
        input = input.get(length..).ok_or(TlsError::Io)?;
        flush_bytes(stream, deadline)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn flush_bytes<S: TlsStream>(stream: &mut S, deadline: &Deadline) -> Result<(), TlsError> {
    while stream.wants_flush() {
        set_timeout(stream.socket(), deadline)?;
        let length = stream.flush_once().map_err(|error| map_io(&error))?;
        deadline.check()?;
        if length == 0 {
            return Err(TlsError::Io);
        }
    }
    Ok(())
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
