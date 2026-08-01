use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use rka_protocol::MAX_FRAME_BYTES;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::TlsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchWriteError {
    PreDispatch(TlsError),
    Ambiguous(TlsError),
}

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

pub(crate) fn write_dispatch_frame<S: TlsStream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: &Deadline,
) -> Result<(), DispatchWriteError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(DispatchWriteError::PreDispatch(TlsError::Frame));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| DispatchWriteError::PreDispatch(TlsError::Frame))?;
    write_bytes(stream, &length.to_be_bytes(), deadline)
        .map_err(DispatchWriteError::PreDispatch)?;

    let mut input = bytes;
    let mut payload_written = false;
    while !input.is_empty() {
        if let Err(error) = set_timeout(stream.socket(), deadline) {
            return Err(classify_dispatch_error(error, payload_written));
        }
        let length = match stream.write_once(input) {
            Ok(length) => length,
            Err(error) => {
                return Err(classify_dispatch_error(map_io(&error), payload_written));
            }
        };
        if length == 0 {
            return Err(classify_dispatch_error(TlsError::Io, payload_written));
        }
        input = input
            .get(length..)
            .ok_or(DispatchWriteError::Ambiguous(TlsError::Io))?;
        payload_written = true;
        if let Err(error) = deadline.check() {
            return Err(DispatchWriteError::Ambiguous(error));
        }
        if let Err(error) = flush_bytes(stream, deadline) {
            return Err(DispatchWriteError::Ambiguous(error));
        }
    }
    flush_bytes(stream, deadline).map_err(DispatchWriteError::Ambiguous)
}

const fn classify_dispatch_error(error: TlsError, payload_written: bool) -> DispatchWriteError {
    if payload_written {
        DispatchWriteError::Ambiguous(error)
    } else {
        DispatchWriteError::PreDispatch(error)
    }
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

#[cfg(test)]
mod dispatch_tests {
    use std::{
        io,
        net::{TcpListener, TcpStream},
        time::Duration,
    };

    use super::{Deadline, DispatchWriteError, TlsStream, write_dispatch_frame};
    use crate::TlsError;

    struct ScriptedStream {
        socket: TcpStream,
        writes: usize,
        partial_payload: bool,
    }

    impl TlsStream for ScriptedStream {
        fn socket(&self) -> &TcpStream {
            &self.socket
        }

        fn read_once(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_once(&mut self, input: &[u8]) -> io::Result<usize> {
            self.writes = self
                .writes
                .checked_add(1)
                .ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;
            match self.writes {
                1 => Ok(input.len()),
                2 if self.partial_payload => Ok(1),
                _ => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        }

        fn wants_flush(&self) -> bool {
            false
        }

        fn flush_once(&mut self) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn scripted(partial_payload: bool) -> Result<ScriptedStream, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let socket = TcpStream::connect(listener.local_addr()?)?;
        let _peer = listener.accept()?;
        Ok(ScriptedStream {
            socket,
            writes: 0,
            partial_payload,
        })
    }

    #[test]
    fn payload_write_failure_before_first_byte_is_pre_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = scripted(false)?;
        let deadline = Deadline::new(Duration::from_secs(1))?;

        let result = write_dispatch_frame(&mut stream, b"request", &deadline);

        assert_eq!(result, Err(DispatchWriteError::PreDispatch(TlsError::Io)));
        Ok(())
    }

    #[test]
    fn payload_write_failure_after_partial_byte_is_ambiguous()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = scripted(true)?;
        let deadline = Deadline::new(Duration::from_secs(1))?;

        let result = write_dispatch_frame(&mut stream, b"request", &deadline);

        assert_eq!(result, Err(DispatchWriteError::Ambiguous(TlsError::Io)));
        Ok(())
    }
}
