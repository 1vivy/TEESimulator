use std::net::TcpStream;

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::{
    TlsError,
    tls_io::{Deadline, map_io, set_timeout},
};

#[doc(hidden)]
pub fn complete_client_handshake(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.is_handshaking() {
        progress_client(stream, deadline)?;
    }
    while stream.conn.wants_write() {
        write_client_tls(stream, deadline)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn complete_server_handshake(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.is_handshaking() {
        progress_server(stream, deadline)?;
    }
    while stream.conn.wants_write() {
        write_server_tls(stream, deadline)?;
    }
    Ok(())
}

fn progress_client(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.wants_write() {
        write_client_tls(stream, deadline)?;
    }
    if stream.conn.wants_read() {
        set_timeout(&stream.sock, deadline)?;
        if stream
            .conn
            .read_tls(&mut stream.sock)
            .map_err(|error| map_io(&error))?
            == 0
        {
            return Err(TlsError::Io);
        }
        deadline.check()?;
        stream
            .conn
            .process_new_packets()
            .map_err(|_| TlsError::Io)?;
    }
    deadline.check()
}

fn progress_server(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    while stream.conn.wants_write() {
        write_server_tls(stream, deadline)?;
    }
    if stream.conn.wants_read() {
        set_timeout(&stream.sock, deadline)?;
        if stream
            .conn
            .read_tls(&mut stream.sock)
            .map_err(|error| map_io(&error))?
            == 0
        {
            return Err(TlsError::Io);
        }
        deadline.check()?;
        stream
            .conn
            .process_new_packets()
            .map_err(|_| TlsError::Io)?;
    }
    deadline.check()
}

fn write_client_tls(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    set_timeout(&stream.sock, deadline)?;
    let written = stream
        .conn
        .write_tls(&mut stream.sock)
        .map_err(|error| map_io(&error))?;
    deadline.check()?;
    if written == 0 {
        Err(TlsError::Io)
    } else {
        Ok(())
    }
}

fn write_server_tls(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    deadline: &Deadline,
) -> Result<(), TlsError> {
    set_timeout(&stream.sock, deadline)?;
    let written = stream
        .conn
        .write_tls(&mut stream.sock)
        .map_err(|error| map_io(&error))?;
    deadline.check()?;
    if written == 0 {
        Err(TlsError::Io)
    } else {
        Ok(())
    }
}
