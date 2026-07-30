use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
};

use rustix::{
    event::PollFlags,
    io::{Errno, read, write},
    net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, accept_with, connect, socket_with,
        sockopt::socket_error,
    },
};

use super::{
    BridgeError, BridgeMessage, EncodedFrame, ExchangeRole,
    deadline::Deadline,
    decode_frame,
    model::{HEADER_BYTES, MAX_FRAME_BYTES},
};

pub(super) fn connect_path(path: &Path, deadline: &Deadline) -> Result<UnixStream, BridgeError> {
    let address = SocketAddrUnix::new(path).map_err(|_| BridgeError::PeerIdentity)?;
    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| BridgeError::Io)?;
    match connect(&descriptor, &address) {
        Ok(()) => {}
        Err(error) if error == Errno::INPROGRESS => {
            deadline.wait(&descriptor, PollFlags::OUT)?;
            socket_error(&descriptor)
                .map_err(|_| BridgeError::Io)?
                .map_err(|_| BridgeError::PeerDied)?;
        }
        Err(error) if error == Errno::AGAIN => {
            deadline.control().expire();
            return Err(BridgeError::Deadline);
        }
        Err(_) => return Err(BridgeError::PeerDied),
    }
    Ok(UnixStream::from(descriptor))
}

pub(super) fn accept_peer(
    listener: &UnixListener,
    deadline: &Deadline,
) -> Result<UnixStream, BridgeError> {
    deadline.wait(listener, PollFlags::IN)?;
    let descriptor =
        accept_with(listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK).map_err(|error| {
            if error == Errno::AGAIN {
                BridgeError::Deadline
            } else {
                BridgeError::PeerDied
            }
        })?;
    Ok(UnixStream::from(descriptor))
}

pub(super) fn read_message(
    stream: &UnixStream,
    role: ExchangeRole,
    deadline: &Deadline,
) -> Result<BridgeMessage, BridgeError> {
    let mut header = [0_u8; HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let length_bytes: [u8; 4] = header
        .get(16..20)
        .ok_or(BridgeError::Truncated)?
        .try_into()
        .map_err(|_| BridgeError::Truncated)?;
    let body_length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| BridgeError::FrameTooLarge)?;
    if body_length == 0 {
        return Err(BridgeError::EmptyFrame);
    }
    if body_length > MAX_FRAME_BYTES {
        return Err(BridgeError::FrameTooLarge);
    }
    let total = HEADER_BYTES
        .checked_add(body_length)
        .ok_or(BridgeError::FrameTooLarge)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(total)
        .map_err(|_| BridgeError::Allocation)?;
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    let body = frame
        .get_mut(HEADER_BYTES..)
        .ok_or(BridgeError::Truncated)?;
    read_exact(stream, body, deadline)?;
    let result = decode_frame(&frame, role);
    frame.fill(0);
    result
}

pub(super) fn write_message(
    stream: &UnixStream,
    frame: &EncodedFrame,
    deadline: &Deadline,
) -> Result<(), BridgeError> {
    let mut remaining = frame.as_slice();
    while !remaining.is_empty() {
        deadline.wait(stream, PollFlags::OUT)?;
        match write(stream, remaining) {
            Ok(0) => return Err(BridgeError::PeerDied),
            Ok(count) => {
                remaining = remaining.get(count..).ok_or(BridgeError::Io)?;
            }
            Err(error) if error == Errno::AGAIN => {}
            Err(_) => return Err(BridgeError::PeerDied),
        }
    }
    Ok(())
}

pub(super) fn read_exact(
    stream: &UnixStream,
    mut remaining: &mut [u8],
    deadline: &Deadline,
) -> Result<(), BridgeError> {
    while !remaining.is_empty() {
        deadline.wait(stream, PollFlags::IN)?;
        match read(stream, &mut *remaining) {
            Ok(0) => return Err(BridgeError::PeerDied),
            Ok(count) => {
                remaining = remaining.get_mut(count..).ok_or(BridgeError::Io)?;
            }
            Err(error) if error == Errno::AGAIN => {}
            Err(_) => return Err(BridgeError::PeerDied),
        }
    }
    Ok(())
}
