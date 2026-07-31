use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use super::DonorIngressError;

const MAX_FRAME_BYTES: usize = 1_048_576;

fn remaining(started: Instant, budget: Duration) -> Result<Duration, DonorIngressError> {
    budget
        .checked_sub(started.elapsed())
        .filter(|value| !value.is_zero())
        .ok_or(DonorIngressError::Io)
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut output: &mut [u8],
    started: Instant,
    budget: Duration,
) -> Result<(), DonorIngressError> {
    while !output.is_empty() {
        stream
            .set_read_timeout(Some(remaining(started, budget)?))
            .map_err(|_| DonorIngressError::Io)?;
        match stream.read(output) {
            Ok(0) | Err(_) => return Err(DonorIngressError::Io),
            Ok(count) => output = output.get_mut(count..).ok_or(DonorIngressError::Io)?,
        }
    }
    Ok(())
}

pub(super) fn read_frame_until(
    mut stream: UnixStream,
    started: Instant,
    budget: Duration,
) -> Result<Vec<u8>, DonorIngressError> {
    let mut length = [0_u8; 4];
    read_exact_until(&mut stream, &mut length, started, budget)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| DonorIngressError::Bounds)?;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(DonorIngressError::Bounds);
    }
    let mut request = vec![0_u8; length];
    read_exact_until(&mut stream, &mut request, started, budget)?;
    Ok(request)
}

pub(super) fn write_response_until(
    stream: &mut UnixStream,
    response: &[u8],
    started: Instant,
    budget: Duration,
) -> Result<(), DonorIngressError> {
    let length = u32::try_from(response.len()).map_err(|_| DonorIngressError::Bounds)?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(response);
    let mut remaining_bytes = frame.as_slice();
    while !remaining_bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(started, budget)?))
            .map_err(|_| DonorIngressError::Io)?;
        let count = stream
            .write(remaining_bytes)
            .map_err(|_| DonorIngressError::Io)?;
        if count == 0 {
            return Err(DonorIngressError::Io);
        }
        remaining_bytes = remaining_bytes.get(count..).ok_or(DonorIngressError::Io)?;
    }
    Ok(())
}
