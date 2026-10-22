// SPDX-License-Identifier: MIT OR Apache-2.0

//! Length-prefixed frames (ADR-029 point 4): a 4-byte big-endian length,
//! then exactly that many bytes of UTF-8. A frame is refused before its
//! body is read when the length is zero or over the limit.

use std::fmt;
use std::io::{self, Read, Write};

/// Largest request frame.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Largest response frame.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the stream before the first byte of a frame: a
    /// normal end of the conversation.
    Closed,
    Empty,
    TooLarge {
        length: usize,
        limit: usize,
    },
    /// The stream ended inside a frame.
    Truncated,
    InvalidUtf8,
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("stream closed"),
            Self::Empty => formatter.write_str("empty frame"),
            Self::TooLarge { length, limit } => {
                write!(
                    formatter,
                    "frame of {length} bytes is over the {limit}-byte limit"
                )
            }
            Self::Truncated => formatter.write_str("stream ended inside a frame"),
            Self::InvalidUtf8 => formatter.write_str("frame is not UTF-8"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reads one frame of at most `limit` bytes.
pub fn read_frame<R: Read>(reader: &mut R, limit: usize) -> Result<String, FrameError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Err(FrameError::Closed),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    let length = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > limit {
        return Err(FrameError::TooLarge { length, limit });
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(error),
        })?;
    String::from_utf8(body).map_err(|_| FrameError::InvalidUtf8)
}

/// Writes one frame and flushes it.
pub fn write_frame<W: Write>(writer: &mut W, body: &str, limit: usize) -> Result<(), FrameError> {
    let length = body.len();
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > limit {
        return Err(FrameError::TooLarge { length, limit });
    }
    let header = u32::try_from(length)
        .map_err(|_| FrameError::TooLarge { length, limit })?
        .to_be_bytes();
    writer.write_all(&header).map_err(FrameError::Io)?;
    writer.write_all(body.as_bytes()).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(body.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn frames_round_trip() -> Result<(), FrameError> {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, r#"{"a":1}"#, 64)?;
        write_frame(&mut buffer, "второй", 64)?;
        assert_eq!(&buffer[..4], &[0, 0, 0, 7]);
        let mut reader = buffer.as_slice();
        assert_eq!(read_frame(&mut reader, 64)?, r#"{"a":1}"#);
        assert_eq!(read_frame(&mut reader, 64)?, "второй");
        assert!(matches!(
            read_frame(&mut reader, 64),
            Err(FrameError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn bad_frames_are_refused_before_parsing() {
        // Zero length, over the limit (refused from the header alone, the
        // body is never read), truncated header and body, invalid UTF-8.
        assert!(matches!(
            read_frame(&mut [0_u8, 0, 0, 0].as_slice(), 64),
            Err(FrameError::Empty)
        ));
        let huge = [0xff_u8, 0xff, 0xff, 0xff];
        assert!(matches!(
            read_frame(&mut huge.as_slice(), 64),
            Err(FrameError::TooLarge { length, limit: 64 }) if length == 0xffff_ffff
        ));
        assert!(matches!(
            read_frame(&mut [0_u8, 0].as_slice(), 64),
            Err(FrameError::Truncated)
        ));
        let mut short = framed(b"0123456789");
        short.truncate(8);
        assert!(matches!(
            read_frame(&mut short.as_slice(), 64),
            Err(FrameError::Truncated)
        ));
        assert!(matches!(
            read_frame(&mut framed(&[0xc3, 0x28]).as_slice(), 64),
            Err(FrameError::InvalidUtf8)
        ));
    }

    #[test]
    fn oversized_or_empty_bodies_are_not_written() {
        let mut buffer = Vec::new();
        assert!(matches!(
            write_frame(&mut buffer, "", 64),
            Err(FrameError::Empty)
        ));
        assert!(matches!(
            write_frame(&mut buffer, &"x".repeat(65), 64),
            Err(FrameError::TooLarge {
                length: 65,
                limit: 64
            })
        ));
        assert!(buffer.is_empty());
    }
}
