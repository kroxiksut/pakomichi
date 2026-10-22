// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal, read-only reader of the decompressed control tar stream.
//!
//! It lists entries and copies out the `control` file; it never creates a
//! file, follows a link, or interprets a path on the local filesystem. The
//! ustar, GNU (`L` long names), and pax (`path` records) variants produced by
//! `dpkg-deb`, `tar`, and common DEB builders are understood. Anything
//! ambiguous (duplicate names, a non-regular `control`, `..` components) is
//! rejected rather than resolved.

use std::collections::HashSet;

use super::InspectLimits;
use super::error::InspectError;

const BLOCK: usize = 512;
const MAX_LONG_NAME_BYTES: u64 = 4096;
const MAX_PAX_HEADER_BYTES: u64 = 64 * 1024;
const MAX_NAME_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Regular,
    HardLink,
    Symlink,
    Directory,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TarEntry {
    /// The name without leading `./`; empty for the archive root.
    pub(crate) name: String,
    pub(crate) kind: EntryKind,
}

#[derive(Debug)]
pub(crate) struct ControlTar {
    pub(crate) entries: Vec<TarEntry>,
    pub(crate) control: Vec<u8>,
}

/// Reads the whole control tar stream held in `bytes`.
pub(crate) fn read_control_tar(
    bytes: &[u8],
    limits: &InspectLimits,
) -> Result<ControlTar, InspectError> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut control = None;
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut offset = 0_usize;

    loop {
        if offset == bytes.len() {
            // A stream without the end-of-archive blocks; every entry was
            // complete, so nothing is lost.
            break;
        }
        let header = bytes
            .get(offset..offset + BLOCK)
            .ok_or_else(|| malformed("truncated tar header"))?;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        verify_checksum(header)?;

        if header[124] & 0x80 != 0 {
            return Err(malformed("tar size uses base-256 encoding"));
        }
        let size = parse_octal(&header[124..136]).ok_or_else(|| malformed("invalid tar size"))?;
        let data_start = offset + BLOCK;
        let data_end = usize::try_from(size)
            .ok()
            .and_then(|size| data_start.checked_add(size))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("truncated tar member"))?;
        let data = &bytes[data_start..data_end];
        let next = data_start + (data_end - data_start).div_ceil(BLOCK) * BLOCK;
        if next > bytes.len() {
            return Err(malformed("truncated tar member padding"));
        }
        offset = next;

        let typeflag = header[156];
        match typeflag {
            b'L' => {
                if size > MAX_LONG_NAME_BYTES {
                    return Err(malformed("tar long name is too long"));
                }
                long_name = Some(text(until_nul(data))?);
                continue;
            }
            b'x' => {
                if size > MAX_PAX_HEADER_BYTES {
                    return Err(malformed("pax header is too long"));
                }
                if let Some(path) = pax_record(data, "path")? {
                    pax_path = Some(path);
                }
                continue;
            }
            b'K' => {
                if size > MAX_LONG_NAME_BYTES {
                    return Err(malformed("tar long link name is too long"));
                }
                continue;
            }
            b'g' => {
                if size > MAX_PAX_HEADER_BYTES {
                    return Err(malformed("pax header is too long"));
                }
                continue;
            }
            _ => {}
        }

        if entries.len() >= limits.max_tar_entries {
            return Err(malformed("too many entries in the control archive"));
        }
        let raw_name = match (pax_path.take(), long_name.take()) {
            (Some(path), _) => path,
            (None, Some(name)) => name,
            (None, None) => header_name(header)?,
        };
        let name = normalize(&raw_name)?;
        let kind = match typeflag {
            b'0' | 0 | b'7' => EntryKind::Regular,
            b'1' => EntryKind::HardLink,
            b'2' => EntryKind::Symlink,
            b'5' => EntryKind::Directory,
            _ => EntryKind::Other,
        };

        if kind != EntryKind::Directory && !seen.insert(name.clone()) {
            return Err(malformed("duplicate entry in the control archive"));
        }
        if name == "control" {
            if kind != EntryKind::Regular {
                return Err(malformed("control is not a regular file"));
            }
            if size > limits.max_control_file_bytes {
                return Err(InspectError::ControlFileTooLarge {
                    size,
                    limit: limits.max_control_file_bytes,
                });
            }
            control = Some(data.to_vec());
        }
        entries.push(TarEntry { name, kind });
    }

    if long_name.is_some() || pax_path.is_some() {
        return Err(malformed("extended header without an entry"));
    }
    let control = control.ok_or_else(|| malformed("the control file is missing"))?;
    Ok(ControlTar { entries, control })
}

fn verify_checksum(header: &[u8]) -> Result<(), InspectError> {
    let recorded =
        parse_octal(&header[148..156]).ok_or_else(|| malformed("invalid tar checksum field"))?;
    let (unsigned, signed) =
        header
            .iter()
            .enumerate()
            .fold((0_u64, 0_i64), |(unsigned, signed), (index, byte)| {
                let byte = if (148..156).contains(&index) {
                    b' '
                } else {
                    *byte
                };
                (
                    unsigned + u64::from(byte),
                    signed + i64::from(byte.cast_signed()),
                )
            });
    // Historic writers summed signed bytes; accept either convention.
    if recorded == unsigned || i64::try_from(recorded).is_ok_and(|recorded| recorded == signed) {
        Ok(())
    } else {
        Err(malformed("tar header checksum mismatch"))
    }
}

/// Parses an octal field padded with spaces or NUL bytes.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let start = field.iter().position(|byte| *byte != b' ')?;
    let digits = &field[start..];
    let end = digits
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(digits.len());
    let digits = &digits[..end];
    if digits.is_empty() || !digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
        return None;
    }
    // At most 21 octal digits fit in 64 bits; the fields hold 11.
    u64::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok()
}

fn header_name(header: &[u8]) -> Result<String, InspectError> {
    let name = text(until_nul(&header[0..100]))?;
    // POSIX ustar splits long names into a prefix; GNU headers use that
    // area for other data and carry the magic "ustar  ".
    if &header[257..263] == b"ustar\0" {
        let prefix = text(until_nul(&header[345..500]))?;
        if !prefix.is_empty() {
            return Ok(format!("{prefix}/{name}"));
        }
    }
    Ok(name)
}

/// Finds `key` in pax extended header records (`"<len> key=value\n"`).
fn pax_record(mut data: &[u8], key: &str) -> Result<Option<String>, InspectError> {
    let mut found = None;
    while !data.is_empty() {
        let space = data
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| malformed("invalid pax record"))?;
        let length: usize = std::str::from_utf8(&data[..space])
            .ok()
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(|| malformed("invalid pax record length"))?;
        if length <= space + 1 || length > data.len() || data[length - 1] != b'\n' {
            return Err(malformed("invalid pax record length"));
        }
        let record = &data[space + 1..length - 1];
        let separator = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| malformed("invalid pax record"))?;
        if &record[..separator] == key.as_bytes() {
            found = Some(text(&record[separator + 1..])?);
        }
        data = &data[length..];
    }
    Ok(found)
}

fn until_nul(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

fn text(bytes: &[u8]) -> Result<String, InspectError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed("tar name is not UTF-8"))
}

/// Strips leading `./` and a trailing `/`, and rejects names that are not
/// plain relative ASCII paths.
fn normalize(raw: &str) -> Result<String, InspectError> {
    if raw.len() > MAX_NAME_BYTES {
        return Err(malformed("tar name is too long"));
    }
    if !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(malformed("tar name has unsafe characters"));
    }
    if raw.starts_with('/') {
        return Err(malformed("absolute name in the control archive"));
    }
    let mut name = raw;
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    let name = name.trim_end_matches('/');
    let name = if name == "." { "" } else { name };
    if name
        .split('/')
        .any(|component| component == ".." || component == ".")
    {
        return Err(malformed("relative component in a control archive name"));
    }
    Ok(name.to_owned())
}

const fn malformed(problem: &'static str) -> InspectError {
    InspectError::MalformedControlArchive { problem }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::fixtures::{TarItem, tar, tar_with_gnu_long_name, tar_with_pax_path};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn read(bytes: &[u8]) -> Result<ControlTar, InspectError> {
        read_control_tar(bytes, &InspectLimits::default())
    }

    #[test]
    fn lists_entries_and_extracts_control() -> TestResult {
        let bytes = tar(&[
            TarItem::dir("./"),
            TarItem::file("./control", b"Package: probe\n"),
            TarItem::file("./md5sums", b""),
            TarItem::file("./preinst", b"#!/bin/sh\n"),
        ]);
        let archive = read(&bytes)?;
        assert_eq!(archive.control, b"Package: probe\n");
        let names: Vec<_> = archive
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["", "control", "md5sums", "preinst"]);
        assert_eq!(archive.entries[0].kind, EntryKind::Directory);
        Ok(())
    }

    #[test]
    fn accepts_names_without_a_dot_prefix_and_without_end_blocks() -> TestResult {
        let mut bytes = tar(&[TarItem::file("control", b"Package: probe\n")]);
        bytes.truncate(bytes.len() - 2 * BLOCK);
        assert_eq!(read(&bytes)?.control, b"Package: probe\n");
        Ok(())
    }

    #[test]
    fn understands_gnu_long_names_and_pax_paths() -> TestResult {
        let long = format!("./{}", "a".repeat(150));
        let archive = read(&tar_with_gnu_long_name(&long, b"x"))?;
        assert!(archive.entries.iter().any(|entry| entry.name == long[2..]));

        // A pax path overrides the header name.
        let archive = read(&tar_with_pax_path(
            "./control",
            "./placeholder",
            b"Package: p\n",
        ))?;
        assert_eq!(archive.control, b"Package: p\n");
        Ok(())
    }

    #[test]
    fn rejects_a_missing_or_non_regular_control() {
        for items in [
            vec![TarItem::file("./md5sums", b"")],
            vec![TarItem::symlink("./control", "/etc/passwd")],
            vec![TarItem::hardlink("./control", "./md5sums")],
            vec![TarItem::dir("./control")],
        ] {
            assert!(matches!(
                read(&tar(&items)),
                Err(InspectError::MalformedControlArchive { .. })
            ));
        }
    }

    #[test]
    fn rejects_duplicate_entries() {
        let bytes = tar(&[
            TarItem::file("./control", b"Package: first\n"),
            TarItem::file("control", b"Package: second\n"),
        ]);
        assert!(matches!(
            read(&bytes),
            Err(InspectError::MalformedControlArchive {
                problem: "duplicate entry in the control archive"
            })
        ));
    }

    #[test]
    fn rejects_unsafe_names() {
        for name in [
            "../control",
            "/control",
            "./a/../control",
            "con trol",
            "contröl",
        ] {
            let bytes = tar(&[
                TarItem::file("./control", b"Package: p\n"),
                TarItem::file(name, b""),
            ]);
            assert!(
                matches!(
                    read(&bytes),
                    Err(InspectError::MalformedControlArchive { .. })
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_corruption_and_truncation() {
        let bytes = tar(&[TarItem::file("./control", &[b'x'; 700])]);
        let mut corrupt = bytes.clone();
        corrupt[10] ^= 1;
        assert!(matches!(
            read(&corrupt),
            Err(InspectError::MalformedControlArchive {
                problem: "tar header checksum mismatch"
            })
        ));
        for length in [1, BLOCK - 1, BLOCK + 10, 2 * BLOCK + 1] {
            assert!(
                matches!(
                    read(&bytes[..length]),
                    Err(InspectError::MalformedControlArchive { .. })
                ),
                "{length}"
            );
        }
    }

    #[test]
    fn enforces_entry_and_control_size_limits() {
        let many: Vec<_> = (0..10).map(|index| format!("./file{index}")).collect();
        let mut items: Vec<_> = many.iter().map(|name| TarItem::file(name, b"")).collect();
        items.push(TarItem::file("./control", b"Package: p\n"));
        let limits = InspectLimits {
            max_tar_entries: 10,
            ..InspectLimits::default()
        };
        assert!(matches!(
            read_control_tar(&tar(&items), &limits),
            Err(InspectError::MalformedControlArchive {
                problem: "too many entries in the control archive"
            })
        ));

        let limits = InspectLimits {
            max_control_file_bytes: 4,
            ..InspectLimits::default()
        };
        assert!(matches!(
            read_control_tar(&tar(&[TarItem::file("./control", b"12345")]), &limits),
            Err(InspectError::ControlFileTooLarge { size: 5, limit: 4 })
        ));
    }

    #[test]
    fn parses_padded_octal() {
        assert_eq!(parse_octal(b"00000000017\0"), Some(15));
        assert_eq!(parse_octal(b"     17 \0"), Some(15));
        assert_eq!(parse_octal(b"\0\0\0"), None);
        assert_eq!(parse_octal(b"0000008\0"), None);
    }
}
