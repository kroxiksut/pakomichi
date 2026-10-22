// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outer `ar` container of a binary DEB, as described in deb(5).
//!
//! Only member headers and the small `debian-binary` member are read; the
//! control and data members are skipped by seeking. Every size is checked
//! against the file length, so a truncated archive is rejected before any
//! decompressor sees it.

use std::io::{self, Read, Seek, SeekFrom};

use super::InspectLimits;
use super::error::InspectError;

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_BYTES: u64 = 60;
const HEADER_END: &[u8; 2] = b"`\n";
const DEBIAN_BINARY: &str = "debian-binary";
/// dpkg-deb reads at most this much of `debian-binary`.
const MAX_DEBIAN_BINARY_BYTES: u64 = 64;
const MAX_MEMBERS: usize = 32;
const SUPPORTED_MAJOR_VERSION: &str = "2";

/// The compression of a DEB member, taken from its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Lzma,
}

impl Compression {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "lzma",
        }
    }

    fn from_suffix(suffix: &str) -> Option<Self> {
        match suffix {
            "" => Some(Self::None),
            ".gz" => Some(Self::Gzip),
            ".xz" => Some(Self::Xz),
            ".zst" => Some(Self::Zstd),
            ".bz2" => Some(Self::Bzip2),
            ".lzma" => Some(Self::Lzma),
            _ => None,
        }
    }
}

/// The container-level format of a binary DEB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebFormat {
    version: String,
    control_compression: Compression,
    control_member_bytes: u64,
    data_compression: Compression,
    data_member_bytes: u64,
    ignored_members: Vec<String>,
}

impl DebFormat {
    /// The first line of `debian-binary`, for example `2.0`.
    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn control_compression(&self) -> Compression {
        self.control_compression
    }

    /// The compressed size of the control member.
    pub const fn control_member_bytes(&self) -> u64 {
        self.control_member_bytes
    }

    pub const fn data_compression(&self) -> Compression {
        self.data_compression
    }

    pub const fn data_member_bytes(&self) -> u64 {
        self.data_member_bytes
    }

    /// Members that deb(5) tells readers to ignore: `_`-prefixed members
    /// (for example, embedded signatures) and anything after the data member.
    pub fn ignored_members(&self) -> &[String] {
        &self.ignored_members
    }
}

struct MemberHeader {
    name: String,
    size: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    ExpectVersion,
    ExpectControl,
    ExpectData,
    AfterData,
}

/// Reads the member layout of `reader`, which holds `file_bytes` bytes.
pub(crate) fn read_layout<R: Read + Seek>(
    reader: &mut R,
    file_bytes: u64,
    limits: &InspectLimits,
) -> Result<DebFormat, InspectError> {
    let mut magic = [0_u8; 8];
    if file_bytes < AR_MAGIC.len() as u64 {
        return Err(malformed("file is shorter than the ar signature"));
    }
    read_exact(reader, &mut magic)?;
    if &magic != AR_MAGIC {
        return Err(InspectError::UnsupportedFormat {
            problem: "not an ar archive",
        });
    }

    let mut offset = AR_MAGIC.len() as u64;
    let mut stage = Stage::ExpectVersion;
    let mut version = None;
    let mut control = None;
    let mut data = None;
    let mut ignored_members = Vec::new();
    let mut members = 0_usize;

    while offset < file_bytes {
        members += 1;
        if members > MAX_MEMBERS {
            return Err(malformed("too many ar members"));
        }
        let header = read_header(reader, offset, file_bytes)?;
        let body = offset + HEADER_BYTES;
        let body_end = body
            .checked_add(header.size)
            .filter(|end| *end <= file_bytes)
            .ok_or_else(|| malformed("ar member extends past the end of the file"))?;

        match stage {
            Stage::ExpectVersion => {
                if header.name != DEBIAN_BINARY {
                    return Err(malformed("the first member is not debian-binary"));
                }
                version = Some(read_version(reader, header.size)?);
                stage = Stage::ExpectControl;
            }
            Stage::ExpectControl => {
                if let Some(suffix) = header.name.strip_prefix("control.tar") {
                    let compression = control_compression(suffix)?;
                    if header.size > limits.max_control_member_bytes {
                        return Err(InspectError::ControlMemberTooLarge {
                            size: header.size,
                            limit: limits.max_control_member_bytes,
                        });
                    }
                    control = Some((compression, header.size));
                    stage = Stage::ExpectData;
                } else if header.name.starts_with('_') {
                    ignored_members.push(header.name);
                } else {
                    return Err(malformed("unexpected member before the control member"));
                }
            }
            Stage::ExpectData => {
                if let Some(suffix) = header.name.strip_prefix("data.tar") {
                    let compression = Compression::from_suffix(suffix).ok_or(
                        InspectError::UnsupportedFormat {
                            problem: "unsupported data member compression",
                        },
                    )?;
                    data = Some((compression, header.size));
                    stage = Stage::AfterData;
                } else if header.name.starts_with('_') {
                    ignored_members.push(header.name);
                } else {
                    return Err(malformed("unexpected member before the data member"));
                }
            }
            Stage::AfterData => ignored_members.push(header.name),
        }

        // Members start at even offsets; the padding of the last member may
        // be missing.
        offset = body_end + (header.size & 1);
        if offset > file_bytes {
            offset = file_bytes;
        }
    }

    let version = version.ok_or_else(|| malformed("the archive has no members"))?;
    let (control_compression, control_member_bytes) =
        control.ok_or_else(|| malformed("the control member is missing"))?;
    let (data_compression, data_member_bytes) =
        data.ok_or_else(|| malformed("the data member is missing"))?;

    Ok(DebFormat {
        version,
        control_compression,
        control_member_bytes,
        data_compression,
        data_member_bytes,
        ignored_members,
    })
}

fn control_compression(suffix: &str) -> Result<Compression, InspectError> {
    // dpkg accepts only these for the control member.
    match Compression::from_suffix(suffix) {
        Some(
            compression @ (Compression::None
            | Compression::Gzip
            | Compression::Xz
            | Compression::Zstd),
        ) => Ok(compression),
        _ => Err(InspectError::UnsupportedFormat {
            problem: "unsupported control member compression",
        }),
    }
}

fn read_header<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    file_bytes: u64,
) -> Result<MemberHeader, InspectError> {
    if file_bytes - offset < HEADER_BYTES {
        return Err(malformed("truncated ar member header"));
    }
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|source| InspectError::Io {
            operation: "seek in the package",
            source,
        })?;
    let mut header = [0_u8; HEADER_BYTES as usize];
    read_exact(reader, &mut header)?;

    if &header[58..60] != HEADER_END {
        return Err(malformed("invalid ar member header terminator"));
    }

    let raw_name = header[0..16]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(&header[0..0], |last| &header[0..=last]);
    // GNU ar terminates short names with '/'.
    let raw_name = raw_name.strip_suffix(b"/").unwrap_or(raw_name);
    if raw_name.is_empty() || !raw_name.iter().all(u8::is_ascii_graphic) {
        return Err(malformed("invalid ar member name"));
    }
    let name =
        String::from_utf8(raw_name.to_vec()).map_err(|_| malformed("invalid ar member name"))?;

    let size = parse_decimal(&header[48..58]).ok_or_else(|| malformed("invalid ar member size"))?;
    Ok(MemberHeader { name, size })
}

fn read_version<R: Read>(reader: &mut R, size: u64) -> Result<String, InspectError> {
    if size > MAX_DEBIAN_BINARY_BYTES {
        return Err(InspectError::UnsupportedFormat {
            problem: "debian-binary member is too long",
        });
    }
    let mut content = vec![0_u8; size as usize];
    read_exact(reader, &mut content)?;

    // deb(5): readers must accept a larger minor number and extra lines.
    let first_line = content
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let line = std::str::from_utf8(first_line).map_err(|_| InspectError::UnsupportedFormat {
        problem: "debian-binary is not a format version",
    })?;
    let (major, minor) = line
        .split_once('.')
        .filter(|(major, minor)| is_number(major) && is_number(minor))
        .ok_or(InspectError::UnsupportedFormat {
            problem: "debian-binary is not a format version",
        })?;
    if major != SUPPORTED_MAJOR_VERSION {
        return Err(InspectError::UnsupportedFormat {
            problem: "unsupported debian-binary format version",
        });
    }
    Ok(format!("{major}.{minor}"))
}

fn is_number(text: &str) -> bool {
    !text.is_empty() && text.len() <= 9 && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Parses a space-padded decimal ar field.
fn parse_decimal(field: &[u8]) -> Option<u64> {
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ')
        .map(|last| last + 1)?;
    let digits = &field[..end];
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), InspectError> {
    reader.read_exact(buffer).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            malformed("the archive ended unexpectedly")
        } else {
            InspectError::Io {
                operation: "read the package",
                source,
            }
        }
    })
}

const fn malformed(problem: &'static str) -> InspectError {
    InspectError::MalformedArchive { problem }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::inspect::fixtures::{ar, minimal_deb_members};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn layout(bytes: &[u8]) -> Result<DebFormat, InspectError> {
        read_layout(
            &mut Cursor::new(bytes),
            bytes.len() as u64,
            &InspectLimits::default(),
        )
    }

    fn members_with(
        version: &[u8],
        control_name: &str,
        extra: &[(&str, &[u8])],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (control, data) =
            minimal_deb_members("Package: probe\nVersion: 1\nArchitecture: all\n");
        let mut members: Vec<(&str, &[u8])> = vec![
            ("debian-binary", version),
            (control_name, &control),
            ("data.tar", &data),
        ];
        members.extend_from_slice(extra);
        Ok(ar(&members))
    }

    #[test]
    fn reads_a_standard_layout() -> TestResult {
        let bytes = members_with(b"2.0\n", "control.tar", &[])?;
        let format = layout(&bytes)?;
        assert_eq!(format.version(), "2.0");
        assert_eq!(format.control_compression(), Compression::None);
        assert_eq!(format.data_compression(), Compression::None);
        assert!(format.ignored_members().is_empty());
        Ok(())
    }

    #[test]
    fn accepts_a_newer_minor_version_and_extra_lines() -> TestResult {
        let bytes = members_with(b"2.9\nfuture\n", "control.tar", &[])?;
        assert_eq!(layout(&bytes)?.version(), "2.9");
        Ok(())
    }

    #[test]
    fn rejects_other_major_versions_and_garbage() -> TestResult {
        for version in [
            &b"3.0\n"[..],
            b"1.0\n",
            b"2\n",
            b"\n",
            b"two.0\n",
            b"\xff.0\n",
        ] {
            let bytes = members_with(version, "control.tar", &[])?;
            assert!(
                matches!(layout(&bytes), Err(InspectError::UnsupportedFormat { .. })),
                "{version:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn maps_member_names_to_compression() -> TestResult {
        for (name, expected) in [
            ("control.tar.gz", Compression::Gzip),
            ("control.tar.xz", Compression::Xz),
            ("control.tar.zst", Compression::Zstd),
        ] {
            let bytes = members_with(b"2.0\n", name, &[])?;
            assert_eq!(layout(&bytes)?.control_compression(), expected);
        }
        for name in ["control.tar.bz2", "control.tar.lzma", "control.tar.br"] {
            let bytes = members_with(b"2.0\n", name, &[])?;
            assert!(matches!(
                layout(&bytes),
                Err(InspectError::UnsupportedFormat { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn ignores_underscore_and_trailing_members() -> TestResult {
        let (control, data) = minimal_deb_members("Package: probe\n");
        let bytes = ar(&[
            ("debian-binary", b"2.0\n"),
            ("_gpgbuilder", b"sig"),
            ("control.tar", &control),
            ("data.tar", &data),
            ("_gpgorigin", b"sig"),
        ]);
        assert_eq!(
            layout(&bytes)?.ignored_members(),
            ["_gpgbuilder".to_owned(), "_gpgorigin".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_order_and_missing_members() -> TestResult {
        let (control, data) = minimal_deb_members("Package: probe\n");
        let cases: [Vec<(&str, &[u8])>; 4] = [
            vec![("control.tar", &control), ("debian-binary", b"2.0\n")],
            vec![("debian-binary", b"2.0\n"), ("data.tar", &data)],
            vec![("debian-binary", b"2.0\n"), ("control.tar", &control)],
            vec![
                ("debian-binary", b"2.0\n"),
                ("payload", b"x"),
                ("control.tar", &control),
            ],
        ];
        for members in cases {
            assert!(matches!(
                layout(&ar(&members)),
                Err(InspectError::MalformedArchive { .. })
            ));
        }
        assert!(matches!(
            layout(AR_MAGIC),
            Err(InspectError::MalformedArchive { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_every_truncation() -> TestResult {
        let bytes = members_with(b"2.0\n", "control.tar", &[])?;
        for length in 0..bytes.len() {
            let result = layout(&bytes[..length]);
            assert!(
                matches!(result, Err(InspectError::MalformedArchive { .. })),
                "length {length}: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_a_non_ar_file() {
        assert!(matches!(
            layout(b"0.939000\ncontrol"),
            Err(InspectError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn rejects_an_oversized_control_member_before_decompression() -> TestResult {
        let bytes = members_with(b"2.0\n", "control.tar", &[])?;
        let limits = InspectLimits {
            max_control_member_bytes: 512,
            ..InspectLimits::default()
        };
        let result = read_layout(&mut Cursor::new(&bytes), bytes.len() as u64, &limits);
        assert!(matches!(
            result,
            Err(InspectError::ControlMemberTooLarge { limit: 512, .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_corrupt_headers() -> TestResult {
        let bytes = members_with(b"2.0\n", "control.tar", &[])?;
        // Size field of the first member, terminator, and name.
        for (position, value) in [(8 + 48, b'x'), (8 + 58, b'!'), (8, b'\x01')] {
            let mut corrupt = bytes.clone();
            corrupt[position] = value;
            assert!(
                matches!(layout(&corrupt), Err(InspectError::MalformedArchive { .. })),
                "{position}"
            );
        }
        Ok(())
    }
}
