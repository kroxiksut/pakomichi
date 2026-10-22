// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST ONLY builders for synthetic DEB containers and tar streams.
//!
//! They write the formats byte by byte so that tests can produce malformed
//! input that `dpkg-deb --build` refuses to create, and so that the portable
//! parsers are tested without native tools.

/// One tar entry for [`tar`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct TarItem<'a> {
    name: &'a str,
    typeflag: u8,
    data: &'a [u8],
    link: &'a str,
}

impl<'a> TarItem<'a> {
    pub(crate) const fn file(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            typeflag: b'0',
            data,
            link: "",
        }
    }

    pub(crate) const fn dir(name: &'a str) -> Self {
        Self {
            name,
            typeflag: b'5',
            data: b"",
            link: "",
        }
    }

    pub(crate) const fn symlink(name: &'a str, target: &'a str) -> Self {
        Self {
            name,
            typeflag: b'2',
            data: b"",
            link: target,
        }
    }

    pub(crate) const fn hardlink(name: &'a str, target: &'a str) -> Self {
        Self {
            name,
            typeflag: b'1',
            data: b"",
            link: target,
        }
    }

    const fn raw(name: &'a str, typeflag: u8, data: &'a [u8]) -> Self {
        Self {
            name,
            typeflag,
            data,
            link: "",
        }
    }
}

/// An `ar` archive in the layout `dpkg-deb --build` writes.
pub(crate) fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let header = format!(
            "{name:<16}{mtime:<12}{uid:<6}{gid:<6}{mode:<8}{size:<10}`\n",
            mtime = 0,
            uid = 0,
            gid = 0,
            mode = 100_644,
            size = data.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// A POSIX ustar stream with end-of-archive blocks. Names longer than 100
/// bytes are not supported here; see [`tar_with_gnu_long_name`].
pub(crate) fn tar(items: &[TarItem<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        append_entry(&mut out, item);
    }
    out.extend_from_slice(&[0_u8; 1024]);
    out
}

/// A stream with a GNU `L` long-name entry for `name`, followed by a
/// regular `./control`.
pub(crate) fn tar_with_gnu_long_name(name: &str, data: &[u8]) -> Vec<u8> {
    let mut long_name = name.as_bytes().to_vec();
    long_name.push(0);
    let mut out = Vec::new();
    append_entry(&mut out, &TarItem::raw("././@LongLink", b'L', &long_name));
    append_entry(&mut out, &TarItem::file("./placeholder", data));
    append_entry(&mut out, &TarItem::file("./control", b"Package: p\n"));
    out.extend_from_slice(&[0_u8; 1024]);
    out
}

/// A stream whose single entry is named by a pax `path` record.
pub(crate) fn tar_with_pax_path(path: &str, header_name: &str, data: &[u8]) -> Vec<u8> {
    let body = format!(" path={path}\n");
    // The length prefix counts itself.
    let mut length = body.len() + 1;
    while format!("{length}{body}").len() != length {
        length += 1;
    }
    let record = format!("{length}{body}");
    let mut out = Vec::new();
    append_entry(
        &mut out,
        &TarItem::raw("./PaxHeaders/entry", b'x', record.as_bytes()),
    );
    append_entry(&mut out, &TarItem::file(header_name, data));
    out.extend_from_slice(&[0_u8; 1024]);
    out
}

/// An uncompressed control tar holding `control` and an empty data tar.
pub(crate) fn minimal_deb_members(control: &str) -> (Vec<u8>, Vec<u8>) {
    (
        tar(&[
            TarItem::dir("./"),
            TarItem::file("./control", control.as_bytes()),
        ]),
        tar(&[]),
    )
}

fn append_entry(out: &mut Vec<u8>, item: &TarItem<'_>) {
    let mut header = [0_u8; 512];
    put(&mut header[0..100], item.name.as_bytes());
    let mode = if matches!(item.typeflag, b'5') {
        0o755
    } else {
        0o644
    };
    put(&mut header[100..108], format!("{mode:07o}\0").as_bytes());
    put(&mut header[108..116], b"0000000\0");
    put(&mut header[116..124], b"0000000\0");
    put(
        &mut header[124..136],
        format!("{:011o}\0", item.data.len()).as_bytes(),
    );
    put(&mut header[136..148], b"00000000000\0");
    header[156] = item.typeflag;
    put(&mut header[157..257], item.link.as_bytes());
    put(&mut header[257..263], b"ustar\0");
    put(&mut header[263..265], b"00");
    put(&mut header[265..297], b"root");
    put(&mut header[297..329], b"root");

    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    put(
        &mut header[148..156],
        format!("{checksum:06o}\0 ").as_bytes(),
    );

    out.extend_from_slice(&header);
    out.extend_from_slice(item.data);
    let padding = (512 - item.data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0_u8, padding));
}

fn put(field: &mut [u8], value: &[u8]) {
    let length = value.len().min(field.len());
    field[..length].copy_from_slice(&value[..length]);
}
