// SPDX-License-Identifier: MIT OR Apache-2.0

//! RPM reader tests. TEST ONLY packages are built here with the `rpm` crate
//! (`payload` enabled for tests only, no compression) and never committed.
//! Signature fixtures carry placeholder bytes in the signature tags: the
//! reader reports presence and never verifies, so no signing key is needed.

use std::error::Error;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rpm::{
    BuildConfig, CompressionType, Dependency, FileOptions, Header, HeaderEntry, IndexData,
    IndexSignatureTag, IndexTag, Package, PackageBuilder, Scriptlet, SignatureHeaderBuilder,
};

use super::*;
use crate::error::ReasonCode;
use crate::inspect::fixtures::{ar, minimal_deb_members};

type TestResult = Result<(), Box<dyn Error>>;
type Entries = Vec<(u32, IndexData)>;

const NAME: &str = "pakomichi-probe";

fn builder(config: BuildConfig) -> PackageBuilder {
    let mut builder = PackageBuilder::new(
        NAME,
        "1.2.3",
        "MIT OR Apache-2.0",
        "x86_64",
        "TEST ONLY P2-005 RPM inspection fixture",
    );
    builder
        .release("1.el9")
        .epoch(2)
        .using_config(config.compression(CompressionType::None));
    builder
}

fn write(package: &Package) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    package.write(&mut bytes)?;
    Ok(bytes)
}

fn normal_package() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = builder(BuildConfig::v4());
    builder
        .with_file_contents(
            b"TEST ONLY\n".to_vec(),
            FileOptions::new("/usr/share/pakomichi-probe/README"),
        )?
        .requires(Dependency::greater_eq("glibc", "2.34"))
        .provides(Dependency::any("probe-virtual"))
        .conflicts(Dependency::less("probe-old", "1.0"))
        .obsoletes(Dependency::any("probe-legacy"))
        .recommends(Dependency::any("probe-docs"))
        .suggests(Dependency::any("probe-extras"))
        .supplements(Dependency::any("probe-host"))
        .enhances(Dependency::any("probe-target"));
    write(&builder.build()?)
}

fn inspect(bytes: &[u8]) -> Result<RpmInspection, InspectError> {
    inspect_with(bytes, &InspectLimits::default())
}

fn inspect_with(bytes: &[u8], limits: &InspectLimits) -> Result<RpmInspection, InspectError> {
    inspect_rpm(&mut Cursor::new(bytes), bytes.len() as u64, limits)
}

/// Rebuilds the main header after `edit` and refreshes the size and digests
/// in the signature header, so only the intended change remains.
fn rewrite_header(
    bytes: &[u8],
    edit: impl FnOnce(&mut Entries),
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut package = Package::parse(&mut Cursor::new(bytes))?;
    let mut entries = package.metadata.header.get_all_entries()?;
    entries.retain(|(tag, _)| *tag != u32::from(IndexTag::RPMTAG_HEADERIMMUTABLE));
    edit(&mut entries);
    package.metadata.header = Header::from_entries(
        entries
            .into_iter()
            .map(|(tag, data)| HeaderEntry::new(tag, data)),
        IndexTag::RPMTAG_HEADERIMMUTABLE,
    );
    let header = package.metadata.header_bytes()?;
    let length = header.len() as u64 + package.payload.len() as u64;
    package.metadata.signature =
        SignatureHeaderBuilder::from_existing(&package.metadata.signature)?
            .calculate_digests(&header)
            .set_content_length(length)
            .build()?;
    write(&package)
}

fn rewrite_signature(
    bytes: &[u8],
    edit: impl FnOnce(&mut Entries),
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut package = Package::parse(&mut Cursor::new(bytes))?;
    let mut entries = package.metadata.signature.get_all_entries()?;
    entries.retain(|(tag, _)| *tag != u32::from(IndexSignatureTag::HEADER_SIGNATURES));
    edit(&mut entries);
    package.metadata.signature = Header::from_entries(
        entries
            .into_iter()
            .map(|(tag, data)| HeaderEntry::new(tag, data)),
        IndexSignatureTag::HEADER_SIGNATURES,
    );
    write(&package)
}

fn set(entries: &mut Entries, tag: IndexTag, data: IndexData) {
    let tag = u32::from(tag);
    entries.retain(|(existing, _)| *existing != tag);
    entries.push((tag, data));
}

fn remove(entries: &mut Entries, tag: IndexTag) {
    let tag = u32::from(tag);
    entries.retain(|(existing, _)| *existing != tag);
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Offsets of the main header index entries and the size of its store.
struct MainHeader {
    index: usize,
    entries: usize,
    store: usize,
    store_bytes: usize,
}

fn main_header(bytes: &[u8]) -> Result<MainHeader, Box<dyn Error>> {
    let start = usize::try_from(inspect(bytes)?.header_offset())?;
    let entries = get_u32(bytes, start + 8) as usize;
    let store_bytes = get_u32(bytes, start + 12) as usize;
    let index = start + 16;
    Ok(MainHeader {
        index,
        entries,
        store: index + entries * 16,
        store_bytes,
    })
}

/// The index position of the first main header entry with data type `kind`
/// (skipping the region entry).
fn entry_of_type(bytes: &[u8], header: &MainHeader, kind: u32) -> Option<usize> {
    (1..header.entries)
        .map(|entry| header.index + entry * 16)
        .find(|at| get_u32(bytes, at + 4) == kind)
}

fn malformed(result: Result<RpmInspection, InspectError>) -> bool {
    matches!(result, Err(InspectError::MalformedRpm { .. }))
}

fn unique_marker() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "pakomichi-rpm-scriptlet-ran-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A package with every scriptlet and trigger kind; each would create
/// `marker` if anything ran it.
fn scriptlet_package(marker: &std::path::Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let script = format!("touch '{}'\n", marker.display());
    let script = script.as_str();
    let mut builder = builder(BuildConfig::v4());
    builder
        .pre_install_script(script)
        .post_install_script(script)
        .pre_uninstall_script(script)
        .post_uninstall_script(script)
        .pre_trans_script(script)
        .post_trans_script(script)
        .pre_untrans_script(script)
        .post_untrans_script(script)
        .verify_script(script)
        .trigger_in("bash", None, script)
        .file_trigger_in("/usr/lib", None, script)
        .trans_file_trigger_in("/usr/lib", None, script);
    write(&builder.build()?)
}

#[test]
fn reads_identity_relations_and_payload_tags() -> TestResult {
    let bytes = normal_package()?;
    let inspection = inspect(&bytes)?;
    assert_eq!(inspection.name(), NAME);
    assert_eq!(inspection.epoch(), Some(2));
    assert_eq!(inspection.version(), "1.2.3");
    assert_eq!(inspection.release(), "1.el9");
    assert_eq!(inspection.arch(), "x86_64");
    assert_eq!(inspection.evr(), "2:1.2.3-1.el9");
    assert!(!inspection.is_source_package());
    assert_eq!(inspection.format_version(), None);
    assert_eq!(inspection.installed_size(), Some(10));

    let shown =
        |entries: &[RpmDependency]| entries.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert!(shown(inspection.requires()).contains(&"glibc >= 2.34".to_owned()));
    assert!(inspection.requires().iter().any(RpmDependency::is_rpmlib));
    assert!(shown(inspection.provides()).contains(&"probe-virtual".to_owned()));
    assert_eq!(shown(inspection.conflicts()), ["probe-old < 1.0"]);
    assert_eq!(shown(inspection.obsoletes()), ["probe-legacy"]);
    assert_eq!(shown(inspection.recommends()), ["probe-docs"]);
    assert_eq!(shown(inspection.suggests()), ["probe-extras"]);
    assert_eq!(shown(inspection.supplements()), ["probe-host"]);
    assert_eq!(shown(inspection.enhances()), ["probe-target"]);

    assert!(!inspection.has_scriptlets());
    assert_eq!(inspection.payload_format(), Some("cpio"));
    // The TEST ONLY builder writes no compressor tag for an uncompressed
    // payload; librpm would read the absence as gzip.
    assert_eq!(inspection.payload_compressor(), None);
    assert!(!inspection.has_signature());
    assert!(inspection.digests().contains(&RpmDigest::HeaderSha256));
    assert!(inspection.header_offset() > LEAD_SIZE as u64);
    assert_eq!(
        inspection.payload_offset() + inspection.payload_bytes(),
        bytes.len() as u64
    );
    Ok(())
}

#[test]
fn reads_rpm_v6_packages() -> TestResult {
    let mut builder = builder(BuildConfig::v6());
    let inspection = inspect(&write(&builder.build()?)?)?;
    assert_eq!(inspection.format_version(), Some(6));
    assert!(inspection.digests().contains(&RpmDigest::HeaderSha3_256));
    assert_eq!(inspection.evr(), "2:1.2.3-1.el9");
    Ok(())
}

#[test]
fn reports_payload_compressor_as_written() -> TestResult {
    let bytes = rewrite_header(&normal_package()?, |entries| {
        set(
            entries,
            IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
            IndexData::StringTag("zstd".to_owned()),
        );
        set(
            entries,
            IndexTag::RPMTAG_PAYLOADFLAGS,
            IndexData::StringTag("19".to_owned()),
        );
    })?;
    let inspection = inspect(&bytes)?;
    assert_eq!(inspection.payload_compressor(), Some("zstd"));
    assert_eq!(inspection.payload_flags(), Some("19"));
    Ok(())
}

#[test]
fn reports_every_scriptlet_kind_without_running_it() -> TestResult {
    let marker = unique_marker();
    let inspection = inspect(&scriptlet_package(&marker)?)?;
    assert_eq!(inspection.scriptlets(), RpmScriptlet::ALL);
    assert!(inspection.has_scriptlets());
    assert!(!marker.exists(), "a scriptlet ran during inspection");
    Ok(())
}

#[test]
fn interpreter_only_scriptlet_counts_as_present() -> TestResult {
    let mut builder = builder(BuildConfig::v4());
    builder.post_install_script(Scriptlet::new("").prog(vec!["/sbin/ldconfig"]));
    let bytes = rewrite_header(&write(&builder.build()?)?, |entries| {
        remove(entries, IndexTag::RPMTAG_POSTIN);
    })?;
    assert_eq!(inspect(&bytes)?.scriptlets(), [RpmScriptlet::Post]);
    Ok(())
}

#[test]
fn reads_many_dependencies() -> TestResult {
    let mut builder = builder(BuildConfig::v4());
    for index in 0..3000 {
        let name = format!("lib-probe-{index}");
        builder.requires(match index % 5 {
            0 => Dependency::any(name),
            1 => Dependency::eq(name, "1.0-1"),
            2 => Dependency::less_eq(name, "2:3.4"),
            3 => Dependency::greater(name, "0.1"),
            _ => Dependency::greater_eq(name, "5.6~rc1"),
        });
    }
    for index in 0..500 {
        builder
            .provides(Dependency::eq(format!("probe-cap-{index}"), "1.2.3"))
            .conflicts(Dependency::less(format!("probe-old-{index}"), "1"))
            .obsoletes(Dependency::less_eq(format!("probe-older-{index}"), "1"));
    }
    let inspection = inspect(&write(&builder.build()?)?)?;
    let ours: Vec<&RpmDependency> = inspection
        .requires()
        .iter()
        .filter(|entry| entry.name().starts_with("lib-probe-"))
        .collect();
    assert_eq!(ours.len(), 3000);
    let find = |name: &str| {
        ours.iter()
            .find(|entry| entry.name() == name)
            .map(ToString::to_string)
    };
    assert_eq!(find("lib-probe-0").as_deref(), Some("lib-probe-0"));
    assert_eq!(find("lib-probe-1").as_deref(), Some("lib-probe-1 = 1.0-1"));
    assert_eq!(find("lib-probe-2").as_deref(), Some("lib-probe-2 <= 2:3.4"));
    assert_eq!(find("lib-probe-3").as_deref(), Some("lib-probe-3 > 0.1"));
    assert_eq!(
        find("lib-probe-2999").as_deref(),
        Some("lib-probe-2999 >= 5.6~rc1")
    );
    assert!(inspection.provides().len() >= 500);
    assert_eq!(inspection.conflicts().len(), 500);
    assert_eq!(inspection.obsoletes().len(), 500);
    Ok(())
}

#[test]
fn reports_signature_tags_without_verifying_them() -> TestResult {
    let unsigned = normal_package()?;
    let inspection = inspect(&unsigned)?;
    assert!(!inspection.has_signature());
    assert!(inspection.signatures().is_empty());

    // Placeholder bytes, not a signature: presence is all the reader reports.
    let placeholder = || IndexData::Bin(b"TEST ONLY: not a signature".to_vec());
    let rsa = rewrite_signature(&unsigned, |entries| {
        entries.push((u32::from(IndexSignatureTag::RPMSIGTAG_RSA), placeholder()));
    })?;
    assert_eq!(inspect(&rsa)?.signatures(), [RpmSignature::HeaderRsa]);

    let all = rewrite_signature(&unsigned, |entries| {
        entries.push((u32::from(IndexSignatureTag::RPMSIGTAG_DSA), placeholder()));
        entries.push((u32::from(IndexSignatureTag::RPMSIGTAG_RSA), placeholder()));
        entries.push((
            u32::from(IndexSignatureTag::RPMSIGTAG_OPENPGP),
            IndexData::StringArray(vec!["VEVTVCBPTkxZ".to_owned()]),
        ));
        entries.push((u32::from(IndexSignatureTag::RPMSIGTAG_PGP), placeholder()));
        entries.push((u32::from(IndexSignatureTag::RPMSIGTAG_GPG), placeholder()));
        entries.push((SIGTAG_PGP5, placeholder()));
    })?;
    let inspection = inspect(&all)?;
    assert_eq!(inspection.signatures(), RpmSignature::ALL);
    assert!(inspection.has_signature());
    Ok(())
}

#[test]
fn every_truncation_is_rejected() -> TestResult {
    let bytes = normal_package()?;
    for cut in 0..bytes.len() {
        let result = inspect(&bytes[..cut]);
        if cut < LEAD_MAGIC.len() {
            assert!(
                matches!(result, Err(InspectError::NotRpm)),
                "cut {cut}: {result:?}"
            );
        } else {
            assert!(malformed(result), "cut {cut}");
        }
    }
    Ok(())
}

#[test]
fn trailing_bytes_are_rejected() -> TestResult {
    let mut bytes = normal_package()?;
    bytes.push(0);
    assert!(malformed(inspect(&bytes)));
    Ok(())
}

#[test]
fn single_byte_corruption_never_panics() -> TestResult {
    let bytes = normal_package()?;
    let end = usize::try_from(inspect(&bytes)?.payload_offset())?;
    let mut rejected = 0;
    for position in 0..end {
        for value in [0x00, 0xFF, bytes[position] ^ 0x80] {
            let mut corrupt = bytes.clone();
            corrupt[position] = value;
            if inspect(&corrupt).is_err() {
                rejected += 1;
            }
        }
    }
    // The point is that no mutation panics. Mutations of string contents,
    // the lead name, or the reserved space stay undetected: the reader
    // checks structure, not digests, which native RPM verifies.
    assert!(rejected > 0);
    println!("{rejected} of {} single-byte mutations rejected", end * 3);
    Ok(())
}

#[test]
fn rejects_files_that_are_not_rpm() -> TestResult {
    let (control, data) = minimal_deb_members("Package: probe\nVersion: 1\nArchitecture: all\n");
    let deb = ar(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar", &control),
        ("data.tar", &data),
    ]);
    let mut wrong_magic = normal_package()?;
    wrong_magic[0] = 0xEE;
    for bytes in [Vec::new(), deb, b"#!/bin/sh\n".to_vec(), wrong_magic] {
        let error = inspect(&bytes).err().ok_or("expected a rejection")?;
        assert!(matches!(error, InspectError::NotRpm), "{error:?}");
        assert_eq!(error.reason_code(), Some(ReasonCode::EArtifactMalformed));
    }
    Ok(())
}

#[test]
fn rejects_unsupported_lead_and_corrupt_header_magic() -> TestResult {
    let bytes = normal_package()?;
    let header_offset = usize::try_from(inspect(&bytes)?.header_offset())?;

    let mut old_lead = bytes.clone();
    old_lead[4] = 2;
    let mut signature_type = bytes.clone();
    signature_type[79] = 1;
    for corrupt in [old_lead, signature_type] {
        assert!(matches!(
            inspect(&corrupt),
            Err(InspectError::UnsupportedFormat { .. })
        ));
    }

    for at in [LEAD_SIZE, LEAD_SIZE + 3, header_offset, header_offset + 3] {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0x01;
        assert!(malformed(inspect(&corrupt)), "byte {at}");
    }
    Ok(())
}

#[test]
fn enforces_header_limits_before_allocating() -> TestResult {
    let bytes = normal_package()?;
    let header = main_header(&bytes)?;
    let start = header.index - 16;
    let too_large = |result: Result<RpmInspection, InspectError>| {
        matches!(result, Err(InspectError::RpmHeaderTooLarge { .. }))
    };

    let few_tags = InspectLimits {
        max_rpm_header_entries: 5,
        ..InspectLimits::default()
    };
    assert!(too_large(inspect_with(&bytes, &few_tags)));
    let small_signature = InspectLimits {
        max_rpm_signature_bytes: 16,
        ..InspectLimits::default()
    };
    assert!(too_large(inspect_with(&bytes, &small_signature)));

    // The hard caps of librpm hold even when the limits are raised.
    let unlimited = InspectLimits {
        max_rpm_signature_entries: u32::MAX,
        max_rpm_signature_bytes: u32::MAX,
        max_rpm_header_entries: u32::MAX,
        max_rpm_header_bytes: u32::MAX,
        ..InspectLimits::default()
    };
    for (at, value) in [
        (start + 8, RPM_HEADER_MAX_ENTRIES + 1),
        (start + 12, RPM_HEADER_MAX_BYTES + 1),
        (start + 12, u32::MAX),
        (LEAD_SIZE + 8, RPM_SIGNATURE_MAX_ENTRIES + 1),
        (LEAD_SIZE + 12, RPM_SIGNATURE_MAX_BYTES + 1),
    ] {
        let mut corrupt = bytes.clone();
        put_u32(&mut corrupt, at, value);
        assert!(
            too_large(inspect_with(&corrupt, &unlimited)),
            "{at}={value}"
        );
    }

    // Within the caps but beyond the file: rejected as truncated, without
    // allocating the declared size.
    for (at, value) in [
        (start + 12, RPM_HEADER_MAX_BYTES),
        (start + 8, 0xFFFF),
        (start + 8, 0),
    ] {
        let mut corrupt = bytes.clone();
        put_u32(&mut corrupt, at, value);
        assert!(
            malformed(inspect_with(&corrupt, &unlimited)),
            "{at}={value}"
        );
    }

    let small_package = InspectLimits {
        max_package_bytes: bytes.len() as u64 - 1,
        ..InspectLimits::default()
    };
    assert!(matches!(
        inspect_with(&bytes, &small_package),
        Err(InspectError::PackageTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn rejects_index_entries_outside_the_store() -> TestResult {
    let bytes = normal_package()?;
    let header = main_header(&bytes)?;
    let int32 = entry_of_type(&bytes, &header, TYPE_INT32).ok_or("no int32 entry")?;
    let string = entry_of_type(&bytes, &header, TYPE_STRING).ok_or("no string entry")?;
    let store = u32::try_from(header.store_bytes)?;

    let cases: [(usize, u32, &str); 9] = [
        (int32 + 8, u32::MAX, "negative offset"),
        (int32 + 8, store + 1, "offset past the store"),
        (int32 + 8, 1, "misaligned int32"),
        (int32 + 12, u32::MAX, "count overflow"),
        (int32 + 12, store, "count past the store"),
        (int32 + 4, 10, "unknown type"),
        (string + 12, 2, "string count"),
        // The store ends with the region trailer, which holds no NUL.
        (string + 8, store - 1, "unterminated string"),
        (
            header.index + 2 * 16,
            get_u32(&bytes, header.index + 16),
            "duplicate tag",
        ),
    ];
    for (at, value, case) in cases {
        let mut corrupt = bytes.clone();
        put_u32(&mut corrupt, at, value);
        assert!(malformed(inspect(&corrupt)), "{case}");
    }
    assert!(header.store > header.index);
    Ok(())
}

#[test]
fn validates_identity_tags() -> TestResult {
    let bytes = normal_package()?;
    let string = |value: &str| IndexData::StringTag(value.to_owned());
    let cases: [(IndexTag, Option<IndexData>, &str, bool); 7] = [
        (IndexTag::RPMTAG_NAME, None, "Name", true),
        (IndexTag::RPMTAG_NAME, Some(string("")), "Name", true),
        (
            IndexTag::RPMTAG_NAME,
            Some(string("../probe")),
            "Name",
            false,
        ),
        (
            IndexTag::RPMTAG_VERSION,
            Some(string("1.2-3")),
            "Version",
            false,
        ),
        (
            IndexTag::RPMTAG_RELEASE,
            Some(string("1 el9")),
            "Release",
            false,
        ),
        (IndexTag::RPMTAG_ARCH, Some(string("x86 64")), "Arch", false),
        (IndexTag::RPMTAG_EPOCH, Some(string("2")), "Epoch", false),
    ];
    for (tag, data, field, missing) in cases {
        let corrupt = rewrite_header(&bytes, |entries| match data {
            Some(data) => set(entries, tag, data),
            None => remove(entries, tag),
        })?;
        let result = inspect(&corrupt);
        let expected = if missing {
            matches!(result, Err(InspectError::MissingField { field: actual }) if actual == field)
        } else {
            matches!(result, Err(InspectError::InvalidField { field: actual, .. }) if actual == field)
        };
        assert!(expected, "{field}: {result:?}");
    }
    Ok(())
}

#[test]
fn rejects_mismatched_dependency_arrays() -> TestResult {
    let bytes = normal_package()?;
    let shorter = rewrite_header(&bytes, |entries| {
        let tag = u32::from(IndexTag::RPMTAG_REQUIREFLAGS);
        for (existing, data) in entries.iter_mut() {
            if *existing == tag
                && let IndexData::Int32(flags) = data
            {
                flags.pop();
            }
        }
    })?;
    let missing = rewrite_header(&bytes, |entries| {
        remove(entries, IndexTag::RPMTAG_CONFLICTVERSION);
    })?;
    for (corrupt, field) in [(shorter, "Requires"), (missing, "Conflicts")] {
        let result = inspect(&corrupt);
        assert!(
            matches!(result, Err(InspectError::InvalidField { field: actual, .. }) if actual == field),
            "{field}: {result:?}"
        );
    }
    Ok(())
}

/// Ad hoc evidence against packages built by other tools, such as the signed
/// samples shipped in the `rpm` crate source (`tests/assets`). Run with
/// `PAKOMICHI_RPM_SAMPLES=<dir> cargo test -- --ignored rpm_samples`.
#[test]
#[ignore = "needs PAKOMICHI_RPM_SAMPLES pointing at real RPM files"]
fn rpm_samples() -> TestResult {
    let root = PathBuf::from(
        std::env::var_os("PAKOMICHI_RPM_SAMPLES").ok_or("PAKOMICHI_RPM_SAMPLES is not set")?,
    );
    let mut pending = vec![root];
    let mut inspected = 0;
    while let Some(directory) = pending.pop() {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<_, _>>()?;
        paths.sort();
        for path in paths {
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rpm") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let inspection =
                inspect(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
            println!(
                "{}: {}-{}.{} source={} format={:?} compressor={:?} signatures={:?} digests={:?} scriptlets={:?} requires={}",
                path.display(),
                inspection.name(),
                inspection.evr(),
                inspection.arch(),
                inspection.is_source_package(),
                inspection.format_version(),
                inspection.payload_compressor(),
                inspection.signatures(),
                inspection.digests(),
                inspection.scriptlets(),
                inspection.requires().len(),
            );
            let text = path.to_string_lossy().replace('\\', "/");
            if text.contains("/signed/") {
                assert!(inspection.has_signature(), "{text}");
            } else {
                assert!(!inspection.has_signature(), "{text}");
            }
            if text.contains("scriptlets") && !text.contains("/SRPMS/") {
                assert!(inspection.has_scriptlets(), "{text}");
            }
            assert_eq!(
                inspection.is_source_package(),
                text.contains("/SRPMS/"),
                "{text}"
            );
            for compressor in ["gzip", "xz", "zstd"] {
                if text.contains(&format!("/{compressor}/")) {
                    assert_eq!(inspection.payload_compressor(), Some(compressor), "{text}");
                }
            }
            inspected += 1;
        }
    }
    println!("inspected {inspected} RPM files");
    assert!(inspected > 0);
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::{TestResult, scriptlet_package, unique_marker};
    use crate::inspect::runner::effective_uid;
    use crate::inspect::{InspectError, RpmInspector, RpmInspectorConfig, RpmScriptlet};

    const RPMDB_DIRECTORIES: [&str; 2] = ["/var/lib/rpm", "/usr/lib/sysimage/rpm"];

    /// SHA-256 of every regular file in the rpmdb directories that exist.
    fn rpmdb_state() -> std::io::Result<BTreeMap<PathBuf, String>> {
        let mut state = BTreeMap::new();
        for directory in RPMDB_DIRECTORIES.map(Path::new) {
            let Ok(entries) = fs::read_dir(directory) else {
                continue;
            };
            for entry in entries {
                let path = entry?.path();
                if fs::symlink_metadata(&path)?.is_file() {
                    state.insert(
                        path.clone(),
                        format!("{:x}", Sha256::digest(fs::read(&path)?)),
                    );
                }
            }
        }
        Ok(state)
    }

    fn inspector() -> Result<RpmInspector, InspectError> {
        RpmInspector::new(RpmInspectorConfig {
            allow_root: true,
            ..RpmInspectorConfig::default()
        })
    }

    #[test]
    fn inspector_reads_a_file_without_running_scriptlets_or_touching_the_rpmdb() -> TestResult {
        let marker = unique_marker();
        let package = marker.with_extension("rpm");
        fs::write(&package, scriptlet_package(&marker)?)?;
        let before = rpmdb_state()?;
        let result = inspector()?.inspect(&package);
        let after = rpmdb_state()?;
        fs::remove_file(&package)?;

        assert_eq!(result?.scriptlets(), RpmScriptlet::ALL);
        assert!(!marker.exists(), "a scriptlet ran during inspection");
        assert_eq!(before, after, "the rpmdb changed");
        if before.is_empty() {
            eprintln!("NOTE: no rpmdb on this host; only the scriptlet marker was checked");
        }
        Ok(())
    }

    #[test]
    fn inspector_refuses_symlinks_and_directories() -> TestResult {
        let marker = unique_marker();
        let package = marker.with_extension("rpm");
        let link = marker.with_extension("link");
        fs::write(&package, scriptlet_package(&marker)?)?;
        symlink(&package, &link)?;
        let inspector = inspector()?;
        let through_link = inspector.inspect(&link);
        let directory = inspector.inspect(&std::env::temp_dir());
        fs::remove_file(&link)?;
        fs::remove_file(&package)?;
        assert!(matches!(through_link, Err(InspectError::NotRegularFile)));
        assert!(matches!(directory, Err(InspectError::NotRegularFile)));
        Ok(())
    }

    #[test]
    fn inspector_refuses_root_by_default() -> TestResult {
        let result = RpmInspector::new(RpmInspectorConfig::default());
        if effective_uid()? == 0 {
            assert!(matches!(result, Err(InspectError::RunningAsRoot)));
        } else {
            assert!(result.is_ok());
        }
        Ok(())
    }
}
