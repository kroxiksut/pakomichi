// SPDX-License-Identifier: MIT OR Apache-2.0

//! RPM metadata from the lead, the signature header, and the main header.
//!
//! The reader works in-process and never touches the payload: it reads the
//! 96-byte lead and both headers sequentially, checks their envelope against
//! the inspection limits and librpm's own bounds before allocating, checks
//! every index entry against its data store, and only then hands the bytes to
//! the `rpm` crate (built without its `payload`, compression, and signature
//! features). The crate indexes into the data store without bounds checks, so
//! the envelope check is what keeps malformed input from panicking or
//! exhausting memory; it is not an optimisation.
//!
//! Nothing here verifies a signature or a digest. Signature presence is
//! reported for policy; verification belongs to the native RPM/DNF policy
//! (R-002). Relationship entries stay raw; resolving them belongs to the
//! family and dependency model.

use std::fmt;
use std::io::{self, Cursor, Read};

use rpm::{IndexSignatureTag, IndexTag, PackageMetadata};

use super::InspectLimits;
use super::error::InspectError;

const LEAD_SIZE: usize = 96;
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
/// `RPMSIGTYPE_HEADERSIG`, the only signature type librpm accepts in a lead.
const LEAD_SIGNATURE_TYPE: u16 = 5;
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
const INTRO_SIZE: usize = 16;
const ENTRY_SIZE: u64 = 16;

/// librpm's bounds (`hdrblobRead`): a signature header has at most 32 tags
/// and 64 MiB of data; a main header at most 65535 tags and 256 MiB.
pub const RPM_SIGNATURE_MAX_ENTRIES: u32 = 32;
pub const RPM_SIGNATURE_MAX_BYTES: u32 = 64 * 1024 * 1024;
pub const RPM_HEADER_MAX_ENTRIES: u32 = 0xFFFF;
pub const RPM_HEADER_MAX_BYTES: u32 = 0x0FFF_FFFF;

const MAX_IDENTITY_BYTES: usize = 256;

// Index entry data types.
const TYPE_NULL: u32 = 0;
const TYPE_CHAR: u32 = 1;
const TYPE_INT8: u32 = 2;
const TYPE_INT16: u32 = 3;
const TYPE_INT32: u32 = 4;
const TYPE_INT64: u32 = 5;
const TYPE_STRING: u32 = 6;
const TYPE_BIN: u32 = 7;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18N_STRING: u32 = 9;

// `RPMSENSE_*` comparison and marker bits of a dependency.
const SENSE_LESS: u32 = 1 << 1;
const SENSE_GREATER: u32 = 1 << 2;
const SENSE_EQUAL: u32 = 1 << 3;
const SENSE_RPMLIB: u32 = 1 << 24;

/// Signature-header tags that carry no IndexSignatureTag constant.
const SIGTAG_PGP5: u32 = 1006;

/// Scripts and triggers that librpm runs. Only their presence is recorded;
/// their content is never executed or interpreted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RpmScriptlet {
    Pre,
    Post,
    PreUn,
    PostUn,
    PreTrans,
    PostTrans,
    /// `%preuntrans` (RPM 4.18 and later).
    PreUnTrans,
    /// `%postuntrans` (RPM 4.18 and later).
    PostUnTrans,
    /// `%verifyscript`, run by `rpm --verify`.
    Verify,
    /// `%triggerprein`, `%triggerin`, `%triggerun`, `%triggerpostun`.
    Trigger,
    /// `%filetriggerin`, `%filetriggerun`, `%filetriggerpostun`.
    FileTrigger,
    /// `%transfiletriggerin`, `%transfiletriggerun`, `%transfiletriggerpostun`.
    TransFileTrigger,
}

impl RpmScriptlet {
    pub const ALL: [Self; 12] = [
        Self::Pre,
        Self::Post,
        Self::PreUn,
        Self::PostUn,
        Self::PreTrans,
        Self::PostTrans,
        Self::PreUnTrans,
        Self::PostUnTrans,
        Self::Verify,
        Self::Trigger,
        Self::FileTrigger,
        Self::TransFileTrigger,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::Post => "post",
            Self::PreUn => "preun",
            Self::PostUn => "postun",
            Self::PreTrans => "pretrans",
            Self::PostTrans => "posttrans",
            Self::PreUnTrans => "preuntrans",
            Self::PostUnTrans => "postuntrans",
            Self::Verify => "verifyscript",
            Self::Trigger => "trigger",
            Self::FileTrigger => "filetrigger",
            Self::TransFileTrigger => "transfiletrigger",
        }
    }

    /// The script tag and the interpreter tag. A scriptlet written as
    /// `%post -p /sbin/ldconfig` has only the interpreter tag, and librpm
    /// still runs it, so either tag means "present".
    const fn tags(self) -> (IndexTag, IndexTag) {
        match self {
            Self::Pre => (IndexTag::RPMTAG_PREIN, IndexTag::RPMTAG_PREINPROG),
            Self::Post => (IndexTag::RPMTAG_POSTIN, IndexTag::RPMTAG_POSTINPROG),
            Self::PreUn => (IndexTag::RPMTAG_PREUN, IndexTag::RPMTAG_PREUNPROG),
            Self::PostUn => (IndexTag::RPMTAG_POSTUN, IndexTag::RPMTAG_POSTUNPROG),
            Self::PreTrans => (IndexTag::RPMTAG_PRETRANS, IndexTag::RPMTAG_PRETRANSPROG),
            Self::PostTrans => (IndexTag::RPMTAG_POSTTRANS, IndexTag::RPMTAG_POSTTRANSPROG),
            Self::PreUnTrans => (IndexTag::RPMTAG_PREUNTRANS, IndexTag::RPMTAG_PREUNTRANSPROG),
            Self::PostUnTrans => (
                IndexTag::RPMTAG_POSTUNTRANS,
                IndexTag::RPMTAG_POSTUNTRANSPROG,
            ),
            Self::Verify => (
                IndexTag::RPMTAG_VERIFYSCRIPT,
                IndexTag::RPMTAG_VERIFYSCRIPTPROG,
            ),
            Self::Trigger => (
                IndexTag::RPMTAG_TRIGGERSCRIPTS,
                IndexTag::RPMTAG_TRIGGERSCRIPTPROG,
            ),
            Self::FileTrigger => (
                IndexTag::RPMTAG_FILETRIGGERSCRIPTS,
                IndexTag::RPMTAG_FILETRIGGERSCRIPTPROG,
            ),
            Self::TransFileTrigger => (
                IndexTag::RPMTAG_TRANSFILETRIGGERSCRIPTS,
                IndexTag::RPMTAG_TRANSFILETRIGGERSCRIPTPROG,
            ),
        }
    }
}

/// A signature tag present in the signature header. Presence says nothing
/// about validity or about the key; native RPM/DNF policy verifies it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RpmSignature {
    /// `RPMSIGTAG_DSA`: an OpenPGP header-only signature (DSA, ECDSA, EdDSA).
    HeaderDsa,
    /// `RPMSIGTAG_RSA`: an OpenPGP header-only RSA signature.
    HeaderRsa,
    /// `RPMSIGTAG_OPENPGP`: the RPM v6 list of OpenPGP header signatures.
    OpenPgp,
    /// `RPMSIGTAG_PGP`: a legacy header-and-payload RSA signature.
    LegacyPgp,
    /// `RPMSIGTAG_GPG`: a legacy header-and-payload DSA signature.
    LegacyGpg,
    /// `RPMSIGTAG_PGP5`: an obsolete header-and-payload signature.
    LegacyPgp5,
}

impl RpmSignature {
    pub const ALL: [Self; 6] = [
        Self::HeaderDsa,
        Self::HeaderRsa,
        Self::OpenPgp,
        Self::LegacyPgp,
        Self::LegacyGpg,
        Self::LegacyPgp5,
    ];

    const fn tag(self) -> u32 {
        match self {
            Self::HeaderDsa => IndexSignatureTag::RPMSIGTAG_DSA as u32,
            Self::HeaderRsa => IndexSignatureTag::RPMSIGTAG_RSA as u32,
            Self::OpenPgp => IndexSignatureTag::RPMSIGTAG_OPENPGP as u32,
            Self::LegacyPgp => IndexSignatureTag::RPMSIGTAG_PGP as u32,
            Self::LegacyGpg => IndexSignatureTag::RPMSIGTAG_GPG as u32,
            Self::LegacyPgp5 => SIGTAG_PGP5,
        }
    }
}

/// A digest tag present in the signature header; not checked here.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RpmDigest {
    /// `RPMSIGTAG_MD5` over header and payload.
    Md5,
    /// `RPMSIGTAG_SHA1` over the header.
    HeaderSha1,
    /// `RPMSIGTAG_SHA256` over the header.
    HeaderSha256,
    /// `RPMSIGTAG_SHA3_256` over the header (RPM v6).
    HeaderSha3_256,
}

impl RpmDigest {
    pub const ALL: [Self; 4] = [
        Self::Md5,
        Self::HeaderSha1,
        Self::HeaderSha256,
        Self::HeaderSha3_256,
    ];

    const fn tag(self) -> IndexSignatureTag {
        match self {
            Self::Md5 => IndexSignatureTag::RPMSIGTAG_MD5,
            Self::HeaderSha1 => IndexSignatureTag::RPMSIGTAG_SHA1,
            Self::HeaderSha256 => IndexSignatureTag::RPMSIGTAG_SHA256,
            Self::HeaderSha3_256 => IndexSignatureTag::RPMSIGTAG_SHA3_256,
        }
    }
}

/// One raw relationship entry as the header stores it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmDependency {
    name: String,
    flags: u32,
    version: String,
}

impl RpmDependency {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The raw `RPMSENSE_*` bits, including markers such as `rpmlib()`,
    /// `Requires(pre)`, or rich-dependency context.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// The version or EVR; empty for an unversioned entry.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The comparison operator encoded in the flags, if any.
    pub const fn operator(&self) -> Option<&'static str> {
        match self.flags & (SENSE_LESS | SENSE_GREATER | SENSE_EQUAL) {
            SENSE_LESS => Some("<"),
            SENSE_GREATER => Some(">"),
            SENSE_EQUAL => Some("="),
            value if value == SENSE_LESS | SENSE_EQUAL => Some("<="),
            value if value == SENSE_GREATER | SENSE_EQUAL => Some(">="),
            _ => None,
        }
    }

    /// An `rpmlib(...)` feature requirement of librpm itself.
    pub const fn is_rpmlib(&self) -> bool {
        self.flags & SENSE_RPMLIB != 0
    }
}

impl fmt::Display for RpmDependency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.operator() {
            Some(operator) if !self.version.is_empty() => {
                write!(formatter, "{} {operator} {}", self.name, self.version)
            }
            _ => formatter.write_str(&self.name),
        }
    }
}

/// Everything the inspector learned about one RPM package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmInspection {
    name: String,
    epoch: Option<u32>,
    version: String,
    release: String,
    arch: String,
    source_package: bool,
    format_version: Option<u32>,
    installed_size: Option<u64>,
    requires: Vec<RpmDependency>,
    provides: Vec<RpmDependency>,
    conflicts: Vec<RpmDependency>,
    obsoletes: Vec<RpmDependency>,
    recommends: Vec<RpmDependency>,
    suggests: Vec<RpmDependency>,
    supplements: Vec<RpmDependency>,
    enhances: Vec<RpmDependency>,
    scriptlets: Vec<RpmScriptlet>,
    payload_format: Option<String>,
    payload_compressor: Option<String>,
    payload_flags: Option<String>,
    signatures: Vec<RpmSignature>,
    digests: Vec<RpmDigest>,
    header_offset: u64,
    payload_offset: u64,
    payload_bytes: u64,
}

impl RpmInspection {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn epoch(&self) -> Option<u32> {
        self.epoch
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// `[epoch:]version-release`, as RPM prints an EVR.
    pub fn evr(&self) -> String {
        match self.epoch {
            Some(epoch) => format!("{epoch}:{}-{}", self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    /// A source package (SRPM) rather than a binary one.
    pub const fn is_source_package(&self) -> bool {
        self.source_package
    }

    /// `RPMTAG_RPMFORMAT` (6 for RPM v6 packages); absent in RPM v4.
    pub const fn format_version(&self) -> Option<u32> {
        self.format_version
    }

    /// `RPMTAG_LONGSIZE` or `RPMTAG_SIZE`: the installed size in bytes.
    pub const fn installed_size(&self) -> Option<u64> {
        self.installed_size
    }

    pub fn requires(&self) -> &[RpmDependency] {
        &self.requires
    }

    pub fn provides(&self) -> &[RpmDependency] {
        &self.provides
    }

    pub fn conflicts(&self) -> &[RpmDependency] {
        &self.conflicts
    }

    pub fn obsoletes(&self) -> &[RpmDependency] {
        &self.obsoletes
    }

    /// Weak forward dependency; DNF installs these by default.
    pub fn recommends(&self) -> &[RpmDependency] {
        &self.recommends
    }

    pub fn suggests(&self) -> &[RpmDependency] {
        &self.suggests
    }

    /// Weak reverse dependency; DNF installs these by default.
    pub fn supplements(&self) -> &[RpmDependency] {
        &self.supplements
    }

    pub fn enhances(&self) -> &[RpmDependency] {
        &self.enhances
    }

    /// Scriptlets and triggers present, in [`RpmScriptlet::ALL`] order.
    pub fn scriptlets(&self) -> &[RpmScriptlet] {
        &self.scriptlets
    }

    pub fn has_scriptlets(&self) -> bool {
        !self.scriptlets.is_empty()
    }

    /// `RPMTAG_PAYLOADFORMAT`, normally `cpio`.
    pub fn payload_format(&self) -> Option<&str> {
        self.payload_format.as_deref()
    }

    /// `RPMTAG_PAYLOADCOMPRESSOR` as written; librpm reads an absent tag as
    /// `gzip`.
    pub fn payload_compressor(&self) -> Option<&str> {
        self.payload_compressor.as_deref()
    }

    /// `RPMTAG_PAYLOADFLAGS`, usually the compression level.
    pub fn payload_flags(&self) -> Option<&str> {
        self.payload_flags.as_deref()
    }

    /// Signature tags present, in [`RpmSignature::ALL`] order. None of them
    /// was verified.
    pub fn signatures(&self) -> &[RpmSignature] {
        &self.signatures
    }

    /// Whether the signature header carries any signature tag.
    pub fn has_signature(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Digest tags present, in [`RpmDigest::ALL`] order. None was checked.
    pub fn digests(&self) -> &[RpmDigest] {
        &self.digests
    }

    /// Byte offset of the main header (after the signature header padding).
    pub const fn header_offset(&self) -> u64 {
        self.header_offset
    }

    /// Byte offset of the payload, which was not read.
    pub const fn payload_offset(&self) -> u64 {
        self.payload_offset
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
}

/// Which header an envelope check concerns.
#[derive(Clone, Copy)]
enum Section {
    Signature,
    Main,
}

impl Section {
    const fn name(self) -> &'static str {
        match self {
            Self::Signature => "signature header",
            Self::Main => "main header",
        }
    }

    fn limits(self, limits: &InspectLimits) -> (u32, u32) {
        match self {
            Self::Signature => (
                limits
                    .max_rpm_signature_entries
                    .min(RPM_SIGNATURE_MAX_ENTRIES),
                limits.max_rpm_signature_bytes.min(RPM_SIGNATURE_MAX_BYTES),
            ),
            Self::Main => (
                limits.max_rpm_header_entries.min(RPM_HEADER_MAX_ENTRIES),
                limits.max_rpm_header_bytes.min(RPM_HEADER_MAX_BYTES),
            ),
        }
    }
}

/// Reads the package metadata from `input`, which holds a package of
/// `file_size` bytes positioned at its start. Reads stop at the payload.
pub(crate) fn inspect_rpm(
    input: &mut impl Read,
    file_size: u64,
    limits: &InspectLimits,
) -> Result<RpmInspection, InspectError> {
    if file_size > limits.max_package_bytes {
        return Err(InspectError::PackageTooLarge {
            size: file_size,
            limit: limits.max_package_bytes,
        });
    }

    let mut metadata = vec![0_u8; LEAD_SIZE];
    let lead_length = read_up_to(input, &mut metadata)?;
    if lead_length < LEAD_MAGIC.len() || metadata[..LEAD_MAGIC.len()] != LEAD_MAGIC {
        return Err(InspectError::NotRpm);
    }
    if lead_length < LEAD_SIZE {
        return Err(malformed("the lead is truncated"));
    }
    check_lead(&metadata)?;

    read_header(input, file_size, Section::Signature, limits, &mut metadata)?;
    let padding = (8 - metadata.len() % 8) % 8;
    read_exact_within(input, file_size, padding, &mut metadata)?;
    let header_offset = metadata.len() as u64;
    read_header(input, file_size, Section::Main, limits, &mut metadata)?;
    let payload_offset = metadata.len() as u64;

    let parsed = PackageMetadata::parse(&mut Cursor::new(metadata.as_slice()))
        .map_err(|_| malformed("the header parser rejected the package"))?;
    drop(metadata);

    let payload_bytes = file_size - payload_offset;
    check_declared_size(&parsed, file_size - header_offset)?;
    build_inspection(&parsed, header_offset, payload_offset, payload_bytes)
}

fn check_lead(lead: &[u8]) -> Result<(), InspectError> {
    if !matches!(lead[4], 3 | 4) {
        return Err(InspectError::UnsupportedFormat {
            problem: "the lead major version is not 3 or 4",
        });
    }
    if u16::from_be_bytes([lead[78], lead[79]]) != LEAD_SIGNATURE_TYPE {
        return Err(InspectError::UnsupportedFormat {
            problem: "the lead signature type is not a header signature",
        });
    }
    Ok(())
}

/// Reads one header (intro, index, data store) into `out` after checking
/// its declared size against the limits and the remaining file.
fn read_header(
    input: &mut impl Read,
    file_size: u64,
    section: Section,
    limits: &InspectLimits,
    out: &mut Vec<u8>,
) -> Result<(), InspectError> {
    let start = out.len();
    read_exact_within(input, file_size, INTRO_SIZE, out)?;
    let intro = &out[start..];
    if intro[..4] != HEADER_MAGIC {
        return Err(malformed(match section {
            Section::Signature => "the signature header magic is wrong",
            Section::Main => "the main header magic is wrong",
        }));
    }
    let entries = u32::from_be_bytes([intro[8], intro[9], intro[10], intro[11]]);
    let bytes = u32::from_be_bytes([intro[12], intro[13], intro[14], intro[15]]);
    let (max_entries, max_bytes) = section.limits(limits);
    if entries > max_entries || bytes > max_bytes {
        return Err(InspectError::RpmHeaderTooLarge {
            header: section.name(),
            entries,
            bytes,
        });
    }
    if entries == 0 {
        return Err(malformed("a header has no index entries"));
    }

    let length = u64::from(entries) * ENTRY_SIZE + u64::from(bytes);
    let length = usize::try_from(length).map_err(|_| malformed("a header is too large"))?;
    read_exact_within(input, file_size, length, out)?;
    let index_end = start + INTRO_SIZE + entries as usize * ENTRY_SIZE as usize;
    check_index(&out[start + INTRO_SIZE..index_end], &out[index_end..])
}

/// librpm's per-entry checks: a known type, an offset inside the store,
/// natural alignment, and data that ends inside the store. Duplicate tags are
/// rejected because the crate and librpm could pick different copies.
fn check_index(index: &[u8], store: &[u8]) -> Result<(), InspectError> {
    let mut tags = Vec::with_capacity(index.len() / ENTRY_SIZE as usize);
    for entry in index.chunks_exact(ENTRY_SIZE as usize) {
        let word = |at: usize| {
            u32::from_be_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
        };
        let (tag, kind, offset, count) = (word(0), word(4), word(8), word(12));
        tags.push(tag);

        let offset = usize::try_from(i32::from_be_bytes(offset.to_be_bytes()))
            .map_err(|_| malformed("an index entry has a negative offset"))?;
        let rest = store
            .get(offset..)
            .ok_or_else(|| malformed("an index entry points outside the data store"))?;
        let count = count as usize;
        let fixed = |width: usize| -> Result<(), InspectError> {
            if offset % width != 0 {
                return Err(malformed("an index entry is misaligned"));
            }
            match count.checked_mul(width) {
                Some(length) if length <= rest.len() => Ok(()),
                _ => Err(malformed("an index entry runs past the data store")),
            }
        };
        match kind {
            TYPE_NULL => {}
            TYPE_CHAR | TYPE_INT8 | TYPE_BIN => fixed(1)?,
            TYPE_INT16 => fixed(2)?,
            TYPE_INT32 => fixed(4)?,
            TYPE_INT64 => fixed(8)?,
            TYPE_STRING if count != 1 => {
                return Err(malformed("a string entry has a count other than one"));
            }
            TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18N_STRING => {
                let mut remaining = rest;
                for _ in 0..count {
                    let end = remaining
                        .iter()
                        .position(|byte| *byte == 0)
                        .ok_or_else(|| malformed("a string entry is not terminated"))?;
                    remaining = &remaining[end + 1..];
                }
            }
            _ => return Err(malformed("an index entry has an unknown data type")),
        }
    }
    tags.sort_unstable();
    if tags.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(malformed("a header repeats a tag"));
    }
    Ok(())
}

/// `RPMSIGTAG_LONGSIZE`/`RPMSIGTAG_SIZE` cover the main header and the
/// payload. A difference means a truncated or extended file.
fn check_declared_size(parsed: &PackageMetadata, actual: u64) -> Result<(), InspectError> {
    let signature = &parsed.signature;
    let declared = match signature.get_entry_data_as_u64(IndexSignatureTag::RPMSIGTAG_LONGSIZE) {
        Ok(size) => Some(size),
        Err(_) if signature.entry_is_present(IndexSignatureTag::RPMSIGTAG_LONGSIZE) => {
            return Err(malformed("the signature header size tag is invalid"));
        }
        Err(_) => match signature.get_entry_data_as_u32(IndexSignatureTag::RPMSIGTAG_SIZE) {
            Ok(size) => Some(u64::from(size)),
            Err(_) if signature.entry_is_present(IndexSignatureTag::RPMSIGTAG_SIZE) => {
                return Err(malformed("the signature header size tag is invalid"));
            }
            Err(_) => None,
        },
    };
    match declared {
        Some(declared) if declared != actual => Err(malformed(
            "the file size differs from the size in the signature header",
        )),
        _ => Ok(()),
    }
}

fn build_inspection(
    parsed: &PackageMetadata,
    header_offset: u64,
    payload_offset: u64,
    payload_bytes: u64,
) -> Result<RpmInspection, InspectError> {
    let header = &parsed.header;
    let name = identity(parsed, IndexTag::RPMTAG_NAME, "Name", is_name)?;
    let version = identity(parsed, IndexTag::RPMTAG_VERSION, "Version", is_version)?;
    let release = identity(parsed, IndexTag::RPMTAG_RELEASE, "Release", is_version)?;
    let arch = identity(parsed, IndexTag::RPMTAG_ARCH, "Arch", is_arch)?;
    let epoch = optional_u32(parsed, IndexTag::RPMTAG_EPOCH, "Epoch")?;
    let format_version = optional_u32(parsed, IndexTag::RPMTAG_RPMFORMAT, "RpmFormat")?;
    let installed_size = if header.entry_is_present(IndexTag::RPMTAG_LONGSIZE) {
        match header.get_entry_data_as_u64_array(IndexTag::RPMTAG_LONGSIZE) {
            Ok(sizes) if sizes.len() == 1 => sizes.first().copied(),
            _ => return Err(invalid("LongSize", "not a single 64-bit integer")),
        }
    } else {
        optional_u32(parsed, IndexTag::RPMTAG_SIZE, "Size")?.map(u64::from)
    };

    let relation =
        |field, names, flags, versions| dependencies(parsed, field, names, flags, versions);
    Ok(RpmInspection {
        name,
        epoch,
        version,
        release,
        arch,
        source_package: parsed.is_source_package(),
        format_version,
        installed_size,
        requires: relation(
            "Requires",
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREFLAGS,
            IndexTag::RPMTAG_REQUIREVERSION,
        )?,
        provides: relation(
            "Provides",
            IndexTag::RPMTAG_PROVIDENAME,
            IndexTag::RPMTAG_PROVIDEFLAGS,
            IndexTag::RPMTAG_PROVIDEVERSION,
        )?,
        conflicts: relation(
            "Conflicts",
            IndexTag::RPMTAG_CONFLICTNAME,
            IndexTag::RPMTAG_CONFLICTFLAGS,
            IndexTag::RPMTAG_CONFLICTVERSION,
        )?,
        obsoletes: relation(
            "Obsoletes",
            IndexTag::RPMTAG_OBSOLETENAME,
            IndexTag::RPMTAG_OBSOLETEFLAGS,
            IndexTag::RPMTAG_OBSOLETEVERSION,
        )?,
        recommends: relation(
            "Recommends",
            IndexTag::RPMTAG_RECOMMENDNAME,
            IndexTag::RPMTAG_RECOMMENDFLAGS,
            IndexTag::RPMTAG_RECOMMENDVERSION,
        )?,
        suggests: relation(
            "Suggests",
            IndexTag::RPMTAG_SUGGESTNAME,
            IndexTag::RPMTAG_SUGGESTFLAGS,
            IndexTag::RPMTAG_SUGGESTVERSION,
        )?,
        supplements: relation(
            "Supplements",
            IndexTag::RPMTAG_SUPPLEMENTNAME,
            IndexTag::RPMTAG_SUPPLEMENTFLAGS,
            IndexTag::RPMTAG_SUPPLEMENTVERSION,
        )?,
        enhances: relation(
            "Enhances",
            IndexTag::RPMTAG_ENHANCENAME,
            IndexTag::RPMTAG_ENHANCEFLAGS,
            IndexTag::RPMTAG_ENHANCEVERSION,
        )?,
        scriptlets: RpmScriptlet::ALL
            .into_iter()
            .filter(|scriptlet| {
                let (script, program) = scriptlet.tags();
                header.entry_is_present(script) || header.entry_is_present(program)
            })
            .collect(),
        payload_format: optional_string(parsed, IndexTag::RPMTAG_PAYLOADFORMAT, "PayloadFormat")?,
        payload_compressor: optional_string(
            parsed,
            IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
            "PayloadCompressor",
        )?,
        payload_flags: optional_string(parsed, IndexTag::RPMTAG_PAYLOADFLAGS, "PayloadFlags")?,
        signatures: RpmSignature::ALL
            .into_iter()
            .filter(|signature| parsed.signature.entry_is_present(signature.tag()))
            .collect(),
        digests: RpmDigest::ALL
            .into_iter()
            .filter(|digest| parsed.signature.entry_is_present(digest.tag()))
            .collect(),
        header_offset,
        payload_offset,
        payload_bytes,
    })
}

fn identity(
    parsed: &PackageMetadata,
    tag: IndexTag,
    field: &'static str,
    valid: fn(&str) -> bool,
) -> Result<String, InspectError> {
    if !parsed.header.entry_is_present(tag) {
        return Err(InspectError::MissingField { field });
    }
    let value = parsed
        .header
        .get_entry_data_as_string(tag)
        .map_err(|_| invalid(field, "not a single UTF-8 string"))?;
    if value.is_empty() {
        return Err(InspectError::MissingField { field });
    }
    if value.len() > MAX_IDENTITY_BYTES || !valid(value) {
        return Err(invalid(field, "contains characters RPM does not allow"));
    }
    Ok(value.to_owned())
}

fn optional_u32(
    parsed: &PackageMetadata,
    tag: IndexTag,
    field: &'static str,
) -> Result<Option<u32>, InspectError> {
    if !parsed.header.entry_is_present(tag) {
        return Ok(None);
    }
    match parsed.header.get_entry_data_as_u32_array(tag) {
        Ok(values) if values.len() == 1 => Ok(values.first().copied()),
        _ => Err(invalid(field, "not a single 32-bit integer")),
    }
}

fn optional_string(
    parsed: &PackageMetadata,
    tag: IndexTag,
    field: &'static str,
) -> Result<Option<String>, InspectError> {
    if !parsed.header.entry_is_present(tag) {
        return Ok(None);
    }
    parsed
        .header
        .get_entry_data_as_string(tag)
        .map(|value| Some(value.to_owned()))
        .map_err(|_| invalid(field, "not a single UTF-8 string"))
}

/// The three parallel arrays of one relationship kind. All absent means no
/// entries; any other mismatch is rejected rather than truncated.
fn dependencies(
    parsed: &PackageMetadata,
    field: &'static str,
    names_tag: IndexTag,
    flags_tag: IndexTag,
    versions_tag: IndexTag,
) -> Result<Vec<RpmDependency>, InspectError> {
    let header = &parsed.header;
    let present = [names_tag, flags_tag, versions_tag].map(|tag| header.entry_is_present(tag));
    if present == [false; 3] {
        return Ok(Vec::new());
    }
    let broken = || invalid(field, "the name, flag, and version arrays do not match");
    if present != [true; 3] {
        return Err(broken());
    }
    let names = header
        .get_entry_data_as_string_array(names_tag)
        .map_err(|_| broken())?;
    let flags = header
        .get_entry_data_as_u32_array(flags_tag)
        .map_err(|_| broken())?;
    let versions = header
        .get_entry_data_as_string_array(versions_tag)
        .map_err(|_| broken())?;
    if names.len() != flags.len() || names.len() != versions.len() {
        return Err(broken());
    }
    if names.iter().any(|name| name.is_empty()) {
        return Err(invalid(field, "an entry has an empty name"));
    }
    Ok(names
        .into_iter()
        .zip(flags)
        .zip(versions)
        .map(|((name, flags), version)| RpmDependency {
            name: name.to_owned(),
            flags,
            version: version.to_owned(),
        })
        .collect())
}

/// rpmbuild's character set for `Name`, without macro characters: an
/// alphanumeric or `_` first, then alphanumerics and `._+-`.
fn is_name(name: &str) -> bool {
    name.starts_with(|character: char| character.is_ascii_alphanumeric() || character == '_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

/// rpmbuild's character set for `Version` and `Release`, without macro
/// characters; `-` would make the NEVRA ambiguous.
fn is_version(version: &str) -> bool {
    version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._+~^".contains(&byte))
}

fn is_arch(arch: &str) -> bool {
    arch.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Fills `buffer` as far as the input allows and returns the length read.
fn read_up_to(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, InspectError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(InspectError::Io {
                    operation: "read the package",
                    source,
                });
            }
        }
    }
    Ok(filled)
}

/// Appends exactly `length` bytes to `out`. The length is checked against
/// the file size first, so a declared size never allocates more than the
/// file holds.
fn read_exact_within(
    input: &mut impl Read,
    file_size: u64,
    length: usize,
    out: &mut Vec<u8>,
) -> Result<(), InspectError> {
    let start = out.len();
    let end = start
        .checked_add(length)
        .filter(|end| *end as u64 <= file_size)
        .ok_or_else(|| malformed("the package metadata is truncated"))?;
    out.resize(end, 0);
    if read_up_to(input, &mut out[start..])? != length {
        return Err(malformed("the package metadata is truncated"));
    }
    Ok(())
}

const fn malformed(problem: &'static str) -> InspectError {
    InspectError::MalformedRpm { problem }
}

const fn invalid(field: &'static str, problem: &'static str) -> InspectError {
    InspectError::InvalidField { field, problem }
}

#[cfg(target_os = "linux")]
pub use linux::{RpmInspector, RpmInspectorConfig};

#[cfg(target_os = "linux")]
mod linux {
    use std::io::BufReader;
    use std::path::Path;

    use super::{InspectLimits, RpmInspection, inspect_rpm};
    use crate::inspect::error::InspectError;
    use crate::inspect::runner::{open_package, refuse_root};

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct RpmInspectorConfig {
        pub limits: InspectLimits,
        /// TEST ONLY: permit effective UID 0. A deployed inspector runs as
        /// an unprivileged user and leaves this `false`.
        pub allow_root: bool,
    }

    /// Reads RPM metadata in-process without installing, unpacking, or
    /// running scriptlets, and without the `rpm` tools or an rpmdb.
    #[derive(Debug)]
    pub struct RpmInspector {
        config: RpmInspectorConfig,
    }

    impl RpmInspector {
        pub fn new(config: RpmInspectorConfig) -> Result<Self, InspectError> {
            refuse_root(config.allow_root)?;
            Ok(Self { config })
        }

        /// Inspects the package at `path`, which must be a regular file and
        /// not a symlink.
        pub fn inspect(&self, path: &Path) -> Result<RpmInspection, InspectError> {
            refuse_root(self.config.allow_root)?;
            let file = open_package(path)?;
            let size = file
                .metadata()
                .map_err(|source| InspectError::Io {
                    operation: "inspect the package file",
                    source,
                })?
                .len();
            inspect_rpm(&mut BufReader::new(file), size, &self.config.limits)
        }
    }
}

#[cfg(test)]
#[path = "rpm_reader_tests.rs"]
mod tests;
