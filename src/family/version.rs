// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native version ordering of dpkg and RPM.
//!
//! Versions are compared with the algorithm of each package manager, never
//! lexicographically: `1.10` is newer than `1.9`, `1.0~rc1` is older than
//! `1.0`, and dpkg treats `1.0` and `1.00` as the same version. The
//! algorithms follow dpkg `verrevcmp` (`lib/dpkg/version.c`) and RPM
//! `rpmvercmp`/`rpmverOverlap` (`rpmio/rpmvercmp.c`, `lib/rpmver.c`); the
//! shared vectors in `tests/data/native-versions.tsv` are checked against
//! both these functions and the native tools
//! (`scripts/check-native-versions.py`).

use std::cmp::Ordering;
use std::fmt;

/// A comparison operator of a dependency or a versioned `Provides`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Op {
    /// DEB `<<`, RPM `<`.
    Less,
    /// DEB `<=` (and the obsolete `<`), RPM `<=`.
    LessEqual,
    Equal,
    /// DEB `>=` (and the obsolete `>`), RPM `>=`.
    GreaterEqual,
    /// DEB `>>`, RPM `>`.
    Greater,
}

impl Op {
    /// Whether `ordering` (candidate compared with the constraint version)
    /// satisfies this operator.
    pub const fn accepts(self, ordering: Ordering) -> bool {
        match self {
            Self::Less => matches!(ordering, Ordering::Less),
            Self::LessEqual => !matches!(ordering, Ordering::Greater),
            Self::Equal => matches!(ordering, Ordering::Equal),
            Self::GreaterEqual => !matches!(ordering, Ordering::Less),
            Self::Greater => matches!(ordering, Ordering::Greater),
        }
    }

    const fn has_less(self) -> bool {
        matches!(self, Self::Less | Self::LessEqual)
    }

    const fn has_equal(self) -> bool {
        matches!(self, Self::LessEqual | Self::Equal | Self::GreaterEqual)
    }

    const fn has_greater(self) -> bool {
        matches!(self, Self::Greater | Self::GreaterEqual)
    }

    /// The DEB spelling.
    pub const fn deb(self) -> &'static str {
        match self {
            Self::Less => "<<",
            Self::LessEqual => "<=",
            Self::Equal => "=",
            Self::GreaterEqual => ">=",
            Self::Greater => ">>",
        }
    }

    /// The RPM spelling.
    pub const fn rpm(self) -> &'static str {
        match self {
            Self::Less => "<",
            Self::LessEqual => "<=",
            Self::Equal => "=",
            Self::GreaterEqual => ">=",
            Self::Greater => ">",
        }
    }
}

/// Why a version string is not a version of its ecosystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionError {
    Empty,
    /// Whitespace anywhere in the version.
    Whitespace,
    /// DEB epoch empty, not a decimal number, or above `i32::MAX`.
    BadEpoch,
    /// Nothing after the epoch colon, or an empty upstream version.
    EmptyUpstream,
    /// A trailing `-` with no revision.
    EmptyRevision,
    /// A character dpkg or RPM refuses in this part.
    InvalidCharacter {
        part: &'static str,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty version"),
            Self::Whitespace => formatter.write_str("whitespace in version"),
            Self::BadEpoch => formatter.write_str("epoch is not a number"),
            Self::EmptyUpstream => formatter.write_str("empty upstream version"),
            Self::EmptyRevision => formatter.write_str("empty revision"),
            Self::InvalidCharacter { part } => write!(formatter, "invalid character in {part}"),
        }
    }
}

impl std::error::Error for VersionError {}

/// A parsed dpkg version `[epoch:]upstream[-revision]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebVersion {
    epoch: u32,
    upstream: String,
    revision: String,
}

impl DebVersion {
    /// Parses like dpkg `parseversion`, but also refuses what dpkg only
    /// warns about, except an upstream version that does not start with a
    /// digit: dpkg and APT install such packages.
    pub fn parse(text: &str) -> Result<Self, VersionError> {
        if text.is_empty() {
            return Err(VersionError::Empty);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(VersionError::Whitespace);
        }
        let (epoch, rest) = match text.split_once(':') {
            Some((epoch, rest)) => {
                if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(VersionError::BadEpoch);
                }
                let epoch = epoch
                    .parse::<u32>()
                    .ok()
                    .filter(|value| i32::try_from(*value).is_ok())
                    .ok_or(VersionError::BadEpoch)?;
                (epoch, rest)
            }
            None => (0, text),
        };
        if rest.is_empty() {
            return Err(VersionError::EmptyUpstream);
        }
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((_, "")) => return Err(VersionError::EmptyRevision),
            Some((upstream, revision)) => (upstream, revision),
            None => (rest, ""),
        };
        if upstream.is_empty() {
            return Err(VersionError::EmptyUpstream);
        }
        if !upstream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+~:".contains(&byte))
        {
            return Err(VersionError::InvalidCharacter {
                part: "upstream version",
            });
        }
        if !revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+~".contains(&byte))
        {
            return Err(VersionError::InvalidCharacter { part: "revision" });
        }
        Ok(Self {
            epoch,
            upstream: upstream.to_owned(),
            revision: revision.to_owned(),
        })
    }

    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }
}

impl Ord for DebVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| verrevcmp(&self.upstream, &other.upstream))
            .then_with(|| verrevcmp(&self.revision, &other.revision))
    }
}

impl PartialOrd for DebVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The weight of one non-digit character in dpkg ordering: `~` sorts
/// before everything, even the end of the string; letters sort before
/// other characters.
fn deb_order(byte: u8) -> i32 {
    if byte.is_ascii_digit() || byte == 0 {
        0
    } else if byte.is_ascii_alphabetic() {
        i32::from(byte)
    } else if byte == b'~' {
        -1
    } else {
        i32::from(byte) + 256
    }
}

/// dpkg `verrevcmp`.
fn verrevcmp(left: &str, right: &str) -> Ordering {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    let at = |bytes: &[u8], index: usize| bytes.get(index).copied().unwrap_or(0);
    let (mut a, mut b) = (0, 0);
    while a < left.len() || b < right.len() {
        let mut first_diff = Ordering::Equal;
        while (a < left.len() && !at(left, a).is_ascii_digit())
            || (b < right.len() && !at(right, b).is_ascii_digit())
        {
            let (ac, bc) = (deb_order(at(left, a)), deb_order(at(right, b)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            a += 1;
            b += 1;
        }
        while at(left, a) == b'0' {
            a += 1;
        }
        while at(right, b) == b'0' {
            b += 1;
        }
        while at(left, a).is_ascii_digit() && at(right, b).is_ascii_digit() {
            if first_diff == Ordering::Equal {
                first_diff = at(left, a).cmp(&at(right, b));
            }
            a += 1;
            b += 1;
        }
        if at(left, a).is_ascii_digit() {
            return Ordering::Greater;
        }
        if at(right, b).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

/// A parsed RPM `[epoch:]version[-release]`. Package headers always carry a
/// release; a dependency or `Provides` version may omit the epoch, the
/// release, or both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmEvr {
    epoch: Option<String>,
    version: String,
    release: Option<String>,
}

impl RpmEvr {
    /// Splits like RPM `rpmverParse`: the epoch is the leading digits before
    /// a `:`, the release follows the last `-`. Whitespace and an empty
    /// version are refused; RPM itself refuses `-` in a version or release
    /// when it builds a package, so a second `-` is refused too.
    pub fn parse(text: &str) -> Result<Self, VersionError> {
        if text.is_empty() {
            return Err(VersionError::Empty);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(VersionError::Whitespace);
        }
        let digits = text.bytes().take_while(u8::is_ascii_digit).count();
        let (epoch, rest) = if text.as_bytes().get(digits) == Some(&b':') {
            let epoch = &text[..digits];
            (
                Some(if epoch.is_empty() { "0" } else { epoch }.to_owned()),
                &text[digits + 1..],
            )
        } else {
            (None, text)
        };
        let (version, release) = match rest.rsplit_once('-') {
            Some((_, "")) => return Err(VersionError::EmptyRevision),
            Some((version, release)) => (version, Some(release.to_owned())),
            None => (rest, None),
        };
        if version.is_empty() {
            return Err(VersionError::EmptyUpstream);
        }
        if version.contains(['-', ':']) {
            return Err(VersionError::InvalidCharacter { part: "version" });
        }
        if release
            .as_deref()
            .is_some_and(|release| release.contains(':'))
        {
            return Err(VersionError::InvalidCharacter { part: "release" });
        }
        Ok(Self {
            epoch,
            version: version.to_owned(),
            release,
        })
    }

    pub fn epoch(&self) -> Option<&str> {
        self.epoch.as_deref()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn release(&self) -> Option<&str> {
        self.release.as_deref()
    }

    /// Ordering as RPM `rpmverCmp`: a missing epoch is 0 and a missing
    /// release compares as empty (`1.0` < `1.0-1`, checked against
    /// `rpm.ver` of RPM 4.16). Package headers always carry a release.
    pub fn compare(&self, other: &Self) -> Ordering {
        rpmvercmp(self.epoch().unwrap_or("0"), other.epoch().unwrap_or("0"))
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| {
                rpmvercmp(
                    self.release().unwrap_or_default(),
                    other.release().unwrap_or_default(),
                )
            })
    }
}

/// Whether the ranges `left_op left` and `right_op right` overlap, as RPM
/// `rpmverOverlap` decides it. This is how a `Requires` is matched against
/// a `Provides`: a missing epoch counts as 0, and when only one side has a
/// release, the side without it matches every release of the other side
/// if its operator includes equality.
pub fn rpm_ranges_overlap(left: &RpmEvr, left_op: Op, right: &RpmEvr, right_op: Op) -> bool {
    let positive_epoch = |epoch: Option<&str>| {
        epoch.is_some_and(|epoch| {
            epoch
                .trim_start_matches('0')
                .bytes()
                .any(|b| b.is_ascii_digit())
        })
    };
    let mut sense = match (left.epoch(), right.epoch()) {
        (Some(a), Some(b)) => rpmvercmp(a, b),
        (a, _) if positive_epoch(a) => Ordering::Greater,
        (_, b) if positive_epoch(b) => Ordering::Less,
        _ => Ordering::Equal,
    };
    if sense == Ordering::Equal {
        sense = rpmvercmp(&left.version, &right.version);
        if sense == Ordering::Equal {
            match (left.release(), right.release()) {
                (Some(a), Some(b)) => sense = rpmvercmp(a, b),
                (Some(_), None) if right_op.has_equal() => return true,
                (None, Some(_)) if left_op.has_equal() => return true,
                _ => {}
            }
        }
    }
    match sense {
        Ordering::Less => left_op.has_greater() || right_op.has_less(),
        Ordering::Greater => left_op.has_less() || right_op.has_greater(),
        Ordering::Equal => {
            (left_op.has_equal() && right_op.has_equal())
                || (left_op.has_less() && right_op.has_less())
                || (left_op.has_greater() && right_op.has_greater())
        }
    }
}

/// RPM `rpmvercmp` (ASCII only, as RPM's `risalnum`).
pub fn rpmvercmp(left: &str, right: &str) -> Ordering {
    if left == right {
        return Ordering::Equal;
    }
    let (one, two) = (left.as_bytes(), right.as_bytes());
    let at = |bytes: &[u8], index: usize| bytes.get(index).copied().unwrap_or(0);
    let separator =
        |byte: u8| byte != 0 && !byte.is_ascii_alphanumeric() && byte != b'~' && byte != b'^';
    let (mut a, mut b) = (0, 0);
    while a < one.len() || b < two.len() {
        while separator(at(one, a)) {
            a += 1;
        }
        while separator(at(two, b)) {
            b += 1;
        }
        let (ca, cb) = (at(one, a), at(two, b));
        if ca == b'~' || cb == b'~' {
            if ca != b'~' {
                return Ordering::Greater;
            }
            if cb != b'~' {
                return Ordering::Less;
            }
            a += 1;
            b += 1;
            continue;
        }
        if ca == b'^' || cb == b'^' {
            if ca == 0 {
                return Ordering::Less;
            }
            if cb == 0 {
                return Ordering::Greater;
            }
            if ca != b'^' {
                return Ordering::Greater;
            }
            if cb != b'^' {
                return Ordering::Less;
            }
            a += 1;
            b += 1;
            continue;
        }
        if ca == 0 || cb == 0 {
            break;
        }
        let numeric = ca.is_ascii_digit();
        let class = |byte: u8| {
            if numeric {
                byte.is_ascii_digit()
            } else {
                byte.is_ascii_alphabetic()
            }
        };
        let end_a = a + one[a..].iter().take_while(|byte| class(**byte)).count();
        let end_b = b + two[b..].iter().take_while(|byte| class(**byte)).count();
        // The first segment is never empty: it starts with an alphanumeric.
        if end_b == b {
            // A numeric segment is newer than an alphabetic one.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut segment_a, mut segment_b) = (&one[a..end_a], &two[b..end_b]);
        if numeric {
            while segment_a.first() == Some(&b'0') {
                segment_a = &segment_a[1..];
            }
            while segment_b.first() == Some(&b'0') {
                segment_b = &segment_b[1..];
            }
            match segment_a.len().cmp(&segment_b.len()) {
                Ordering::Equal => {}
                longer => return longer,
            }
        }
        match segment_a.cmp(segment_b) {
            Ordering::Equal => {}
            different => return different,
        }
        a = end_a;
        b = end_b;
    }
    match (a >= one.len(), b >= two.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;
