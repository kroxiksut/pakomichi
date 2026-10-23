// SPDX-License-Identifier: MIT OR Apache-2.0

//! The target system and CPU architecture families.
//!
//! Native architecture names differ between ecosystems (`amd64` in dpkg,
//! `x86_64` in RPM), and release asset names use either or neither. A
//! family groups the names of one CPU so that a file name can be compared
//! with the target. Only the native metadata read by the inspector decides
//! admission; a family from a file name only avoids downloading files that
//! are clearly for another CPU.

use std::fmt;

/// The package ecosystem of the target system.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Ecosystem {
    Deb,
    Rpm,
}

impl Ecosystem {
    /// The architecture name that installs on every CPU.
    pub const fn universal_arch(self) -> &'static str {
        match self {
            Self::Deb => "all",
            Self::Rpm => "noarch",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        })
    }
}

/// A CPU architecture family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArchFamily {
    X86_64,
    Aarch64,
    X86,
    Armhf,
    Armel,
    Ppc64le,
    S390x,
    Riscv64,
    Loong64,
}

/// Native names per family: `(family, dpkg name, RPM name)`.
const NATIVE_NAMES: [(ArchFamily, &str, &str); 9] = [
    (ArchFamily::X86_64, "amd64", "x86_64"),
    (ArchFamily::Aarch64, "arm64", "aarch64"),
    (ArchFamily::X86, "i386", "i686"),
    (ArchFamily::Armhf, "armhf", "armv7hl"),
    (ArchFamily::Armel, "armel", "armv6hl"),
    (ArchFamily::Ppc64le, "ppc64el", "ppc64le"),
    (ArchFamily::S390x, "s390x", "s390x"),
    (ArchFamily::Riscv64, "riscv64", "riscv64"),
    (ArchFamily::Loong64, "loong64", "loongarch64"),
];

/// What a spelling in an asset name stands for.
#[derive(Clone, Copy)]
enum Spelling {
    One(ArchFamily),
    /// 32-bit ARM whose float ABI the name does not tell (`armv6`): it may
    /// be either `armel` or `armhf`.
    Arm32,
    Universal,
}

/// Spellings seen in asset names, matched as whole words (see
/// [`arch_hint`]). Longer spellings come first so that `x86_64` is not
/// also read as `x86`. The flag marks spellings that count only after `_`
/// or `-`: Go release names use `linux_386`, while `386` after a dot is a
/// version component such as `v1.386.0`.
const NAME_SPELLINGS: [(&str, Spelling, bool); 27] = [
    ("loongarch64", Spelling::One(ArchFamily::Loong64), false),
    ("ppc64le", Spelling::One(ArchFamily::Ppc64le), false),
    ("ppc64el", Spelling::One(ArchFamily::Ppc64le), false),
    ("aarch64", Spelling::One(ArchFamily::Aarch64), false),
    ("armv7hl", Spelling::One(ArchFamily::Armhf), false),
    ("riscv64", Spelling::One(ArchFamily::Riscv64), false),
    ("loong64", Spelling::One(ArchFamily::Loong64), false),
    ("x86_64", Spelling::One(ArchFamily::X86_64), false),
    ("x86-64", Spelling::One(ArchFamily::X86_64), false),
    ("armv7l", Spelling::One(ArchFamily::Armhf), false),
    ("armv6l", Spelling::Arm32, false),
    ("noarch", Spelling::Universal, false),
    ("amd64", Spelling::One(ArchFamily::X86_64), false),
    ("arm64", Spelling::One(ArchFamily::Aarch64), false),
    ("armhf", Spelling::One(ArchFamily::Armhf), false),
    ("armv7", Spelling::One(ArchFamily::Armhf), false),
    ("armv6", Spelling::Arm32, false),
    ("armel", Spelling::One(ArchFamily::Armel), false),
    ("s390x", Spelling::One(ArchFamily::S390x), false),
    ("i386", Spelling::One(ArchFamily::X86), false),
    ("i486", Spelling::One(ArchFamily::X86), false),
    ("i586", Spelling::One(ArchFamily::X86), false),
    ("i686", Spelling::One(ArchFamily::X86), false),
    ("x64", Spelling::One(ArchFamily::X86_64), false),
    ("x86", Spelling::One(ArchFamily::X86), false),
    ("386", Spelling::One(ArchFamily::X86), true),
    ("all", Spelling::Universal, false),
];

impl ArchFamily {
    /// The family of a native architecture name of `ecosystem`; `None` for
    /// an unknown name and for the universal name.
    pub fn from_native(ecosystem: Ecosystem, name: &str) -> Option<Self> {
        NATIVE_NAMES
            .iter()
            .find(|(_, deb, rpm)| match ecosystem {
                Ecosystem::Deb => *deb == name,
                Ecosystem::Rpm => *rpm == name,
            })
            .map(|(family, _, _)| *family)
    }

    const fn is_arm32(self) -> bool {
        matches!(self, Self::Armhf | Self::Armel)
    }
}

/// What an asset name says about its CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchHint {
    /// Exactly one family is named.
    Family(ArchFamily),
    /// 32-bit ARM with an unknown float ABI (`armv6`): `armel` or `armhf`.
    Arm32,
    /// Only the universal name (`all`, `noarch`) is named.
    Universal,
    /// No family, or several different ones.
    Unknown,
}

impl ArchHint {
    /// Whether the name clearly points at a CPU other than `family`, so the
    /// asset need not be downloaded. Only a clear mismatch counts.
    pub fn excludes(self, family: ArchFamily) -> bool {
        match self {
            Self::Family(named) => named != family,
            Self::Arm32 => !family.is_arm32(),
            Self::Universal | Self::Unknown => false,
        }
    }
}

/// Reads the architecture hint of an asset name. A spelling counts only
/// as a whole word: the characters around it must not be ASCII letters
/// or digits, so `x64` inside `linux64` or `all` inside `install` is
/// ignored.
pub fn arch_hint(asset_name: &str) -> ArchHint {
    let name = asset_name.to_ascii_lowercase();
    let bytes = name.as_bytes();
    let mut taken = vec![false; bytes.len()];
    let mut families: Vec<ArchFamily> = Vec::new();
    let mut arm32 = false;
    let mut universal = false;
    for (spelling, meaning, after_separator) in NAME_SPELLINGS {
        let mut from = 0;
        while let Some(offset) = name.get(from..).and_then(|rest| rest.find(spelling)) {
            let start = from + offset;
            let end = start + spelling.len();
            from = start + 1;
            let before = start.checked_sub(1).map(|index| bytes[index]);
            let before_ok = match before {
                None => !after_separator,
                Some(byte) if after_separator => byte == b'_' || byte == b'-',
                Some(byte) => !byte.is_ascii_alphanumeric(),
            };
            let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
            if !before_ok || !after_ok || taken[start..end].iter().any(|used| *used) {
                continue;
            }
            taken[start..end].iter_mut().for_each(|used| *used = true);
            match meaning {
                Spelling::One(family) if !families.contains(&family) => families.push(family),
                Spelling::One(_) => {}
                Spelling::Arm32 => arm32 = true,
                Spelling::Universal => universal = true,
            }
        }
    }
    match (families.as_slice(), arm32) {
        ([family], false) => ArchHint::Family(*family),
        ([family], true) if family.is_arm32() => ArchHint::Family(*family),
        ([], true) => ArchHint::Arm32,
        ([], false) if universal => ArchHint::Universal,
        _ => ArchHint::Unknown,
    }
}

/// Why a target platform could not be described.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// The native architecture is not one Pakomichi knows for the ecosystem.
    UnknownArchitecture,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArchitecture => formatter.write_str("unknown native architecture"),
        }
    }
}

impl std::error::Error for PlatformError {}

/// The system packages are selected for: its ecosystem and the native
/// architecture its package manager reports (`dpkg --print-architecture`,
/// `rpm --eval %_arch`). Foreign architectures (dpkg multiarch, RPM
/// multilib) are not targets in 0.1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlatform {
    ecosystem: Ecosystem,
    native_arch: String,
    family: ArchFamily,
}

impl TargetPlatform {
    pub fn new(ecosystem: Ecosystem, native_arch: &str) -> Result<Self, PlatformError> {
        let family = ArchFamily::from_native(ecosystem, native_arch)
            .ok_or(PlatformError::UnknownArchitecture)?;
        Ok(Self {
            ecosystem,
            native_arch: native_arch.to_owned(),
            family,
        })
    }

    pub const fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    pub fn native_arch(&self) -> &str {
        &self.native_arch
    }

    pub const fn family(&self) -> ArchFamily {
        self.family
    }

    /// The native architecture or the universal one, compared exactly as
    /// the package manager would.
    pub fn accepts_native_arch(&self, arch: &str) -> bool {
        arch == self.native_arch || arch == self.ecosystem.universal_arch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_names_map_to_one_family_per_ecosystem() {
        assert_eq!(
            ArchFamily::from_native(Ecosystem::Deb, "amd64"),
            Some(ArchFamily::X86_64)
        );
        assert_eq!(
            ArchFamily::from_native(Ecosystem::Rpm, "x86_64"),
            Some(ArchFamily::X86_64)
        );
        assert_eq!(ArchFamily::from_native(Ecosystem::Deb, "x86_64"), None);
        assert_eq!(ArchFamily::from_native(Ecosystem::Rpm, "amd64"), None);
        assert_eq!(ArchFamily::from_native(Ecosystem::Rpm, "noarch"), None);
    }

    #[test]
    fn the_target_accepts_only_its_native_and_universal_names() -> Result<(), PlatformError> {
        let deb = TargetPlatform::new(Ecosystem::Deb, "amd64")?;
        assert!(deb.accepts_native_arch("amd64"));
        assert!(deb.accepts_native_arch("all"));
        assert!(!deb.accepts_native_arch("x86_64"));
        assert!(!deb.accepts_native_arch("i386"));
        assert!(!deb.accepts_native_arch("noarch"));

        let rpm = TargetPlatform::new(Ecosystem::Rpm, "aarch64")?;
        assert!(rpm.accepts_native_arch("aarch64"));
        assert!(rpm.accepts_native_arch("noarch"));
        assert!(!rpm.accepts_native_arch("arm64"));

        assert_eq!(
            TargetPlatform::new(Ecosystem::Deb, "sparc"),
            Err(PlatformError::UnknownArchitecture)
        );
        Ok(())
    }

    #[test]
    fn hints_read_common_asset_names() {
        let cases = [
            (
                "netwatch_0.6.1_amd64.deb",
                ArchHint::Family(ArchFamily::X86_64),
            ),
            (
                "netwatch-0.6.1-1.x86_64.rpm",
                ArchHint::Family(ArchFamily::X86_64),
            ),
            ("tool-linux-x64.deb", ArchHint::Family(ArchFamily::X86_64)),
            ("tool_1.0_arm64.deb", ArchHint::Family(ArchFamily::Aarch64)),
            (
                "tool-1.0-1.aarch64.rpm",
                ArchHint::Family(ArchFamily::Aarch64),
            ),
            ("tool-1.0-1.i686.rpm", ArchHint::Family(ArchFamily::X86)),
            ("tool_1.0_armhf.deb", ArchHint::Family(ArchFamily::Armhf)),
            (
                "tool_1.0_ppc64el.deb",
                ArchHint::Family(ArchFamily::Ppc64le),
            ),
            ("tool_1.0_all.deb", ArchHint::Universal),
            ("tool-1.0-1.noarch.rpm", ArchHint::Universal),
            ("tool_1.0.deb", ArchHint::Unknown),
            ("TOOL_1.0_AMD64.DEB", ArchHint::Family(ArchFamily::X86_64)),
        ];
        for (name, expected) in cases {
            assert_eq!(arch_hint(name), expected, "{name}");
        }
    }

    #[test]
    fn only_a_clear_mismatch_excludes_a_target() {
        assert!(ArchHint::Family(ArchFamily::Aarch64).excludes(ArchFamily::X86_64));
        assert!(!ArchHint::Family(ArchFamily::X86_64).excludes(ArchFamily::X86_64));
        assert!(ArchHint::Arm32.excludes(ArchFamily::X86_64));
        assert!(!ArchHint::Arm32.excludes(ArchFamily::Armhf));
        assert!(!ArchHint::Arm32.excludes(ArchFamily::Armel));
        assert!(!ArchHint::Universal.excludes(ArchFamily::S390x));
        assert!(!ArchHint::Unknown.excludes(ArchFamily::S390x));
    }

    #[test]
    fn hints_need_whole_words_and_one_family() {
        // `x86_64` is not also read as `x86`.
        assert_eq!(
            arch_hint("tool-x86_64.rpm"),
            ArchHint::Family(ArchFamily::X86_64)
        );
        // Inside other words or numbers nothing is read.
        assert_eq!(arch_hint("linux64-tool.deb"), ArchHint::Unknown);
        assert_eq!(arch_hint("tool-v2.3864.deb"), ArchHint::Unknown);
        assert_eq!(arch_hint("tool-v1.386.0.deb"), ArchHint::Unknown);
        // Go release names (GOARCH): `386` after `_` or `-`, and `armv6`,
        // whose float ABI the name does not tell.
        assert_eq!(
            arch_hint("gh_2.102.1_linux_386.deb"),
            ArchHint::Family(ArchFamily::X86)
        );
        assert_eq!(
            arch_hint("tool-linux-386.rpm"),
            ArchHint::Family(ArchFamily::X86)
        );
        assert_eq!(arch_hint("386-tool.deb"), ArchHint::Unknown);
        assert_eq!(arch_hint("gh_2.102.1_linux_armv6.deb"), ArchHint::Arm32);
        assert_eq!(
            arch_hint("tool_armv6_armhf.deb"),
            ArchHint::Family(ArchFamily::Armhf)
        );
        assert_eq!(arch_hint("install-helper.deb"), ArchHint::Unknown);
        assert_eq!(arch_hint("smallest.deb"), ArchHint::Unknown);
        // Two different families give no hint at all.
        assert_eq!(arch_hint("tool-amd64-arm64.deb"), ArchHint::Unknown);
        // A family together with the universal name is still that family.
        assert_eq!(
            arch_hint("tool-all-amd64.deb"),
            ArchHint::Family(ArchFamily::X86_64)
        );
    }
}
