// SPDX-License-Identifier: MIT OR Apache-2.0

//! Classifying a release asset from its name, before any download.
//!
//! The name is untrusted input and never evidence of compatibility: it only
//! decides which assets are worth downloading for inspection. A `.deb` or
//! `.rpm` name makes an asset a candidate; the inspector then reads its
//! native metadata, which alone decides the ecosystem, architecture, and
//! version. Everything else is skipped with a recorded reason, and a name
//! that matches no known kind needs review.

/// What an asset name looks like.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    /// A binary `.deb`.
    Deb,
    /// A binary `.rpm`.
    Rpm,
    /// `.src.rpm` / `.nosrc.rpm`.
    SourceRpm,
    /// `.drpm`.
    DeltaRpm,
    /// `.ddeb`, `-dbgsym_*.deb`, `-debuginfo-*.rpm`, `-debugsource-*.rpm`.
    DebugPackage,
    /// `.udeb` (Debian installer component).
    InstallerComponent,
    /// A compressed or uncompressed archive (`.tar.gz`, `.zip`, ...).
    Archive,
    /// A checksum list or a single checksum file.
    Checksum,
    /// A detached signature, certificate, or signature bundle.
    Signature,
    /// A software bill of materials.
    Sbom,
    /// A package or installer for another system (`.msi`, `.dmg`,
    /// `.AppImage`, `.pkg.tar.zst`, ...).
    OtherPlatform,
    /// None of the above; a user has to look at it.
    Unknown,
}

/// Suffixes checked in order; the first match wins. Multi-part suffixes
/// come before the single suffixes they end with.
const SUFFIXES: [(&str, AssetKind); 61] = [
    // Signatures and checksums first: `tool.deb.asc` is a signature.
    (".sigstore.json", AssetKind::Signature),
    (".intoto.jsonl", AssetKind::Signature),
    (".sigstore", AssetKind::Signature),
    (".minisig", AssetKind::Signature),
    (".bundle", AssetKind::Signature),
    (".asc", AssetKind::Signature),
    (".sig", AssetKind::Signature),
    (".gpg", AssetKind::Signature),
    (".pem", AssetKind::Signature),
    (".crt", AssetKind::Signature),
    (".cert", AssetKind::Signature),
    (".p7s", AssetKind::Signature),
    (".sha256sum", AssetKind::Checksum),
    (".sha512sum", AssetKind::Checksum),
    (".sha256", AssetKind::Checksum),
    (".sha512", AssetKind::Checksum),
    (".sha1", AssetKind::Checksum),
    (".md5", AssetKind::Checksum),
    (".b3", AssetKind::Checksum),
    (".spdx.json", AssetKind::Sbom),
    (".cdx.json", AssetKind::Sbom),
    (".cyclonedx.json", AssetKind::Sbom),
    (".cdx.xml", AssetKind::Sbom),
    (".spdx", AssetKind::Sbom),
    (".sbom", AssetKind::Sbom),
    // Packages.
    (".nosrc.rpm", AssetKind::SourceRpm),
    (".src.rpm", AssetKind::SourceRpm),
    (".drpm", AssetKind::DeltaRpm),
    (".ddeb", AssetKind::DebugPackage),
    (".udeb", AssetKind::InstallerComponent),
    (".deb", AssetKind::Deb),
    (".rpm", AssetKind::Rpm),
    // Other systems; Arch Linux packages before the archives they end with.
    (".pkg.tar.zst", AssetKind::OtherPlatform),
    (".pkg.tar.xz", AssetKind::OtherPlatform),
    (".appimage", AssetKind::OtherPlatform),
    (".flatpakref", AssetKind::OtherPlatform),
    (".flatpak", AssetKind::OtherPlatform),
    (".snap", AssetKind::OtherPlatform),
    (".msix", AssetKind::OtherPlatform),
    (".msi", AssetKind::OtherPlatform),
    (".exe", AssetKind::OtherPlatform),
    (".dmg", AssetKind::OtherPlatform),
    (".pkg", AssetKind::OtherPlatform),
    (".apk", AssetKind::OtherPlatform),
    (".ipk", AssetKind::OtherPlatform),
    (".whl", AssetKind::OtherPlatform),
    (".nupkg", AssetKind::OtherPlatform),
    (".vsix", AssetKind::OtherPlatform),
    // Archives.
    (".tar.gz", AssetKind::Archive),
    (".tar.xz", AssetKind::Archive),
    (".tar.bz2", AssetKind::Archive),
    (".tar.zst", AssetKind::Archive),
    (".tgz", AssetKind::Archive),
    (".txz", AssetKind::Archive),
    (".tbz2", AssetKind::Archive),
    (".tar", AssetKind::Archive),
    (".zip", AssetKind::Archive),
    (".7z", AssetKind::Archive),
    (".gz", AssetKind::Archive),
    (".xz", AssetKind::Archive),
    (".zst", AssetKind::Archive),
];

/// Names of checksum lists without a telling suffix (`SHA256SUMS`,
/// `checksums.txt`, `tool_1.0_checksums.txt`).
const CHECKSUM_WORDS: [&str; 6] = [
    "checksum",
    "sha256sum",
    "sha512sum",
    "sha1sum",
    "md5sum",
    "b2sum",
];

/// Classifies an asset by its name, case-insensitively.
pub fn asset_kind(asset_name: &str) -> AssetKind {
    let name = asset_name.to_ascii_lowercase();
    let kind = SUFFIXES
        .iter()
        .find(|(suffix, _)| name.ends_with(suffix))
        .map_or(AssetKind::Unknown, |(_, kind)| *kind);
    match kind {
        AssetKind::Deb if name.contains("-dbgsym_") => AssetKind::DebugPackage,
        AssetKind::Rpm if name.contains("-debuginfo-") || name.contains("-debugsource-") => {
            AssetKind::DebugPackage
        }
        AssetKind::Unknown if CHECKSUM_WORDS.iter().any(|word| name.contains(word)) => {
            AssetKind::Checksum
        }
        kind => kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_are_recognised_with_their_variants() {
        let cases = [
            ("netwatch_0.6.1_amd64.deb", AssetKind::Deb),
            ("NETWATCH_0.6.1_AMD64.DEB", AssetKind::Deb),
            ("netwatch-0.6.1-1.x86_64.rpm", AssetKind::Rpm),
            ("netwatch-0.6.1-1.src.rpm", AssetKind::SourceRpm),
            ("netwatch-0.6.1-1.nosrc.rpm", AssetKind::SourceRpm),
            ("netwatch-0.6.0_0.6.1-1.x86_64.drpm", AssetKind::DeltaRpm),
            ("netwatch-dbgsym_0.6.1_amd64.deb", AssetKind::DebugPackage),
            ("netwatch-dbgsym_0.6.1_amd64.ddeb", AssetKind::DebugPackage),
            (
                "netwatch-debuginfo-0.6.1-1.x86_64.rpm",
                AssetKind::DebugPackage,
            ),
            (
                "netwatch-debugsource-0.6.1-1.x86_64.rpm",
                AssetKind::DebugPackage,
            ),
            (
                "netwatch-udeb_0.6.1_amd64.udeb",
                AssetKind::InstallerComponent,
            ),
        ];
        for (name, kind) in cases {
            assert_eq!(asset_kind(name), kind, "{name}");
        }
    }

    #[test]
    fn signatures_and_checksums_of_packages_are_not_packages() {
        let cases = [
            ("netwatch_0.6.1_amd64.deb.asc", AssetKind::Signature),
            ("netwatch_0.6.1_amd64.deb.sig", AssetKind::Signature),
            (
                "netwatch_0.6.1_amd64.deb.sigstore.json",
                AssetKind::Signature,
            ),
            ("multiple.intoto.jsonl", AssetKind::Signature),
            ("netwatch_0.6.1_amd64.deb.sha256", AssetKind::Checksum),
            ("SHA256SUMS", AssetKind::Checksum),
            ("SHA256SUMS.asc", AssetKind::Signature),
            ("checksums.txt", AssetKind::Checksum),
            ("tool_1.0_checksums.txt", AssetKind::Checksum),
            ("sbom.spdx.json", AssetKind::Sbom),
            ("tool.cdx.json", AssetKind::Sbom),
        ];
        for (name, kind) in cases {
            assert_eq!(asset_kind(name), kind, "{name}");
        }
    }

    #[test]
    fn archives_and_other_systems_are_not_candidates() {
        let cases = [
            ("tool-linux-amd64.tar.gz", AssetKind::Archive),
            ("tool-darwin-arm64.tar.gz", AssetKind::Archive),
            ("tool-1.0-x86_64.pkg.tar.zst", AssetKind::OtherPlatform),
            ("tool-linux.tar.zst", AssetKind::Archive),
            ("OpenSSH-Win64.zip", AssetKind::Archive),
            ("OpenSSH-Win64-v10.4.0.0.msi", AssetKind::OtherPlatform),
            ("tool.dmg", AssetKind::OtherPlatform),
            ("Tool-x86_64.AppImage", AssetKind::OtherPlatform),
            ("tool_1.0_amd64.snap", AssetKind::OtherPlatform),
            ("tool.apk", AssetKind::OtherPlatform),
        ];
        for (name, kind) in cases {
            assert_eq!(asset_kind(name), kind, "{name}");
        }
    }

    #[test]
    fn anything_else_needs_review() {
        for name in [
            "netwatch",
            "netwatch-linux-amd64",
            "install.sh",
            "README.md",
            "tool.deb.bak",
        ] {
            assert_eq!(asset_kind(name), AssetKind::Unknown, "{name}");
        }
    }
}
