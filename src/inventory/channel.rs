// SPDX-License-Identifier: MIT OR Apache-2.0

//! Release channel: stable or pre-release.
//!
//! The provider's `prerelease` flag is mutable and is not the sole
//! criterion (`specifications/github.md`, item 6). A release is stable only
//! when the flag, the tag, and the native version all say so. A flag that
//! says stable next to a tag or version that names a pre-release (for
//! example the tag `10.4.0.0p1-Preview` with `prerelease: false`, R-007)
//! is unclear and is never offered on the stable channel.

/// Which releases a source follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelPolicy {
    /// Only releases whose every signal says stable.
    Stable,
    /// Stable releases and pre-releases, including unclear ones. Choosing
    /// it is an explicit user decision; nothing switches to it by itself.
    IncludePrerelease,
}

/// A word that marks a pre-release in a tag or version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrereleaseMarker {
    Alpha,
    Beta,
    Rc,
    Pre,
    Preview,
    Dev,
    Nightly,
    Snapshot,
    Canary,
    Unstable,
    /// `~` in a native version, which sorts before the release it precedes
    /// in both dpkg and RPM.
    Tilde,
}

const MARKER_WORDS: [(&str, PrereleaseMarker); 10] = [
    ("alpha", PrereleaseMarker::Alpha),
    ("beta", PrereleaseMarker::Beta),
    ("rc", PrereleaseMarker::Rc),
    ("pre", PrereleaseMarker::Pre),
    ("preview", PrereleaseMarker::Preview),
    ("dev", PrereleaseMarker::Dev),
    ("nightly", PrereleaseMarker::Nightly),
    ("snapshot", PrereleaseMarker::Snapshot),
    ("canary", PrereleaseMarker::Canary),
    ("unstable", PrereleaseMarker::Unstable),
];

/// The first pre-release word in `text`. Words are maximal runs of ASCII
/// letters, compared case-insensitively, so `v2.0.0-rc.1`, `1.0beta2`, and
/// `10.4.0.0p1-Preview` are found, while `devtools-1.2` or `prepare` are
/// not.
pub fn marker_in_text(text: &str) -> Option<PrereleaseMarker> {
    text.split(|character: char| !character.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .find_map(|word| {
            MARKER_WORDS
                .iter()
                .find(|(marker, _)| word.eq_ignore_ascii_case(marker))
                .map(|(_, marker)| *marker)
        })
}

/// A pre-release marker in a native version: `~` or a marker word.
pub fn marker_in_native_version(version: &str) -> Option<PrereleaseMarker> {
    if version.contains('~') {
        return Some(PrereleaseMarker::Tilde);
    }
    marker_in_text(version)
}

/// What the signals of one release say.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelVerdict {
    Stable,
    /// The provider flags the release as a pre-release.
    Prerelease,
    /// Flagged stable, but the tag or a native version names a pre-release.
    Unclear(PrereleaseMarker),
}

impl ChannelVerdict {
    /// Combines the provider flag with the markers found so far.
    pub const fn from_signals(prerelease_flag: bool, marker: Option<PrereleaseMarker>) -> Self {
        match (prerelease_flag, marker) {
            (true, _) => Self::Prerelease,
            (false, Some(marker)) => Self::Unclear(marker),
            (false, None) => Self::Stable,
        }
    }

    /// Adds a marker found later, for example in a native version.
    #[must_use]
    pub const fn with_marker(self, marker: Option<PrereleaseMarker>) -> Self {
        match (self, marker) {
            (Self::Stable, Some(marker)) => Self::Unclear(marker),
            (verdict, _) => verdict,
        }
    }

    pub const fn admitted_by(self, policy: ChannelPolicy) -> bool {
        match policy {
            ChannelPolicy::Stable => matches!(self, Self::Stable),
            ChannelPolicy::IncludePrerelease => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_words_are_found_as_whole_letter_runs() {
        let found = [
            ("v2.0.0-rc.1", PrereleaseMarker::Rc),
            ("v2.0.0-RC1", PrereleaseMarker::Rc),
            ("1.0beta2", PrereleaseMarker::Beta),
            ("10.4.0.0p1-Preview", PrereleaseMarker::Preview),
            ("v3.1.0-alpha", PrereleaseMarker::Alpha),
            ("nightly-2026-10-21", PrereleaseMarker::Nightly),
            ("1.2.0.dev3", PrereleaseMarker::Dev),
        ];
        for (text, marker) in found {
            assert_eq!(marker_in_text(text), Some(marker), "{text}");
        }
        for text in [
            "v1.2.3",
            "1.2.3-1",
            "devtools-1.2",
            "prepare-2.0",
            "release-2026",
            "1.0-1ubuntu1",
            "2.1-3.el9",
            "0.6.1-1.fc44",
        ] {
            assert_eq!(marker_in_text(text), None, "{text}");
        }
    }

    #[test]
    fn a_tilde_in_a_native_version_is_a_marker() {
        assert_eq!(
            marker_in_native_version("1.0~rc1-1"),
            Some(PrereleaseMarker::Tilde)
        );
        assert_eq!(marker_in_native_version("2:1.0-1"), None);
    }

    #[test]
    fn stable_needs_every_signal_to_say_stable() {
        let stable = ChannelVerdict::from_signals(false, None);
        assert_eq!(stable, ChannelVerdict::Stable);
        assert!(stable.admitted_by(ChannelPolicy::Stable));

        let flagged = ChannelVerdict::from_signals(true, None);
        assert_eq!(flagged, ChannelVerdict::Prerelease);
        assert!(!flagged.admitted_by(ChannelPolicy::Stable));
        assert!(flagged.admitted_by(ChannelPolicy::IncludePrerelease));

        // The Win32-OpenSSH case: the tag says Preview, the flag says stable.
        let unclear = ChannelVerdict::from_signals(false, marker_in_text("10.4.0.0p1-Preview"));
        assert_eq!(unclear, ChannelVerdict::Unclear(PrereleaseMarker::Preview));
        assert!(!unclear.admitted_by(ChannelPolicy::Stable));
        assert!(unclear.admitted_by(ChannelPolicy::IncludePrerelease));
    }

    #[test]
    fn a_later_marker_makes_a_stable_release_unclear_only() {
        let later = Some(PrereleaseMarker::Tilde);
        assert_eq!(
            ChannelVerdict::Stable.with_marker(later),
            ChannelVerdict::Unclear(PrereleaseMarker::Tilde)
        );
        assert_eq!(
            ChannelVerdict::Prerelease.with_marker(later),
            ChannelVerdict::Prerelease
        );
        assert_eq!(
            ChannelVerdict::Stable.with_marker(None),
            ChannelVerdict::Stable
        );
    }
}
