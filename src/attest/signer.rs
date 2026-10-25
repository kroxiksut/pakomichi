// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Attested signer of a source (ADR-036 point 1): one workflow of the
//! source repository and the ref rule it runs from. The administrator
//! confirms it with the source; a provenance from anything else is a
//! mismatch, never a reason to change it.

use std::fmt;

use super::verifier::SourceRef;

/// A workflow path that is not `.github/workflows/<file>.yml|yaml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidWorkflow;

/// A ref rule that is neither `tag` nor `refs/heads/<branch>`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSignerRef;

/// Checks a workflow path inside the repository, exactly as GitHub names
/// it in the certificate: one file directly under `.github/workflows/`.
pub(super) fn check_workflow(workflow: &str) -> Result<(), InvalidWorkflow> {
    let file = workflow
        .strip_prefix(".github/workflows/")
        .ok_or(InvalidWorkflow)?;
    let valid = !file.is_empty()
        && (file.ends_with(".yml") || file.ends_with(".yaml"))
        && file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !file.starts_with('.');
    if valid { Ok(()) } else { Err(InvalidWorkflow) }
}

/// Where the signer workflow runs from.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignerRef {
    /// `refs/tags/<tag of the release being verified>`.
    ReleaseTag,
    /// `refs/heads/<branch>`, the same for every release.
    Branch(String),
}

impl SignerRef {
    /// `tag` or `refs/heads/<branch>`, the form of `--ref` and of the
    /// state database. A branch name is plain: no empty or dot segment,
    /// no `..`, nothing outside `[A-Za-z0-9._/-]`.
    pub fn parse(text: &str) -> Result<Self, InvalidSignerRef> {
        if text == "tag" {
            return Ok(Self::ReleaseTag);
        }
        let branch = text.strip_prefix("refs/heads/").ok_or(InvalidSignerRef)?;
        let valid = !branch.is_empty()
            && branch.split('/').all(|segment| {
                !segment.is_empty()
                    && !segment.starts_with('.')
                    && !segment.ends_with(".lock")
                    && !segment.contains("..")
            })
            && branch.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
            });
        if valid {
            Ok(Self::Branch(branch.to_owned()))
        } else {
            Err(InvalidSignerRef)
        }
    }

    /// The ref a provenance of the release tagged `tag` must state.
    pub fn for_release(&self, tag: &str) -> SourceRef {
        match self {
            Self::ReleaseTag => SourceRef::ReleaseTag(tag.to_owned()),
            Self::Branch(branch) => SourceRef::Branch(branch.clone()),
        }
    }

    /// The rule behind a full ref seen in a provenance of the release
    /// tagged `tag`; `None` for any other ref.
    pub fn of_ref(full: &str, tag: &str) -> Option<Self> {
        if full.strip_prefix("refs/tags/") == Some(tag) {
            return Some(Self::ReleaseTag);
        }
        Self::parse(full)
            .ok()
            .filter(|rule| *rule != Self::ReleaseTag)
    }
}

impl fmt::Display for SignerRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseTag => formatter.write_str("tag"),
            Self::Branch(branch) => write!(formatter, "refs/heads/{branch}"),
        }
    }
}

/// The confirmed Attested signer of a source.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttestedSigner {
    workflow: String,
    source_ref: SignerRef,
}

impl AttestedSigner {
    pub fn new(
        workflow: impl Into<String>,
        source_ref: SignerRef,
    ) -> Result<Self, InvalidWorkflow> {
        let workflow = workflow.into();
        check_workflow(&workflow)?;
        Ok(Self {
            workflow,
            source_ref,
        })
    }

    pub fn workflow(&self) -> &str {
        &self.workflow
    }

    pub const fn source_ref(&self) -> &SignerRef {
        &self.source_ref
    }
}

impl AttestedSigner {
    /// The `<workflow>@<ref rule>` form of [`fmt::Display`]; a workflow
    /// file name never contains `@`.
    pub fn parse(text: &str) -> Option<Self> {
        let (workflow, rule) = text.split_once('@')?;
        Self::new(workflow, SignerRef::parse(rule).ok()?).ok()
    }
}

impl fmt::Display for AttestedSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.workflow, self.source_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_rule_is_the_release_tag_or_one_plain_branch() {
        assert_eq!(SignerRef::parse("tag"), Ok(SignerRef::ReleaseTag));
        assert_eq!(
            SignerRef::parse("refs/heads/release/1.x"),
            Ok(SignerRef::Branch("release/1.x".into()))
        );
        // A fixed tag would bind every release to one old commit; a bare
        // name is ambiguous; a path trick is not a branch.
        for bad in [
            "refs/tags/v1.0",
            "main",
            "refs/heads/",
            "refs/heads/a//b",
            "refs/heads/../main",
            "refs/heads/.hidden",
            "refs/heads/main.lock",
            "refs/heads/ma in",
            "refs/heads/main\n",
            "Tag",
        ] {
            assert_eq!(SignerRef::parse(bad), Err(InvalidSignerRef), "{bad:?}");
        }
        for rule in [SignerRef::ReleaseTag, SignerRef::Branch("main".into())] {
            assert_eq!(SignerRef::parse(&rule.to_string()), Ok(rule.clone()));
            let signer = AttestedSigner::new(".github/workflows/release.yml", rule)
                .unwrap_or_else(|_| panic!("valid workflow"));
            assert_eq!(AttestedSigner::parse(&signer.to_string()), Some(signer));
        }
        assert_eq!(AttestedSigner::parse(".github/workflows/a@b.yml@tag"), None);
    }

    #[test]
    fn a_provenance_ref_maps_to_a_rule_only_for_its_own_release() {
        assert_eq!(
            SignerRef::of_ref("refs/tags/v1.0", "v1.0"),
            Some(SignerRef::ReleaseTag)
        );
        // Another release's tag is not "the release tag".
        assert_eq!(SignerRef::of_ref("refs/tags/v0.9", "v1.0"), None);
        assert_eq!(
            SignerRef::of_ref("refs/heads/main", "v1.0"),
            Some(SignerRef::Branch("main".into()))
        );
        assert_eq!(SignerRef::of_ref("refs/pull/1/merge", "v1.0"), None);
    }
}
