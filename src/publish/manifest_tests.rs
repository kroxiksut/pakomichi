// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn object(bytes: &[u8]) -> ExpectedObject {
    ExpectedObject::new(Sha256Digest::of(bytes), bytes.len() as u64)
}

fn path(text: &str) -> Result<RepoPath, ManifestError> {
    RepoPath::new(text)
}

fn meta(backend: Backend) -> Result<GenerationMeta, ManifestError> {
    Ok(GenerationMeta {
        repo: RepoName::new("src-1-apt-strict")?,
        source: SourceId::new("src-1")?,
        backend,
        valid_from: Timestamp::new("2026-10-21T00:00:00Z")?,
        valid_until: Timestamp::new("2026-10-28T00:00:00Z")?,
    })
}

fn generation(value: u64) -> Result<GenerationId, ManifestError> {
    GenerationId::new(value).ok_or(ManifestError::Malformed("generation"))
}

/// A small APT generation: signed metadata, one index with its by-hash
/// alias, and one package.
fn apt_objects(package: &[u8]) -> Result<Vec<(RepoPath, ExpectedObject)>, ManifestError> {
    let index = object(b"Package: tool\n");
    let deb = object(package);
    Ok(vec![
        (path("dists/stable/InRelease")?, object(b"signed")),
        (path("dists/stable/main/binary-amd64/Packages")?, index),
        (
            path(&format!(
                "dists/stable/main/binary-amd64/by-hash/SHA256/{}",
                index.sha256.to_hex()
            ))?,
            index,
        ),
        (
            path(&format!("pool/{}/tool_1.0_amd64.deb", deb.sha256.to_hex()))?,
            deb,
        ),
    ])
}

#[test]
fn names_paths_and_ids_are_validated() {
    assert!(RepoName::new("src-1-apt-strict").is_ok());
    for bad in ["", "Src", "a_b", "-a", "a-", "a/b", &"a".repeat(65)] {
        assert!(RepoName::new(bad).is_err(), "{bad}");
    }
    assert!(RepoPath::new("dists/stable/InRelease").is_ok());
    for bad in [
        "",
        "/abs",
        "a//b",
        "a/./b",
        "a/../b",
        "..",
        "a b",
        "a\\b",
        "a/b%2f",
        &"a/".repeat(17),
    ] {
        assert!(RepoPath::new(bad).is_err(), "{bad}");
    }
    assert!(GenerationId::new(0).is_none());
    assert!(GenerationId::new(1).is_some());
    assert!(GenerationId::new(u64::MAX).is_none());
    assert!(Timestamp::new("2026-10-21T00:00:00Z").is_ok());
    for bad in [
        "2026-10-21",
        "2026-10-21 00:00:00Z",
        "2026-10-21T00:00:00+00:00",
    ] {
        assert!(Timestamp::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn paths_are_classified_per_backend() -> TestResult {
    let digest = Sha256Digest::of(b"bytes");
    let hex = digest.to_hex();
    let cases = [
        (
            Backend::Apt,
            "dists/stable/InRelease".to_owned(),
            Ok(PathClass::Mutable),
        ),
        (
            Backend::Apt,
            "dists/stable/Release.gpg".to_owned(),
            Ok(PathClass::Mutable),
        ),
        (
            Backend::Apt,
            "dists/stable/main/binary-amd64/Packages.xz".to_owned(),
            Ok(PathClass::Mutable),
        ),
        (
            Backend::Apt,
            format!("dists/stable/main/binary-amd64/by-hash/SHA256/{hex}"),
            Ok(PathClass::ContentAddressed),
        ),
        (
            Backend::Apt,
            format!("pool/{hex}/tool_1.0_amd64.deb"),
            Ok(PathClass::ContentAddressed),
        ),
        (
            Backend::Dnf5,
            "repodata/repomd.xml".to_owned(),
            Ok(PathClass::Mutable),
        ),
        (
            Backend::Dnf4,
            "repodata/repomd.xml.asc".to_owned(),
            Ok(PathClass::Mutable),
        ),
        (
            Backend::Dnf4,
            format!("repodata/{hex}-primary.xml.gz"),
            Ok(PathClass::ContentAddressed),
        ),
        (
            Backend::Dnf5,
            format!("packages/{hex}/tool-1.0-1.x86_64.rpm"),
            Ok(PathClass::ContentAddressed),
        ),
    ];
    for (backend, text, expected) in cases {
        assert_eq!(
            classify(backend, &path(&text)?, &digest),
            expected,
            "{text}"
        );
    }

    // Simple metadata names (`--simple-md-filenames`) and stray files are
    // refused: every path is either mutable metadata or content-addressed.
    for (backend, text) in [
        (Backend::Dnf4, "repodata/primary.xml.gz".to_owned()),
        (Backend::Dnf4, "tool.rpm".to_owned()),
        (
            Backend::Apt,
            "pool/main/t/tool/tool_1.0_amd64.deb".to_owned(),
        ),
        (Backend::Apt, "index.html".to_owned()),
        (Backend::Apt, "dists/stable/main/Contents-amd64".to_owned()),
        (Backend::Apt, "repodata/repomd.xml".to_owned()),
        (Backend::Dnf5, "dists/stable/InRelease".to_owned()),
    ] {
        assert!(
            matches!(
                classify(backend, &path(&text)?, &digest),
                Err(ManifestError::UnclassifiedPath(_))
            ),
            "{text}"
        );
    }

    // A content-addressed name must carry the digest of its own bytes.
    let other = Sha256Digest::of(b"other").to_hex();
    assert!(matches!(
        classify(
            Backend::Apt,
            &path(&format!("pool/{other}/tool.deb"))?,
            &digest
        ),
        Err(ManifestError::DigestNotInName(_))
    ));
    assert!(matches!(
        classify(
            Backend::Dnf4,
            &path(&format!("repodata/{other}-primary.xml.gz"))?,
            &digest
        ),
        Err(ManifestError::DigestNotInName(_))
    ));
    Ok(())
}

#[test]
fn an_apt_index_needs_its_by_hash_alias() -> TestResult {
    let mut objects = apt_objects(b"deb")?;
    assert!(Manifest::new(meta(Backend::Apt)?, generation(1)?, 0, objects.clone()).is_ok());
    objects.retain(|(path, _)| !path.as_str().contains("/by-hash/"));
    assert!(matches!(
        Manifest::new(meta(Backend::Apt)?, generation(1)?, 0, objects),
        Err(ManifestError::MissingByHashAlias(_))
    ));
    Ok(())
}

#[test]
fn duplicates_and_empty_generations_are_refused() -> TestResult {
    let mut objects = apt_objects(b"deb")?;
    let first = objects[0].clone();
    objects.push(first);
    assert!(matches!(
        Manifest::new(meta(Backend::Apt)?, generation(1)?, 0, objects),
        Err(ManifestError::DuplicatePath(_))
    ));
    assert_eq!(
        Manifest::new(meta(Backend::Apt)?, generation(1)?, 0, Vec::new()),
        Err(ManifestError::Empty)
    );
    Ok(())
}

#[test]
fn the_text_form_round_trips_and_is_canonical() -> TestResult {
    let manifest = Manifest::new(
        meta(Backend::Apt)?,
        generation(7)?,
        1_792_000_000,
        apt_objects(b"deb")?,
    )?;
    let text = manifest.to_text();
    assert!(text.starts_with("pakomichi-generation v1\nrepo src-1-apt-strict\n"));
    let parsed = Manifest::parse(&text)?;
    assert_eq!(parsed, manifest);
    assert_eq!(parsed.to_text(), text);
    assert_eq!(parsed.digest(), Sha256Digest::of(text.as_bytes()));
    assert_eq!(
        parsed.objects().count(),
        3,
        "the alias shares the index object"
    );
    Ok(())
}

#[test]
fn malformed_text_is_refused() -> TestResult {
    let text =
        Manifest::new(meta(Backend::Apt)?, generation(7)?, 1, apt_objects(b"deb")?)?.to_text();
    let lines: Vec<&str> = text.lines().collect();
    let join = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>()
    };

    let mut wrong_magic = lines.clone();
    wrong_magic[0] = "pakomichi-generation v2";
    let mut swapped_header = lines.clone();
    swapped_header.swap(1, 2);
    let mut reordered = lines.clone();
    let last = reordered.len() - 1;
    reordered.swap(last - 1, last);
    let mut missing = lines.clone();
    missing.pop();
    let mut extra_field = lines.clone();
    let extended = format!("{}\textra", lines[last]);
    extra_field[last] = &extended;
    let mut wrong_class = lines.clone();
    let reclassed = lines[last].replacen("\tc\t", "\tm\t", 1);
    wrong_class[last] = &reclassed;
    let mut padded_size = lines.clone();
    let padded = lines[last].replacen("\t3\t", "\t03\t", 1);
    padded_size[last] = &padded;

    for (name, broken) in [
        ("magic", join(&wrong_magic)),
        ("header order", join(&swapped_header)),
        ("path order", join(&reordered)),
        ("entry count", join(&missing)),
        ("extra field", join(&extra_field)),
        ("recorded class", join(&wrong_class)),
        ("padded size", join(&padded_size)),
        ("empty", String::new()),
    ] {
        assert!(Manifest::parse(&broken).is_err(), "{name}");
    }
    Ok(())
}

#[test]
fn content_addressed_paths_keep_their_bytes_across_generations() -> TestResult {
    let old = Manifest::new(meta(Backend::Apt)?, generation(1)?, 0, apt_objects(b"deb")?)?;
    // A newer generation with a new package and the same old one is fine.
    let mut objects = apt_objects(b"deb")?;
    let newer = object(b"deb 1.1");
    objects.push((
        path(&format!(
            "pool/{}/tool_1.1_amd64.deb",
            newer.sha256.to_hex()
        ))?,
        newer,
    ));
    let next = Manifest::new(meta(Backend::Apt)?, generation(2)?, 0, objects)?;
    assert!(check_immutable_paths(&next, std::slice::from_ref(&old)).is_ok());

    // The same content-addressed path with another size is a substitution.
    let deb = object(b"deb");
    let mut tampered = apt_objects(b"deb")?;
    for (path, object) in &mut tampered {
        if path.as_str().starts_with("pool/") {
            *object = ExpectedObject::new(deb.sha256, deb.size + 1);
        }
    }
    let tampered = Manifest::new(meta(Backend::Apt)?, generation(2)?, 0, tampered)?;
    assert!(matches!(
        check_immutable_paths(&tampered, std::slice::from_ref(&old)),
        Err(ManifestError::ImmutablePathChanged(_))
    ));
    Ok(())
}
