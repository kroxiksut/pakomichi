// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

const DEBIAN_OS_RELEASE: &str =
    "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\nID=debian\n";
const ASTRA_OS_RELEASE: &str = "PRETTY_NAME=\"Astra Linux\"\nID=astra\nVERSION_ID=1.8_x86-64\n";
const ALMA_OS_RELEASE: &str = "ID=\"almalinux\"\nVERSION_ID=\"9.8\"\n";
const FEDORA_OS_RELEASE: &str = "ID=fedora\nVERSION_ID=44\n";

#[test]
fn every_first_target_has_a_profile_and_nothing_else_does() {
    let ids: Vec<Option<&str>> = [
        DEBIAN_OS_RELEASE,
        ASTRA_OS_RELEASE,
        ALMA_OS_RELEASE,
        FEDORA_OS_RELEASE,
    ]
    .iter()
    .map(|text| profile_for(text).map(|profile| profile.key_package))
    .collect();
    assert_eq!(
        ids,
        vec![
            Some("debian-archive-keyring"),
            Some("astra-archive-keyring"),
            Some("almalinux-gpg-keys"),
            Some("fedora-gpg-keys"),
        ]
    );
    for other in [
        "ID=debian\nVERSION_ID=\"13\"\n",
        "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
        "ID=astra\nVERSION_ID=1.7_x86-64\n",
        "ID=fedora\nVERSION_ID=43\n",
        "ID=almalinux\nVERSION_ID=\"10.0\"\n",
    ] {
        assert_eq!(profile_for(other), None, "{other}");
    }
    assert_eq!(release_version(ALMA_OS_RELEASE), Some("9"));
    assert_eq!(release_version(FEDORA_OS_RELEASE), Some("44"));
}

/// Shape of `apt-get indextargets` on Debian 12 (lab, 2026-10-21).
const INDEXTARGETS: &str = "MetaKey: main/binary-amd64/Packages
ShortDesc: Packages
Filename: /var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4
Origin: Debian
Trusted: yes
Base-URI: http://deb.debian.org/debian/dists/bookworm/
Created-By: Packages
Sourcesentry: /etc/apt/sources.list.d/debian.sources:1

MetaKey: main/i18n/Translation-en
Filename: /var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_i18n_Translation-en
Base-URI: http://deb.debian.org/debian/dists/bookworm/
Created-By: Translations
Sourcesentry: /etc/apt/sources.list.d/debian.sources:1
Trusted: yes

MetaKey: main/binary-amd64/Packages
Filename: /var/lib/apt/lists/packages.example.com_deb_dists_stable_main_binary-amd64_Packages
Trusted: no
Base-URI: https://packages.example.com/deb/dists/stable/
Created-By: Packages
Sourcesentry: /etc/apt/sources.list.d/example.list:2
";

#[test]
fn index_targets_keep_only_package_indexes() {
    let targets = index_targets(INDEXTARGETS);
    assert_eq!(targets.len(), 2);
    assert_eq!(
        targets[0].sources_entry,
        "/etc/apt/sources.list.d/debian.sources:1"
    );
    assert!(targets[0].trusted);
    assert!(!targets[1].trusted);
    assert_eq!(
        split_sources_entry(&targets[1].sources_entry),
        Some(("/etc/apt/sources.list.d/example.list", 2))
    );
}

const DEBIAN_SOURCES: &str = "Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://deb.debian.org/debian-security
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
";

#[test]
fn signed_by_is_read_from_both_source_formats() {
    let keyring = SignedBy::Files(vec![
        "/usr/share/keyrings/debian-archive-keyring.gpg".to_owned(),
    ]);
    assert_eq!(
        signed_by("/etc/apt/sources.list.d/debian.sources", DEBIAN_SOURCES, 2),
        Some(keyring.clone())
    );
    assert_eq!(
        signed_by("/etc/apt/sources.list.d/debian.sources", DEBIAN_SOURCES, 3),
        None
    );

    // Astra Linux: one-line entries without options use trusted.gpg.d.
    let astra = "deb https://dl.astralinux.ru/astra/stable/1.8_x86-64/main-repository/ 1.8_x86-64 main contrib\n\
                 deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=amd64] https://packages.clickhouse.com/deb stable main\n";
    assert_eq!(
        signed_by("/etc/apt/sources.list", astra, 1),
        Some(SignedBy::Default)
    );
    assert_eq!(
        signed_by("/etc/apt/sources.list", astra, 2),
        Some(SignedBy::Files(vec![
            "/usr/share/keyrings/clickhouse-keyring.gpg".to_owned()
        ]))
    );

    // An inline key or a fingerprint is never a distribution file.
    let inline = "Types: deb\nURIs: https://example.com\nSuites: s\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n mQINBF\n";
    assert_eq!(signed_by("/x.sources", inline, 1), Some(SignedBy::Other));
    let fingerprint = "Types: deb\nURIs: https://example.com\nSuites: s\nSigned-By: 0123456789ABCDEF0123456789ABCDEF01234567\n";
    assert_eq!(
        signed_by("/x.sources", fingerprint, 1),
        Some(SignedBy::Other)
    );
}

#[test]
fn release_file_names_follow_apt() {
    // Names observed in /var/lib/apt/lists on Debian 12 and Astra Linux 1.8.6.
    assert_eq!(
        format!(
            "{}InRelease",
            uri_to_filename("http://deb.debian.org/debian/dists/bookworm/")
        ),
        "deb.debian.org_debian_dists_bookworm_InRelease"
    );
    assert_eq!(
        format!(
            "{}InRelease",
            uri_to_filename(
                "https://dl.astralinux.ru/astra/stable/1.8_x86-64/main-repository/dists/1.8_x86-64/"
            )
        ),
        "dl.astralinux.ru_astra_stable_1.8%5fx86-64_main-repository_dists_1.8%5fx86-64_InRelease"
    );
    assert_eq!(
        uri_to_filename("https://user:secret@host/path/"),
        "host_path_"
    );
}

#[test]
fn dpkg_owner_lines_are_split() {
    assert_eq!(
        dpkg_owners("debian-archive-keyring: /usr/share/keyrings/debian-archive-keyring.gpg\n"),
        vec!["debian-archive-keyring".to_owned()]
    );
    assert_eq!(
        dpkg_owners("a, b:amd64: /usr/share/x\n"),
        vec!["a".to_owned(), "b".to_owned()]
    );
    assert!(dpkg_owners("dpkg-query: no path found matching pattern /x\n").is_empty());
}

#[test]
fn deb_roles_and_provides_come_from_the_paragraph() {
    let paragraphs = deb822(
        "Package: bash\nEssential: yes\nPriority: required\nSection: shells\n\n\
         Package: libc6\nPriority: optional\nSection: libs\nProvides: libc6-x32-compat (= 2.36)\n\n\
         Package: libfoo1\nSection: contrib/oldlibs\n\n\
         Package: gh\nPriority: optional\nSection: devel\n",
    );
    let roles: Vec<PackageRole> = paragraphs
        .iter()
        .map(|paragraph| deb_role(paragraph, PackageRole::DistributionApplication))
        .collect();
    assert_eq!(
        roles,
        vec![
            PackageRole::OsPart,
            PackageRole::OsPart,
            PackageRole::OsPart,
            PackageRole::DistributionApplication
        ]
    );
    assert_eq!(
        deb_provides(&paragraphs[1]),
        vec!["libc6-x32-compat".to_owned()]
    );
    let status = deb822(
        "Package: bash\nStatus: install ok installed\n\nPackage: old\nStatus: deinstall ok config-files\n",
    );
    assert!(deb_installed(&status[0]));
    assert!(!deb_installed(&status[1]));
}

#[test]
fn repo_sections_follow_dnf_defaults_and_continuations() {
    let text = "[baseos]\nname=AlmaLinux $releasever - BaseOS\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9\n\n\
                [crb]\nenabled=0\ngpgkey=file:///a\n  file:///b\n\n\
                [third]\nbaseurl=https://example.com\ngpgcheck=0\n";
    let sections = repo_sections(text);
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[0].id, "baseos");
    assert!(sections[0].enabled && sections[0].gpgcheck);
    assert!(!sections[1].enabled);
    assert!(sections[1].gpgcheck, "gpgcheck defaults to on");
    assert_eq!(
        sections[1].gpgkeys,
        vec!["file:///a".to_owned(), "file:///b".to_owned()]
    );
    assert!(!sections[2].gpgcheck);
    assert_eq!(
        gpgkey_path(
            "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch",
            "44",
            "x86_64"
        ),
        Some("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64".to_owned())
    );
    assert_eq!(gpgkey_path("https://example.com/key", "44", "x86_64"), None);
}

#[test]
fn marked_output_maps_packages_to_provides() {
    // dnf5 repoquery on Fedora 44 and dnf 4.14 on AlmaLinux 9 (lab).
    let output = "@@PKG bash\n/bin/sh\n/bin/bash\nbash = 5.3.9-3.fc44\nbash(x86-64) = 5.3.9-3.fc44\n\n@@PKG glibc\nlibc.so.6(GLIBC_2.38)(64bit)\nld-linux-x86-64.so.2()(64bit)\n\n@@PKG empty\n\n";
    let packages = marked_packages(output);
    assert_eq!(packages.len(), 3);
    assert_eq!(
        packages["bash"],
        vec!["/bin/sh", "/bin/bash", "bash", "bash(x86-64)"]
    );
    assert_eq!(
        packages["glibc"],
        vec![
            "libc.so.6(GLIBC_2.38)(64bit)",
            "ld-linux-x86-64.so.2()(64bit)"
        ]
    );
    assert!(packages["empty"].is_empty());
}

#[test]
fn the_core_group_is_read_in_both_dnf_layouts() {
    let dnf4 = "Group: Core\n Description: Minimal host installation\n Mandatory Packages:\n   audit\n   bash\n Default Packages:\n   NetworkManager\n Optional Packages:\n   tboot\n";
    assert_eq!(core_group(dnf4), vec!["audit", "bash", "NetworkManager"]);
    let dnf5 = "Id                   : core\nRepositories         : fedora, updates\nMandatory packages   : audit\n                     : bash\nDefault packages     : NetworkManager\n                     : firewalld\nOptional packages    : initial-setup\n                     : initscripts\n";
    assert_eq!(
        core_group(dnf5),
        vec!["audit", "bash", "NetworkManager", "firewalld"]
    );
}

#[test]
fn protected_lists_and_sonames_are_recognised() {
    assert_eq!(
        protected_names("# comment\ndnf\n  systemd  # trailing\n\n"),
        vec!["dnf", "systemd"]
    );
    for soname in [
        "libc.so.6()(64bit)",
        "libm.so.6(GLIBC_2.2.5)(64bit)",
        "libc.so.6",
        "libfoo.so",
    ] {
        assert!(is_soname(soname), "{soname}");
    }
    for other in [
        "/lib/libc.so.6",
        "bash",
        "config(openssl)",
        "libsomething",
        "pkgconfig(libsoup-2.4)",
    ] {
        assert!(!is_soname(other), "{other}");
    }
}
