# Первичные технические источники и проверяемые утверждения

[English](../en/references.md) · **Русский**

Ссылки доступны для перепроверки на момент **18 октября 2026 года**; перед кодированием учитывать версию установленного пакета и возможные изменения документации.

## APT

- [apt_preferences(5), Debian](https://manpages.debian.org/bookworm/apt/apt_preferences.5.en.html) — pin влияет на **версию**, при равной версии из двух источников экземпляр может зависеть от порядка источников.
- [sources.list(5), Debian](https://manpages.debian.org/testing/apt/sources.list.5.en.html) — `Signed-By`, проверки `Valid-Until`, deb822.
- [apt-secure(8), Debian](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html) — доверие к подписанным метаданным и пакетам.
- [apt-ftparchive(1)](https://manpages.debian.org/bookworm/apt-utils/apt-ftparchive.1.en.html) — генерация индексов и Release.

## DNF/RPM

- [DNF4 configuration](https://man7.org/linux/man-pages/man5/dnf4.conf.5.html) — `gpgcheck`, `repo_gpgcheck`, `priority`, фильтры и принудительная RPM-политика.
- [DNF5 configuration](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html) — `pkg_gpgcheck`, `repo_gpgcheck`, `gpgcheck_policy`, `includepkgs`.
- [RPM signing](https://rpm.org/docs/4.20.x/manual/signatures.html) — пакетные подписи и проверки (версия документации может отличаться от пакета на испытаниях).

## GitHub

- [REST API Releases](https://docs.github.com/en/rest/releases/releases) — `immutable`, release ID, assets.
- [REST API release assets](https://docs.github.com/en/rest/releases/assets) — asset ID, `digest`.
- [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) — что блокируется и какие attestation формируются.
- [Offline verification of attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline) — sourceRepositoryIdentifier, сравнение numeric repo ID.
- [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) — signed provenance, границы гарантий.
- [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify) — reference verifier, predicate, signer identity и флаги.

## systemd и внешний пример

- [systemd.socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html) — `ListenStream`, `Accept=no` и socket activation.
- [NetWatch](https://github.com/matthart1983/netwatch), [PACKAGING.md](https://github.com/matthart1983/netwatch/blob/main/docs/PACKAGING.md) — реальное сочетание GitHub `.deb/.rpm`, отдельного APT-репозитория и COPR.

**Статус:** источники дают основания для архитектурных решений; они не заменяют эксперимент `R-001...R-004` на целевой ОС.
