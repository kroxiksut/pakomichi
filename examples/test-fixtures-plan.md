# План синтетических артефактов для исследований

Нужны **только лабораторные** DEB/RPM, созданные агентом во время R-001/R-002 (не распространять их как production packages).

- `sampleapp 0.9-1`, `1.0-1`, `1.1-1`: содержат простой исполняемый файл, который выводит fingerprint сборки.
- `sampleapp 1.0-1` из двух источников: одинаковые имя/версия/архитектура, **разные sha**.
- `sampleapp-helper 1.1-1`: требуется основным пакетом по точной версии.
- `sampleapp-suspicious 1.1-1`: метаданные `Provides` на критический системный namespace; только для инспекции, **не устанавливать на production**.
- Signed RPM, unsigned RPM, invalid signature RPM, подписанный repodata.
- GitHub тестовый Release immutable с аттестацией и mutable с attested artifact.

Для всех fixtures записать `sha256sum`, нативный package metadata dump, build commands и operating system used. Не вкладывать приватные подписи/токены в Git.
