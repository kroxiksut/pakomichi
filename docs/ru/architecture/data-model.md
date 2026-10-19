# Модель данных — семантическая спецификация

[English](../../en/architecture/data-model.md) · **Русский**

Таблицы ниже описывают смысл; физические столбцы, индексы и миграции проектируются отдельно. Все идентификаторы входных Git-данных — недоверенный ввод до проверки.

| Сущность | Обязательные поля и инварианты |
|---|---|
| `ForgeRepository` | внутренний UUID, forge, **постоянный repo ID**, owner ID, canonical URL, first_seen, last_verified, состояние, предыдущие адреса; `(forge,repo_id)` уникально |
| `PackageFamily` | UUID, repository UUID, имя/назначение, разрешённые имена в конкретной экосистеме, текущая ревизия набора, согласие пользователя |
| `PackageIdentity` | family UUID, ecosystem (`deb`/`rpm`), native name, allowed arches; строго не путать Git tag и native version |
| `ReleaseRecord` | release ID, tag, commit (верифицированное значение), дата, канал по отдельной политике, immutable claim, проверенное состояние |
| `Artifact` | asset ID, native package tuple, exact filename, SHA-256, size, release ID, source ID, build variant (`unknown` допустимо), verification evidence ID |
| `TrustEvidence` | тип Strict/Attested, доверенная root chain, подписант, source repo ID, проверяемый SHA, predicate, время проверки, версия проверяющего; только append-only audit |
| `SourcePolicy` | repo ID, family/package, режим observing/active/suspended, allowed channel, accepted trust modes, выбранный нативный источник, штатные ограничения |
| `InstalledObservation` | native package, версия, arch, reported repository if proven, confidence, время, фактические данные менеджера; **не первичный источник истины** |
| `OSInventory` | distro ID/version, manager/version, arch, enabled repos, installed packages, apt/dnf priority, timestamp; пересчитываем при изменениях |
| `ArtifactCache` | content SHA, bytes path, verified state, refcount/pins, download state; никогда не использовать filename как идентичность |
| `Snapshot` | generation, repo, native backend, list manifests, hashes, signatures, valid_from/until, state staged/published/retired, reserved CAS refs |
| `DecisionLog` | event ID, object ID, rule/version, allow/hold/deny, human-readable reason, evidence, timestamp; воспроизводимость решений |
| `AdminOperation` | ID, desired state, previous hashes, staged files, apply/rollback status; восстановление после прерывания между SQLite и конфигурацией |

## Ключевые связи

`ForgeRepository 1 → N PackageFamily 1 → N PackageIdentity`; `ForgeRepository 1 → N ReleaseRecord 1 → N Artifact`; каждый `Artifact` связан с разрешённым `PackageIdentity` и `TrustEvidence`; Snapshot ссылается на ровно определённые артефакты по хешам.

Семейство — **не** wildcard по префиксу имени. Два разных пакета одного релиза могут относиться к разным семействам. Нативные `Provides`, `Obsoletes`, `Replaces` не означают разрешение распространять произвольный новый системный пакет.

## Согласованность и уникальность

- Один `source` никогда не переназначается на другой `repo ID`. Передача владельца требует отдельного утверждения.
- Ключ закреплённой записи: `(forge, repository_id, release_id, asset_id, verified_digest)`; существующая запись не перезаписывается при смене digest.
- Артефакт ссылается только на доказательство, предмет которого — его собственный digest. До проверки доказательства нет, и артефакт не может быть `verified`, `eligible`, `published` или `retired`; присоединённое доказательство не заменяется и не удаляется.
- Не объявлять `source_of_installed_package=Git` из совпадения имени/версии. Если история установки не доказана — `unknown`.
- Новый Snapshot нельзя сделать `published`, пока все его индексы, подписи и резервирования файлов согласованы.
- Пользовательский выбор применён успешно лишь после сверки с фактическими настройками APT/DNF.
- При необратимой ошибке БД не реконструировать доверие по произвольной повторной выборке API; требуется доверенная резервная конфигурация или повторное подтверждение.

## Индексы БД / масштабирование

Индексировать repo ID, family/name/backend, native version (сравнение по нативному компаратору, **не лексикографически**), release ID, SHA256, state. Журнал/история отделены от кешируемых API ответов.
