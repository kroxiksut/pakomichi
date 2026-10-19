# R-003 — Подтверждение GitHub Strict/Attested и идентичности

[English](../../en/research/R-003-github-provenance.md) · **Русский**

Результат этого протокола обязателен до заявления о поддержке режимов GitHub Strict или Attested.

## Цели

Проверить: (а) Strict immutable release + корректная release attestation; (б) mutable release + signed artifact build provenance; (в) привязку к постоянному repo ID в аттестации; (г) запрет старого имени нового repo/fork; (д) неизменность принятых digest.

## Примеры

Использовать свой **тестовый** репозиторий с доступными контролируемыми релизами и маленькими файлами. Как read-only внешняя проверка — `matthart1983/netwatch`, где в выпуске v0.35.4 есть `immutable:false` и опубликованные build attestations. Не мутировать и не форкать внешний проект ради теста.

## Шаги

1. Создать release draft, прикрепить файлы, опубликовать immutable release; запросить release attestation, разобрать predicate и проверить подписанта/source ID.
2. Создать mutable release с `actions/attest-build-provenance` для файла; проверить signature, source repo ID, workflow identity, SHA256; использовать `gh attestation verify -R owner/repo --format json` как экспериментальный эталон, но проверить ограничения CLI.
3. Изменить существующий *тестовый* mutable asset и проверить, что сохранённый `(release ID, asset ID, SHA)` не переписывается автоматически; повторная публикация новой версии — отдельный выпуск.
4. Моделировать rename/transfer; проверить repository ID и owner ID, а также поведение `gh attestation verify` при старом и новом именах. Для transfer → suspend.
5. Попробовать аттестацию от другого репозитория/форка с тем же именем артефакта и большей версией; она не принимается.
6. Проверить случаи отсутствия provenance, неверного predicate, signer workflow, недоверенной корневой цепочки, отсутствия asset digest, без сети.
7. Проверить, не выдаёт ли GitHub CLI только name binding вместо repo ID при offline bundle; отдельно сверить embedded `sourceRepositoryIdentifier`.

## PASS и fallback

PASS при сохранённых в отчёте реальных JSON verification results и точных правилах сопоставления repo ID, asset SHA, release/commit. Нельзя ориентироваться только на имя файла и флаг `immutable`.

**Fallback:** отключить конкретный неподтверждённый режим (Strict или Attested) на данном хосте/проекте до появления проверенного средства верификации; источник observing, не «trust on SHA alone».
