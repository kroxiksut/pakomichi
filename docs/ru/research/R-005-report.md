# Отчёт R-005 — provenance evidence у пакетов в GitHub Releases

[English](../../en/research/R-005-report.md) · **Русский**

- **Дата / исполнитель:** 2026-10-20, программный агент по запросу владельца проекта; протокол: [R-005](R-005-provenance-survey.md).
- **Результат:** **PASS для исследовательского протокола**, но не для готовности продукта. Phase A содержит 100 подходящих репозиториев из двух источников и 291 строку релизов; Phase B полностью классифицировала детерминированную подвыборку из 20 репозиториев и 30 package assets.
- **Граница решения:** отчёт служит evidence для proposed ADR-018. Он не изменяет accepted ADR-005, не утверждает Pinned mode и не проверяет будущую quarantine-механику Pakomichi.

## Окружение и изоляция

Все сетевые запросы и проверки выполнялись непривилегированным пользователем `r005` в отдельной WSL2-дистрибуции `pakomichi-r005-survey`. Она импортирована из `fedora:44`, закреплённого manifest `sha256:be9d65e2…` и layer `sha256:59259e16…`. Использовались Python 3.14.8, GitHub CLI 2.97.0, GnuPG 2.4.9, minisign 0.12 и RPM 6.0.2; точные значения находятся в `research/r-005/results/environment.tsv`.

Личная Ubuntu владельца, package sources Windows, VirtualBox и чужие репозитории не изменялись. Исследование выполняло только read-only GitHub requests: issues, pull requests, forks, stars, comments и другие записи не создавались. Пакеты загружались в уникальные `/tmp/pakomichi-r005-*`, не устанавливались и не распаковывались и удалялись при выходе. Сырые API responses и verifier logs остались в игнорируемом `.research-local/r-005/`.

WSL отображает GitHub release hosts в benchmarking-range `198.18.0.0/15`. Phase B использовала документированный узкий opt-in только для этого диапазона; loopback, private, link-local, URL credentials, не-HTTPS URL и порты кроме 443 по-прежнему запрещались.

## Выборка и воспроизводимость

Выборка зафиксирована в `2026-10-20T07:45:32Z`:

- `deb-get` использован только как список имён GitHub repositories: commit `8fa6a694e2733f73ff4ec9cba8c12b0632b48ff8`, SHA-256 tarball `c1172a9e62c5ae5be254be8e30cb5f667804aa61b39e54f99ac30e4d2303f7f6`;
- GitHub Search использовал фиксированные topics `linux`, `cli` и `desktop`, каждый с `stars:>=100 archived:false fork:false`;
- приняты 80 репозиториев только из deb-get, 4 только из поиска и 16 из обоих источников;
- 31 кандидат исключён с сохранённой причиной: 25 не имели `.deb`/`.rpm` в 30 недавних релизах, 3 были archived, 2 — forks, 1 не найден;
- 94 репозитория дали три подходящих stable releases, 3 — два, 3 — один.

Это не prevalence survey всего GitHub. deb-get смещён к популярным desktop applications, а поиск — к starred projects и выбранным topics. Candidate list — исследовательский артефакт, а не discovery feature; collector не перечислял все репозитории владельца.

Команды воспроизведения:

```bash
bash research/r-005/run-phase-a.sh
python3 -I research/r-005/phase_b.py prepare \
  --sample research/r-005/results/phase-b-sample.tsv \
  --output research/r-005/results/phase-b-plan.tsv
# Перед запуском вручную разрешить каждую строку plan.
bash research/r-005/run-phase-b.sh
python3 -I research/r-005/aggregate.py \
  --phase-a research/r-005/results/phase-a.tsv \
  --phase-b research/r-005/results/phase-b.tsv \
  --repositories research/r-005/results/repositories.tsv \
  --regressions research/r-005/results/regressions.tsv \
  --summary research/r-005/results/aggregate.json
```

## Phase A: заявленное evidence

Phase A записывает имена и наблюдения GitHub API; asset с именем `.sig` не считается доказанной подписью.

| Классификация последнего релиза | Репозитории | Доля |
|---|---:|---:|
| Strict-claimed | 6 | 6% |
| Attested-claimed | 1 | 1% |
| Signed-claimed | 7 | 7% |
| Checksums-only | 8 | 8% |
| Nothing-observed | 55 | 55% |
| Unknown-attestation | 23 | 23% |

`Unknown-attestation` означает, что GitHub asset не предоставил digest и Phase A не могла выполнить адресованный по digest attestation request. Это не доказательство отсутствия attestation.

Полученное заявленное покрытие 0.1:

| Допущенные уровни | Репозитории | Доля |
|---|---:|---:|
| Strict + Attested | 7 | 7% |
| Strict + Attested + Signed | 14 | 14% |
| Плюс Pinned | 100 | только 100% теоретической eligibility |

Строка Pinned не измеряет quarantine, реакцию на mutation, explicit consent или безопасность. Её нельзя представлять как проверенное product coverage.

## Phase B: проверенная подвыборка

Двадцать репозиториев выбраны независимо от заявленного evidence детерминированным хешем даты выборки, repository ID и имени. Для каждого формата plan предпочитал native x86-64 package. Загружены и классифицированы 30 assets общим объёмом около 0,94 GiB.

| Высший подтверждённый уровень | Репозитории | Доля только Phase B |
|---|---:|---:|
| Strict | 3 | 15% |
| Attested | 1 | 5% |
| Signed | 0 | 0% |
| Checksums-only | 1 | 5% |
| Nothing-observed | 15 | 75% |

Strict + Attested покрывает 4/20 (20%) в Phase B; добавление Signed ничего не меняет. Процент описывает только детерминированную verification subset и не является оценкой всей сотни.

Важные детали проверки:

- GitHub release и asset attestations подтвердили Strict для `GyulyVGC/sniffnet`, `anchore/grype` и `olalie/tapmap`; artifact attestation подтвердила Attested для `sharkdp/fd`.
- Четыре sampled `Unknown-attestation` repositories были загружены и запрошены по вычисленному SHA-256. Все вернули точный 404 attestation endpoint и классифицированы `Nothing-observed`; транспортные ошибки отсутствием не считаются.
- `muesli/duf` опубликовал OpenPGP signature над checksums, а `fail2ban/fail2ban` — detached OpenPGP signature пакета. Структура подписей проверена, checksum file связывал выбранные duf assets, но точный поиск fingerprint и release notes не выявили key identity, опубликованную самим проектом. Оба остались `Nothing-observed`, а не Signed.
- Checksums `nextpad-plus-plus/nextpad-plus-plus-linux` связывали байты обоих выбранных пакетов, но не были подписаны, поэтому уровень остался Checksums-only.
- `rpmkeys --checksig --verbose` запускался в пустом inspection rpmdb для всех 10 выбранных RPM. Ни один не содержал встроенной RPM signature. GitHub Strict/Attested evidence и native RPM signature — независимые свойства; fallback обязательной политики R-002 сохраняется.

Таблица по репозиториям — `repositories.tsv`; точные package rows, digests, methods, RPM state и очищенные verdicts — `phase-b.tsv`. Подробный verifier output остаётся игнорируемым.

## Стабильность evidence между релизами

191 сравнимая пара соседних релизов дала:

| Переход | Количество |
|---|---:|
| Stable | 121 |
| Improvement | 6 |
| Regression | 0 |
| Unknown | 64 |

Шесть improvements добавили checksums, Strict release evidence или artifact attestation. Регрессий не наблюдалось, но 64 перехода неизвестны, потому что хотя бы в одном релизе отсутствовал API digest для Phase A. Выборка не доказывает, что evidence никогда не регрессирует; proposed ratchet ADR-018 всё равно требует прямых negative tests.

## Выводы и вход для решения

1. Контекстное предположение ADR-005 не подтверждается этой выборкой: только 7% последних релизов заявляли Strict или Attested evidence. Из-за известных смещений это input для решения, а не GitHub-wide prevalence estimate.
2. Добавление всех `Signed-claimed` повышает заявленное покрытие лишь до 14%, а Phase B не подтвердила ни одного Signed repository в детерминированной подвыборке. Имя signature-файла не считается без cryptographic verification против опубликованной проектом identity.
3. Pinned сделал бы все sampled repositories теоретически eligible, но R-005 не проверяла quarantine или mutation handling. Число 100% не доказывает безопасность или готовность Pinned для 0.1.
4. Отсутствие GitHub API asset digest существенно ограничивает metadata-only classification: 23% последних релизов получили `Unknown-attestation`. Download + hashing в Phase B разрешили четыре sampled случая в отсутствие наблюдаемого attestation.
5. Provenance и native package signatures ортогональны. Ни один из 10 выбранных RPM не имел встроенной подписи, включая RPM с подтверждённым Strict GitHub release evidence.

Для владельца проекта: результат поддерживает продолжение обсуждения ADR-018, поскольку ADR-005 оставил бы большинство выборки в `observing`. Он сам по себе не выбирает Signed или Pinned, не supersede ADR-005 и не заменяет необходимые R-003 и quarantine negative tests.

## Отклонения и наблюдения реализации

- Первая попытка Phase A завершилась после более 200 cached responses, потому что retry boundary не охватывал `http.client.RemoteDisconnected`. Теперь клиент повторяет `HTTPException` с bounded backoff; unit test воспроизводит disconnect, затем успех. Финальный authenticated run завершился с достаточным API quota.
- `cosign` не устанавливался, поскольку ни одна выбранная plan row не требовала его. GitHub attestations проверялись reference oracle из ADR-017 — GitHub CLI 2.97.0.
- Намеренно выбранные rare-signature examples не добавлялись в denominator. Phase B subset осталась детерминированной и независимой от claimed level.

## Предлагаемые строки для индексов

- `docs/ru/process/decisions-and-evidence.md`: `R-005 — PASS протокола: 100 репозиториев из deb-get и GitHub Search; заявленное покрытие последних релизов — 7% Strict+Attested и 14% с Signed-claimed; детерминированная Phase B проверила 20 репозиториев: 3 Strict, 1 Attested, 0 Signed, 1 checksums-only и 15 nothing observed. Pinned coverage только теоретическое; ADR-018 остаётся решением владельца.`
- `docs/ru/research/INDEX.md`: `Отчёт R-005: [provenance evidence у пакетов в GitHub Releases](R-005-report.md) — PASS протокола; 100 репозиториев и проверенная подвыборка из 20.`
