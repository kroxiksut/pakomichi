# Контракт адаптера GitHub Releases

1. При `source add` получать repo canonical URL, numerical repository ID, owner ID из API. При каждой синхронизации сверять их. Git rename с неизменными ID допускается; owner transfer -> приостановить.
2. Запрашивать только Releases выбранного repo ID. Никаких Search API для соседних repos, форков, альтернативных владельцев. Не использовать HTML scraping.
3. Release ID/tag/target_commitish — разные поля. Требуется верифицированная связь с коммитом и выпуском там, где режим доверия её заявляет; `target_commitish` не является достаточной криптографической проверкой SHA.
4. Сначала изучать список assets (name, size, digest, ID), отфильтровывать формат/архитектуру; по необходимости скачивать *только* кандидатов и инспектировать родные метаданные.
5. Сверять digest полученного содержимого, не считать API `digest` независимой подписью. Проверить cryptographic attestation, predicate, verified source repo ID, workflow и exact digest.
6. Каналы stable/beta/alpha — явная политика и нативная версия; флаг `prerelease` изменяем и не единственный критерий.
7. Записывать ETag/Last-Modified, использовать условные запросы, backoff по `Retry-After` и лимитам; при ошибке не подменять достоверную дату успешной синхронизации.
8. HTTP redirect validation на каждом hop; не обращаться к приватным IP/metadata endpoints по параметрам недоверенного источника; ограничить размеры/число assets.
9. Нет аттестации/проблемы repo ID/файл изменился → `held`/`rejected`, событие журнала, не публикация.

Ссылки: `docs/references.md`. Обязательное исследование: `R-003`.
