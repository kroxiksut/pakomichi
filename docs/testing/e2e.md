# Сквозные сценарии E2E

## E2E-01 GitHub → APT

VM с Debian, тестовый публичный GitHub Release с 1.0 и 1.1 `.deb`, подписанное provenance. Закрепить repo ID, `source add`, инспекция, активировать family, выполнить `apt update && apt install sampleapp`, новый Release → `apt update && apt upgrade`; убедиться в нативной версии, SHA и отсутствии изменений чужих sources.

## E2E-02 GitHub → DNF

Аналогично на DNF4/DNF5, с signed RPM и подписью repodata. Для unsigned RPM — отдельно положительный только при явном согласии и разрешённой политике; обязательная подпись блокирует.

## E2E-03 Multiple packages

Release `sampleapp`, `sampleapp-cli`, `sampleapp-service`. Нативные зависимости main→service; обновление 1.0→1.1 согласовано; новая `sampleapp-driver` не добавляется автоматически.

## E2E-04 Установленная программа из другого источника

В системе уже `sampleapp 1.0`; Git предлагает 1.1. Сначала observing, затем user-approved migration в допустимой конфигурации. При равной версии с разными SHA автоматический переход не совершается.

## E2E-05 NetWatch (read-only внешний эталон)

Рассмотреть `matthart1983/netwatch`: `netwatch` `.deb/.rpm`, APT на GitHub Pages, COPR native dynamic vs GitHub static RPM, Rust name `netwatch-tui`. Не считать все варианты сборок идентичными. Не модифицировать чужой репозиторий и не пытаться установить конфликтующую сборку на рабочую машину.

## E2E-06 Uninstall / offline

В VM установить через нашу прослойку, оборвать сеть, проверить кеш и истечение freshness; удалить Pakomichi, убедиться, что программа остаётся установленной, а прочие системные источники сохранены.

Во всех случаях **фактические команды, хеши файлов, состояние пакетной базы до/после** — обязательное доказательство.
