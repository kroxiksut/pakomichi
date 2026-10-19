# Дорожная карта Pakomichi 0.1 alpha

[English](../en/roadmap.md) · **Русский**

**Этап 00 — подготовка:** структура, Rust baseline, SQLite модель, инструменты и лицензирование. Rust 1.94.1 утверждён ADR-015; начальные runtime, библиотеки, упаковка и модель процессов утверждены ADR-017 по итогам прототипа P0-004.

**Этап 01 — проверка блокирующих гипотез:** R-001 APT/DNF, R-002 RPM checks, R-003 GitHub proof, R-004 socket/snapshots. После отдельных результатов можно делать зависимые компоненты; 01 не блокирует всю прочую работу.

**Этап 02 — ядро:** pinned GitHub repo identity, Releases discovery, metadata, Strict/Attested verification, safe DEB/RPM inspection, CAS, family policy.

**Этап 03 — Linux native:** подписанные APT/RPM-индексы, отдельные политики выбора источника, один HTTP gateway и полный путь установки/обновления через штатные инструменты.

**Этап 04 — эксплуатация:** CLI, read-only API, privileged apply/reconcile, freshness, offline, uninstall/recovery, злоумышленный ввод.

**Этап 05 — alpha:** E2E на зафиксированных дистрибутивах, реальные проекты (NetWatch и другие), пользовательская инструкция, пакет Pakomichi, release-gate.

## Критический путь

`Rust-прототипы → каркас репозитория → GitHub provenance → Strict/Attested → policy engine → APT/RPM metadata → HTTP snapshots → native upgrade E2E → platform matrix → alpha gate`. Исследования выбора источника, RPM-подписей и отказоустойчивой доставки можно выполнять параллельно; путь зависит от допустимых fallback.

## Не расширять 0.1

GUI, WinGet, GitLab/Forgejo/Gitea, общедоступные каталоги пакетов, автоматически найденные форки и самостоятельный dependency solver — отдельные будущие эпики.

## Артефакты вех

- После этапа 01: четыре отчёта исследований и обновлённые ADR/матрица ОС.
- После этапа 02: воспроизводимая проверка чужих assets + state DB.
- После этапа 03: E2E apt/dnf install+upgrade, включая конфликты.
- После этапа 04: crash recovery, удаление и диагностика.
- После этапа 05: подписанные сборки мостового пакета, alpha notes, support matrix и release evidence.
