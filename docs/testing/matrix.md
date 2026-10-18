# Матрица проверяемых платформ

Это план испытаний, а не заявление о поддержке. В итоговой альфе перечислить **только реально проверенные** комбинации.

| Экосистема | Среда для экспериментов | Контроль |
|---|---|---|
| APT | Debian 12 amd64 | `apt --version`, systemd, signature, install→upgrade, equal version conflict |
| APT | Debian 13 amd64 | То же + modern deb822 source |
| APT | Ubuntu 24.04 amd64 | То же + системные библиотеки |
| DNF4 | образ дистрибутива с реально установленным DNF4 | RPM signatures, policy, family, origin collision |
| DNF5 | образ дистрибутива с реально установленным DNF5 | pkg/repo GPG semantics, command differences |
| APT | Debian arm64 (при доступности CI/VM) | asset selection и native metadata |
| RPM | aarch64 (при доступности CI/VM) | ABI/arch, dependencies |
| Astra Linux | **не заявлять поддержанной без отдельного испытания** | реальное окружение и политика ОС |

Версию систем `bookworm/trixie/...` не выводить из названия машины; сохранять `os-release`, `uname -a`, версии managers и список sources. Для socket activation требуется среда с настоящим systemd, не произвольный контейнер без init.

## Для каждого стенда

- Fresh snapshot VM, тестовые локальные repos и лабораторные ключи.
- Изоляция `dpkg/rpm` состояния от production.
- Логи команд: `apt-cache policy`, `apt-get -s`, `dnf repolist`, фактические SHA downloaded artifacts, подпись репозитория.
- Негативные случаи: совпадение версий, GPG отказ, stale snapshot, поведение offline.
- PASS/FAIL/INCONCLUSIVE с причиной, ссылки на R-отчёт.
