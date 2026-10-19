# Границы безопасности ОС

[English](../../en/architecture/privileges.md) · **Русский**

| Компонент | Права | Ограничение |
|---|---|---|
| Forge network client | user/unprivileged | Только исходящие запросы к выбранной платформе и проверяемым asset URL |
| Inspector пакетов | sandbox/unprivileged | Не исполнять `postinst`, rpm scripts; лимиты файлов/ресурсов |
| Проверка attestation | непривилегированно | Криптография и pinned IDs |
| Blob store | отдельный системный пользователь | Запрет подмены файла другим пользователем; content hash check |
| Local HTTP | unprivileged, loopback | Только GET/HEAD, никаких административных запросов |
| Signer | минимальные права к приватному ключу | Подписывать только одобренный Snapshot |
| Admin applier | root/ограниченный helper | Изменять **только наши** repo/prefs/keyring files; журнал изменений |
| Read-only API | локальный сокет | Без команд `apt install`, изменения ключей и источников |

Защищать от path traversal, SSRF, symlink race, zip bombs, потребления диска/памяти; не доверять имени `source`/`asset` как пути на ФС. Audit log не содержит токенов, ключей, bearer headers.

Глобальный контроль транзакций APT/DNF отсутствует в 0.1. Запуск в VM обязателен для испытаний установки конфликтных/опасных пакетов. Корневая компрометация всей ОС вне гарантий Pakomichi.
