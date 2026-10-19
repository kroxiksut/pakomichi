# Предлагаемые CLI и read-only API

[English](../../en/specifications/cli-api.md) · **Русский**

**Имена команд утверждены владельцем:** основная короткая команда — `pchi`, полная команда — `pakomichi`. Обе точки входа предоставляют один и тот же CLI, набор аргументов, коды завершения и семантику вывода. Документация и интерактивные примеры по умолчанию используют `pchi`. Конфликтующее имя `gitbridge` не использовать.

```text
pchi source add <https-git-url> [--observe]
pchi source list
pchi source inspect <id>
pchi source activate <id> --packages <comma-list> [--policy supplemental|preferred]
pchi source suspend <id>
pchi source remove <id>  # не удаляет программы
pchi sync [<id>] [--force]
pchi status [--json]
pchi diagnose [--json]
pchi cache status
```

Полная форма заменяет только имя точки входа: `pakomichi source list` эквивалентно `pchi source list`. Способ поставки двух точек входа (например, alias, symlink или отдельный launcher) выбирается при реализации пакета, но не должен создавать две расходящиеся реализации CLI.

`add` сам по себе не активирует пакет. Не применять `--yes` для подтверждения transfer repo owner, смены издателя или неоднозначности. Активирование требует прав администратора и выводит исходный и итоговый план файлов/источников.

**Статус API (только чтение):** список источников, идентичность, режим, last_successful_sync, trusted snapshot age, список установленных/допустимых версий, причины held, build variant/confidence, app/package statuses. JSON-ответ содержит `schema_version`, machine-readable `state`, `reason_code`.

API не должен предоставлять команды `install`, `upgrade`, `change source`, `add repo`, `import key`. Приложения могут показать пользователю доступное обновление, но установку выполняет нативный пакетный менеджер.

**Ошибки:** подробности см. `errors.md`. Вывод без секретов/токенов. Не вводить фальшивое сообщение «пакет защищён», если проверено лишь совпадение SHA.
