# Машинные коды причин и ошибок

[English](../../en/specifications/errors.md) · **Русский**

| Код | Значение | Поведение |
|---|---|---|
| `E_REPO_ID_CHANGED` | По URL другой постоянный repo ID | Suspend, не следовать |
| `E_OWNER_TRANSFER` | Владелец сменился | Suspend до подтверждения |
| `E_ASSET_MUTATED` | Уже принятый артефакт изменился | Reject новой копии, не перепривязывать digest |
| `E_ATTESTATION_INVALID` | Проверка доказательства происхождения провалилась | Reject |
| `E_SIGNATURE_POLICY` | Системная политика требует недоступную RPM-подпись | Hold |
| `E_FAMILY_UNAPPROVED` | Новое имя пакета вне разрешённого семейства | Hold |
| `E_SYSTEM_PACKAGE_CONFLICT` | Попытка вытеснить системный пакет/критический `Provides` | Hold |
| `E_SOURCE_AMBIGUOUS` | Одинаковая версия из источников с разными байтами | Observing/hold |
| `E_DEPENDENCY_UNSATISFIABLE` | Требуемые зависимости отсутствуют | Hold |
| `E_PLATFORM_UNSUPPORTED` | Формат/arch/ABI явно не подходит | Hold |
| `E_SNAPSHOT_INCONSISTENT` | Индекс/ссылка/подпись снимка расходится | Не публиковать |
| `E_CACHE_DIGEST_MISMATCH` | Байты кеша не соответствуют принятому SHA | Не отдавать |
| `E_SOURCE_STALE` | Данные превысили допустимую свежесть | Ошибка нашего источника |
| `E_FORGE_UNAVAILABLE` | Git недоступен | Проверенный кеш по политике |
| `E_ADMIN_APPLY_FAILED` | Неполная запись локальной конфигурации | Rollback/reconcile |
| `E_DISK_EXHAUSTED` | Невозможно закончить снимок/загрузку | Отказ новой публикации, старый снимок не менять |

`Reason` содержит человекочитаемую причину и соответствующий source/package/release ID; чувствительные сведения из сети/ключи не логировать.

## Wire contract v1

Каждая причина передаётся как событие с явной версией схемы:

```json
{
  "schema_version": 1,
  "event": "reason",
  "reason": {
    "code": "E_REPO_ID_CHANGED",
    "object": {
      "kind": "source",
      "id": "source-1234"
    },
    "message": "repository identity changed"
  }
}
```

Версия `1` допускает `object.kind`: `source`, `package`, `release`, `artifact`,
`snapshot`, `operation`, `cache`, `platform`. Неизвестная версия, неизвестное
поле или неизвестное enum-значение отклоняются. `object.id` — ограниченный
идентификатор, а не URL. Человекочитаемый `message` создаётся только через
валидируемый тип: управляющие символы и распространённые формы credentials
отклоняются до сериализации и при десериализации. Формы распознаются по
структуре, а не по отдельному слову: присваивания и заголовки (`token=`,
`password:`, `Authorization:`), строки armor (`-----BEGIN …`), токены с
префиксом и реалистичной длиной (`ghp_…`, `github_pat_…`, `xox…`, `AKIA…`) и
любая userinfo-часть URL (`https://user@host`). Поэтому имена вроде
`slovakia-maps` и фразы о ключе подписи допустимы.

CLI отображает ту же причину без отдельной модели:

```text
[E_REPO_ID_CHANGED] source source-1234: repository identity changed
```

Запрет сигнатур чувствительных данных дополняет очистку на границе сетевых и
криптографических адаптеров, но не заменяет её: произвольную входную ошибку
нельзя напрямую превращать в `message`.
