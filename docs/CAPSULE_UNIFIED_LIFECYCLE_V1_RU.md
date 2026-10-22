# Lifecycle-плагин в unified runner

Состояние: интеграция реализована; приёмка на VM с настоящим QEMU и пользовательской
сборкой Phase 1 ещё не выполнена. В этой поставке 45 проверок Python и 15 нативных
проверок lifecycle прошли. Python-проверки используют тестовые исполнители QEMU и
systemd. Нативные проверки загружают настоящий `owner.c` как `.so`, выполняют IPC,
выделение/обнуление/освобождение арены и `dlclose`; планирование удаления QEMU
заменено хостовым harness. Для ограничений текущей среды использованы тестовые
socketpair и перевод PID для `/proc`. Это не результат приёмки QEMU.

## Что теперь выполняется

`--capsule-lifecycle` запускает существующий unified pipeline с тремя плагинами:
неизменённой Phase 1, capsule observer и lifecycle owner. Запуск использует
контролируемый i386 ELF из проекта. Owner имеет собственную арену 4 МиБ и проходит
цикл export → uninstall → callbacks removed → zero/munmap → выгрузка библиотеки.
Observer проверяет продолжение гостя в том же процессе, регистры, стек и файловый
дескриптор. Phase 1 продолжает работать до завершения гостя.

Это настоящий путь запуска через unified runner, chroot, namespaces, runtime
bundle, attempt contract и финализацию. Выбор произвольного ELF вместе с
`--capsule-lifecycle` пока запрещён: адреса двух точек и содержимое экспорта
определены контролируемым ELF. Обычный `--binary` продолжает использовать прежний
режим без lifecycle.

## Файлы и место в системе

| Файл | Изменение и роль |
| --- | --- |
| `taintforge_env/capsule_lifecycle.py` | Новый адаптер owner к unified attempt. Формирует аргументы плагина, объединяет live-гейты, сохраняет экспорт, повторно проверяет протокол и maps при финализации. |
| `taintforge_env/capsule_resources.py` | Новый адаптер transient system service. Ограничивает всё дерево sandbox/QEMU, проверяет реальные параметры cgroup до запуска QEMU, подтверждает завершение дерева после выхода. |
| `taintforge_env/unified_runtime.py` | Включает owner `.so` и его зависимости в хешируемый runtime bundle. |
| `taintforge_env/execution_capsule.py` | Привязывает lifecycle и ресурсную политику к попытке, запускает три плагина, проверяет события и файлы перед завершением attempt. |
| `taintforge_env/prebuilt_runner.py` | Выполняет lifecycle-запуск через ресурсную службу; сохраняет прежний sandbox и проверку кода выхода. |
| `scripts/run_unified_pipeline.py` | Добавляет CLI-флаги lifecycle, режима ошибки, порядка плагинов и памяти; включает сведения о службе в `unified_report.json`. |
| `scripts/run_capsule_unified_e2e.py` | Добавляет `--lifecycle`: положительные сценарии, ошибки owner и контроллера, проверку блокировки повторного исполнения. |
| `experiments/execution_capsule_lifecycle/controller.py` | Позволяет задавать путь экспорта и корень `/proc`; unified читает приватный proc mount своего PID namespace. |
| `experiments/execution_capsule_lifecycle/tests/test_lifecycle.py` | Добавляет нативную проверку выбора proc mount. |
| `tests/test_capsule_unified_lifecycle.py` | Новые проверки bundle, порядка трёх плагинов, экспорта/maps, отказов, очистки службы и лимитов до запуска. |
| `experiments/execution_capsule_{probe,lifecycle,contain}/BASELINE.json` | Добавляет точные хеши проверенной версии bundle-кода. Проверки источников сохраняются. |

Существующий `experiments/execution_capsule_lifecycle/owner.c` не менялся.
`unpacker/**`, `taintforge_env/phase1_runtime.py` и интерфейс экспорта Phase 1
не менялись. Новый экспорт `lifecycle/export.bin` принадлежит только fixture owner;
он не подменяет результат анализа Phase 1.

## Условия успешного запуска

1. Выбрана совместимая сборка QEMU 11.0.1, API 6 и Phase 1 с валидным runtime
   manifest. Bundle содержит проверяемые копии всех трёх плагинов.
2. Перед QEMU supervisor проверяет собственное членство в cgroup, `memory.max`,
   `memory.swap.max=0`, `memory.oom.group=1`, `pids.max=64`, `NoNewPrivs=1` и
   `RLIMIT_CORE=0`. Если проверка не проходит, QEMU не запускается.
3. На первой точке подтверждаются live-события Phase 1, peer PID/UID и
   начальное состояние lifecycle. Запрос uninstall может уже быть отправлен;
   завершение удаления на этой точке ещё не допускается.
4. До разрешения продолжения со второй точки контроллер получает все пять
   событий и EOF, проверяет размер/хеш/содержимое экспорта. По maps того же PID и
   времени старта он подтверждает исчезновение owner `.so` и всего диапазона
   арены, а также присутствие observer и Phase 1.
5. После выхода повторно проверяются протокол, экспорт, сохранённые maps, порядок
   handoff-событий, привязки attempt и результат гостя. Внешний runner подтверждает
   остановку службы и отсутствие процессов в её cgroup.

Сообщение `resources_released` само по себе не достаточно для успеха. Обнуление
заявляет producer; исчезновение диапазона контроллер проверяет независимо.
Это не доказательство стирания всех копий данных или всех выделений анализатора.

## Ограничение ресурсов

По умолчанию: 1024 МиБ, swap 0, 64 задачи, lifetime службы `--timeout + 10`
секунд, `KillMode=control-group`, `OOMPolicy=kill`, остановка с таймаутом 5 секунд.
Разрешён `--capsule-memory-mib` от 256 до 4096. `systemd-run --wait --pipe`
передаёт код выхода sandbox; он сверяется с `guest_exit_code`.

Служба системная, поскольку существующий unified sandbox требует root для
mount/chroot/unshare. Прежний bubblewrap containment с запретом вложенных userns
и сброшенными capabilities не может просто оборачивать этот privileged runner.
Он остаётся отдельным экспериментом. Здесь добавлен ресурсный контроль вокруг
существующей изоляции unified, без утверждения о равенстве двум sandbox-профилям.

Префлайт требует systemd и cgroup v2. Автоматического перехода к запуску без
лимитов нет. OOM, timeout службы, неподтверждённая очистка или отсутствие
свидетельств не могут дать успешную финализацию. Данные остановки службы доступны
в отчёте даже при незавершённой финализации гостя.

## Запуск на VM

Выполнять из корня репозитория обычным пользователем. Нужны существующие
зависимости unified runner, systemd/cgroup v2, GCC, binutils, pkg-config и GLib
development headers. Phase 1 заранее собрана в `build/libtaintforge_ir.so` с
соответствующим `.runtime.json`. Эти команды её не пересобирают.

Один положительный запуск:

```bash
sudo -v
python3 -m scripts.run_unified_pipeline run \
  --capsule-lifecycle \
  --qemu /usr/bin/qemu-i386 \
  --plugin build/libtaintforge_ir.so \
  --network none --max-iterations 1 --max-steps 1 \
  --timeout 60 --capsule-memory-mib 1024 \
  --out runs/capsule-unified-lifecycle-01
```

Каждый `--out` должен быть новым каталогом. Неподдерживаемая версия QEMU или
изменённые защищённые источники останавливают подготовку: не обходить эту
проверку заменой хешей на непроверенные значения.

Полная приёмка этой поставки — 15 сценариев:

```bash
sudo -v
python3 -m scripts.run_capsule_unified_e2e \
  --lifecycle --all-cases \
  --qemu /usr/bin/qemu-i386 \
  --plugin build/libtaintforge_ir.so \
  --memory-mib 1024 \
  --out runs/capsule-unified-lifecycle-e2e-01
```

Ожидаемый результат верхнего `report.json`: `status=passed`. Положительные
запуски должны иметь `capsule.lifecycle.owner_retired=true`,
`capsule.resources.tree_empty=true` и завершённую финализацию. Преднамеренные
ошибки owner (`keep`, `leak-arena`, `bad-export`) имеют `capsule.status=aborted`,
код QEMU 125 и отказ автоматического resume. Сценарий приёмки считается пройденным
именно при подтверждённом отказе; сама попытка исполнения остаётся failed.

`--capsule-owner-order before` проверяет загрузку owner первым; по умолчанию
он идёт последним. `--capsule-case capsule-first` меняет порядок observer/Phase 1.
Совмещать ошибку owner с ошибкой контроллера запрещено, чтобы причина остановки
оставалась однозначной.

## Сохранённые свидетельства

Для каждой попытки под `session/iterations/0000/run/`:

| Путь | Содержимое |
| --- | --- |
| `config/capsule_binding.json` | Идентичность попытки, bundle, lifecycle nonce, режим, адреса и ресурсная политика. |
| `config/capsule_result.json` | Итог повторной проверки lifecycle/ресурсов и границы доказанного результата. |
| `logs/capsule/observations.jsonl` | Снимки гостя, handoff-события и verdict lifecycle в едином порядке. |
| `logs/capsule/lifecycle/export.bin` | Ограниченный экспорт owner, скопированный до удаления временного IPC. |
| `logs/capsule/lifecycle/evidence-point-N.json` | События протокола, EOF, verdict и привязки к процессу на каждой достигнутой точке. |
| `logs/capsule/lifecycle/maps-point-N.txt` | Снимки mappings; при раннем отказе соответствующего файла может не быть. |
| `logs/capsule/resources.json` | Проверенные изнутри лимиты перед стартом QEMU. |
| `logs/capsule/service.json` | Команда службы, её результат и подтверждение очистки снаружи. |
| `logs/capsule/supervisor.json` | Команда QEMU с тремя `-plugin`, PID в sandbox, коды выхода и диагностика. |

Файлы сохраняются вместе с артефактами попытки. Неудача после начала исполнения
не разрешает автоматически повторить ту же попытку.

## Граница перехода к вырезанию анпакера

Подготовлены загрузка owner в рабочем runner, передача экспорта, проверка удаления,
ресурсные ограничения и привязка результата к attempt. Сейчас освобождается
только память fixture owner. Реальная Phase 1 остаётся активной;
`phase1_retired`, `exact_oep_cutover`, `guest_analyzer_memory_separated` и
`hostile_sample_ready` остаются `false`.

После VM-приёмки следующий этап потребует отдельного изменения Phase 1: выделить
всё принадлежащее анпакеру состояние, завершить и проверить её настоящий экспорт,
отключить её callbacks/фоновые работы и освободить это состояние. Затем заменить
фиксированные точки fixture подтверждённой точкой перехода настоящего образца.
Текущая интеграция даёт место для этой замены; сама поставка не заявляет её
выполненной и не объявляет произвольный вредоносный ELF безопасным для запуска.
