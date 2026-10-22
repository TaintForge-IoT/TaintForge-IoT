# Экспериментальный переход capsule внутри unified

Этот шаг подключает проверочный C-плагин и Python-контроллер к настоящим
session/attempt, chroot, пространствам имён и финализации unified pipeline.
Режим включается только флагом `--capsule-probe` и сам собирает контрольный ELF.
Нативный `probe.c`, `guest.S`, заголовок QEMU и файлы фазы 1 не изменены.

## Что означает переход

У текущего контракта фазы 1 событие `export_ready` относится к финализации QEMU.
Ожидание этого события в остановленном живом госте не даёт пригодного механизма
перехода. Выбор `oep_candidate_selected` также не останавливает процесс в выбранном
адресе и не доказывает завершение анализа.

Здесь граница определяется символом `capsule_point_one` известного ELF. Контроллер
проверяет два снимка состояния, неизменность гостевого файла во время паузы,
идентичность реально загруженной фазы 1 и уже записанное событие её instruction
callback. После этого он разрешает продолжение. Вторая точка подтверждает, что
тот же процесс действительно продолжился, сохранив стек и FD.

Последовательность handoff в `observations.jsonl`:

| Запись | Значение |
|---|---|
| `handoff_ready`, point=1 | Состояние проверено; живые события Phase 1 относятся к этой попытке |
| `resume_requested`, point=1 | Контроллер начинает отправку `CONTINUE 1` |
| `continuation_observed`, point=2 | Получены и проверены два снимка после продолжения |
| `resume_requested`, point=2 | Контроллер начинает отправку `CONTINUE 2` |
| `guest_completed`, point=2 | Получено сообщение плагина `done`; успешный код выхода и гостевой oracle проверяются затем |

Финализатор проверяет общий порядок снимков, выдержанных пауз и handoff-записей.
Одной записи `resume_requested` недостаточно для подтверждения продолжения.
Каждая handoff-запись связана с `session_id`, `attempt_id`, хешем контракта,
`analysis_instance_id` и хешем runtime bundle. Ссылки на события Phase 1
повторно проверяются после остановки QEMU по префиксу, прочитанному на границе.

Анпакер продолжает работать после этой границы. `phase1_detached`,
`phase1_finished_at_handoff`, `analyzer_quiescence`, `whole_qemu_stop`,
`memory_isolation`, `checkpoint`, `oep_proven`, `fuzzing_ready` остаются `false`.
История стадий OEP в AttemptStore формируется прежним адаптером; эксперимент
не повышает её до доказанного OEP. Поддерживается только поставляемый
однопоточный ELF, одна попытка и `network=none`.

## Как устроен запуск

1. `run_unified_pipeline.prepare()` проверяет QEMU 11.0.1/API 6, собирает плагин
   и ELF. Плагин, его зависимости, ELF и адреса символов включаются в проверяемый
   analyzer runtime bundle. Произвольный `--binary` вместе с этим режимом запрещён.
2. `unified_runtime.prepare_attempt()` создаёт обычную привязку Phase 1 и
   `capsule_binding.json` с идентичностью текущей попытки.
3. Обычный sandbox wrapper создаёт пространства mount/PID/UTS/IPC/network.
   Каталог с Unix-сокетом монтируется в гостевой `/__taintforge_capsule`.
4. Python-supervisor запускается внутри пространства PID sandbox, вне chroot.
   Он создаёт отдельный процесс контроллера. Только контроллер владеет сокетом.
5. Supervisor запускает через `chroot` тот же упакованный динамический QEMU
   с двумя плагинами. QEMU и контроллер видят PID в одном пространстве имён;
   `SO_PEERCRED`, поле `host_pid` протокола и гостевой `getpid()` согласованы.
   Эти PID нельзя считать PID процессов в пространстве имён хоста.
6. После остановки QEMU supervisor проверяет протокол, код выхода, stdout,
   контрольный файл и состояние процесса контроллера, затем сохраняет результат.
   Копия гостевого `capsule-fd.txt` сохраняется в logs, пока supervisor ещё может
   прочитать файл с правами root/0600.
7. Wrapper убирает временные mounts и сокет. Обычный runner возвращает пользователю
   владение logs, собирает FS/syscall-наблюдения и независимо финализирует capsule
   и Phase 1. Успешные capsule-артефакты попадают в стандартный хешируемый комплект
   артефактов попытки.

Чтения QEMU по-прежнему выполняются только нативным instruction callback с
`QEMU_PLUGIN_CB_R_REGS`. Python читает сообщения и файлы свидетельств; дополнительного
доступа к CPU/памяти у него нет. Пауза одного vCPU не останавливает все потоки QEMU
или анализатора. Unix-сокет внутри linux-user не является защищённым каналом от
недоверенного гостя; режим предназначен для контрольного ELF.

## Карта файлов для чтения и рефакторинга

| Файл | Изменение и место в pipeline |
|---|---|
| `taintforge_env/execution_capsule.py` | Один новый адаптер: профиль bundle, привязка попытки, sandbox-команда, gate, supervisor и проверка результата |
| `scripts/run_unified_pipeline.py` | Opt-in флаги, сборка фиксированного ELF, точная проверка QEMU, включение capsule в `unified_report.json` |
| `taintforge_env/unified_runtime.py` | Добавление capsule в существующий bundle и подключение его sandbox-фрагмента; обычный режим сохраняется |
| `taintforge_env/prebuilt_runner.py` | Отдельный шаг финализации `capsule` после FS-наблюдения, до проверки Phase 1 |
| `experiments/execution_capsule_probe/controller.py` | Два необязательных параметра `control_worker`: путь к гостевому файлу и обработчик переходов; прежний standalone CLI сохраняется |
| `scripts/run_capsule_unified_e2e.py` | VM-приёмка: запускает реальные unified attempts, проверяет артефакты, очистку mounts и блокировку повторного исполнения |
| `tests/test_execution_capsule.py` | Модельные тесты gate, порядка событий, связности идентификаторов, отказов, финализации и supervisor |
| `experiments/execution_capsule_probe/BASELINE.json` | Добавляет хеш проверенной новой версии `unified_runtime.py`, чтобы прежний standalone suite работал после применения |
| `experiments/execution_capsule_probe/README_RU.md`, `SHA256SUMS` | Ссылка на эту интеграцию и актуальные контрольные суммы комплекта |

В новом адаптере функции сгруппированы по ходу исполнения:

- `bundle_profile()` / `verify_profile()` — описание и проверка capsule в bundle.
- `settings()` / `prepare_binding()` — ограничения режима и привязка к attempt.
- `sandbox_fragments()` — запуск supervisor и жизненный цикл IPC mount.
- `live_phase1_evidence()` / `Handoff` — разрешение продолжения и журнал состояний.
- `supervise()` — процессы, их завершение и первичная проверка результатов.
- `verify_evidence()` / `finish_attempt()` — повторная проверка и публикация итога.

Протокол сокета, чтение регистров/памяти и таймауты C не дублируются. Адаптер
использует существующие `control_worker()`, `validate_snapshot()` и `build()`.

## Команды на VM

Из корня репозитория после применения пакета; нужны уже использованные gcc,
binutils, pkgconf, glib2, Python 3.11+ и зависимости рабочего unified runner.

```bash
sudo -v
capsule_unified_out="workdir/capsule-unified-$(date +%Y%m%d-%H%M%S)"

python3 -m scripts.run_unified_pipeline run \
  --capsule-probe \
  --qemu /usr/bin/qemu-i386 \
  --plugin build/libtaintforge_ir.so \
  --network none --max-iterations 1 --max-steps 1 \
  --out "$capsule_unified_out"

python3 -m scripts.run_unified_pipeline verify --out "$capsule_unified_out"
```

В `unified_report.json`: `capsule.status=passed`, `capsule.snapshots=4`,
`capsule.continuation_observed=true`, `capsule.supervisor_kill=false`,
`execution.guest_exit_code=0`, `phase1.artifact_integrity=verified` и
`finalization.status=completed`. `verify` должен подтвердить binding и artifacts.

Приёмочная матрица из пяти сценариев:

```bash
sudo -v
python3 -m scripts.run_capsule_unified_e2e \
  --qemu /usr/bin/qemu-i386 \
  --plugin build/libtaintforge_ir.so \
  --out "workdir/capsule-unified-e2e-$(date +%Y%m%d-%H%M%S)"
```

Это `phase1-first`, `capsule-first`, `timeout-1`, `disconnect-1`, `kill-controller-1`.
Флаг `--all-cases` расширяет матрицу до 11 сценариев совместной загрузки.
`alone` остаётся в прежнем standalone suite. В матрице успешен ожидаемый отказ:
сама unified-попытка при нём имеет `intervention_required`, `capsule.status=aborted`,
код CLI 1. Повторный `resume` проверяется автоматически: исполнений должно быть 0.

Лимиты по умолчанию: удержание 200 мс, одна пауза 5000 мс, plugin total 30000 мс,
внешний wrapper 60 с. Его лимит должен превышать plugin total минимум на 12 с.
Для `total-timeout` используются прежние специальные 5 с общего лимита и 60 с паузы.
Принудительное убийство QEMU supervisor или внешним timeout не считается успешной
проверкой завершения самим плагином.

## Где смотреть результаты

В каталоге `session/iterations/0000/run/`:

- `config/capsule_binding.json` — входной контракт эксперимента этой попытки.
- `logs/capsule/observations.jsonl` — снимки, выдержанные паузы, handoff и done.
- `logs/capsule/supervisor.json` — код QEMU, завершение контроллера, fallback kill.
- `logs/capsule/controller.json` — результат worker; после его SIGKILL отсутствует.
- `logs/capsule/capsule-fd.txt` — сохранённые гостевые байты.
- `config/capsule_result.json` — повторно проверенный результат финализации.
- `config/finalization_status.json` — независимые результаты capsule, Phase 1,
  FS, syscalls и дальнейшей обработки.

Сводный `unified_report.json` находится в корне выбранного `--out`. Матрица создаёт
свой `report.json` с первичным отчётом каждой попытки и результатом проверки resume.
При намеренном `_exit(124/125/126)` Phase 1 может не успеть создать финальный capture
manifest. Это сохраняется как отдельный результат; артефакты не объявляются
финализированными. Любой прерванный capsule-handoff блокирует завершение попытки.

## Локальная проверка без QEMU

```bash
python3 -m unittest \
  tests.test_execution_capsule \
  tests.test_unified_pipeline \
  tests.test_unified_finalization \
  tests.test_unified_preflight -v
```

Эти тесты подставляют исполнение гостя. Они проверяют интеграционный контракт и
реальные механизмы обработки/сохранения результатов, но не подтверждают работу
QEMU, mount/PID namespaces или реального Unix listener. Это задача VM-матрицы.
