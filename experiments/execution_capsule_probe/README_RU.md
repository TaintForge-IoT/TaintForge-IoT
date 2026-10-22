# Execution Capsule — проверочный комплект v1

Компактный эксперимент для **динамического QEMU linux-user 11.0.1, i386, plugin API 6**.
Три основных файла: `probe.c`, `controller.py`, `guest.S`. Плагин фазы 1 загружается
из выбранного `build/libtaintforge_ir.so`; его исходники, сборка и `.runtime.json`
не изменяются. Standalone suite сохраняется. Отдельный opt-in режим
`--capsule-probe` подключает этот же плагин к unified runner: описание контракта,
карта файлов и команды находятся в
[EXECUTION_CAPSULE_UNIFIED_V1.md](../../docs/EXECUTION_CAPSULE_UNIFIED_V1.md).
Исторические `LOCAL_VALIDATION.*` ниже описывают исходный standalone-комплект.

## Исходная версия

Проверена сохранённая локальная интеграция `6b99be177940a8ae20200ae6572e2a78a0c8cabe`,
включающая unified finalization и `taintforge_target_state_fix_v1` от 17 сентября.
Файлы последнего пакета совпали с локальной интеграцией по SHA-256.

GitHub `main` проверен на `3e74e480eea3e945786aa931690609afb81f5f24`:
в нём отсутствуют `unified_runtime.py` и `syscall_result.py`, отличается target oracle.
При этом `Phase1Run` на GitHub содержит более новое необязательное поле
`flags_receipt`: эта конкретная совместимая версия тоже разрешена установщиком.
GitHub и локальные пакеты нельзя считать взаимозаменяемыми целиком.

`BASELINE.json` содержит проверенные хеши пяти интеграционных файлов. Установщик
сверяет содержимое, поэтому применять пакеты и коммитить их тем же SHA не требуется.
При неизвестных отличиях установка прекращается до копирования. Не заменяйте свою
интеграцию старым GitHub checkout для прохождения проверки: сохраните вывод `audit`
и сверьте изменившиеся файлы. Чужие изменения не откатываются.

## Применение на Arch Linux

Поместите скачанный архив в `~/Downloads/taintforge_execution_capsule_probe_v1.zip`.
Команды выполняются **из корня актуального локального TaintForge-IoT**:

```bash
sudo pacman -S --needed gcc binutils pkgconf glib2 python unzip

capsule_kit_dir="$(mktemp -d)"
unzip "$HOME/Downloads/taintforge_execution_capsule_probe_v1.zip" -d "$capsule_kit_dir"

python3 "$capsule_kit_dir/taintforge_execution_capsule_probe_v1/controller.py" audit --repo .
python3 "$capsule_kit_dir/taintforge_execution_capsule_probe_v1/controller.py" install --repo .

python3 experiments/execution_capsule_probe/controller.py suite \
  --repo . \
  --qemu /usr/bin/qemu-i386 \
  --phase1 build/libtaintforge_ir.so \
  --out "workdir/capsule-probe-$(date +%Y%m%d-%H%M%S)"
```

Установщик только добавляет `experiments/execution_capsule_probe/`. Существующий
каталог не перезаписывается. Для работы достаточно Python 3.11+; multilib/libc i386
для сборки этого ELF не нужны: используются `as --32` и `ld -m elf_i386`.
Скрипт ничего не скачивает и не пересобирает QEMU либо анпакер. Сам запуск не требует sudo.

`suite` собирает новый host-плагин и контрольный ELF, проверяет точную версию QEMU,
динамическую компоновку, целостность `.runtime.json` и API 6. На каждый сценарий
создаётся новый каталог и новый процесс QEMU. **Две точки внутри одного сценария
проходятся в одном и том же гостевом процессе**; повторного запуска между ними нет.

Отдельный положительный запуск:

```bash
python3 experiments/execution_capsule_probe/controller.py suite \
  --repo . --qemu /usr/bin/qemu-i386 --phase1 build/libtaintforge_ir.so \
  --case phase1-first --out "workdir/capsule-single-$(date +%Y%m%d-%H%M%S)"
```

`--case alone` проверяет только загрузку capsule-плагина; выбранный Phase 1 runtime
при этом всё равно проверяется на preflight, но не передаётся QEMU.

## Что делает эксперимент

1. Однопоточный статический ET_EXEC открывает `capsule-fd.txt` с O_EXCL в новом
   рабочем каталоге, записывает `before\n`, размещает 32 байта контрольных данных
   на стеке. Обе паузы происходят внутри вызванной функции; после них выполняется `ret`.
2. В первой точке плагин читает девять i386-регистров, 16 байт буфера и 32 байта стека.
   EAX = `0x11111111`, ECX указывает на буфер `0123456789ABCDEF`, EDX = 16.
3. Контроллер удерживает выполнение на 200 мс, проверяет отсутствие продвижения
   файлового результата, запрашивает повторное чтение `CHECK 1` и сверяет состояние.
   Команда `CONTINUE 1` возвращает управление из callback.
4. **Сам ELF** проверяет стек/PID/смещение FD, дописывает `between\n`, меняет буфер
   на `fedcba9876543210` и доходит до второй точки с EAX = `0x22222222`.
5. После второй пары чтений и `CONTINUE 2` ELF снова проверяет стек и смещение FD,
   дописывает `after\n`, читает файл обратно через тот же дескриптор, сравнивает все
   21 байт, закрывает FD, возвращается в вызывающий код и печатает `CAPSULE_OK`.

Контроллер дополнительно сверяет неизменные PID, ESP, EBP, ESI, EDI и содержимое
стека между точками. Изменение буфера инициируется гостем; команды записи в память
контроллеру не предоставляются. Режим для произвольного ELF отсутствует.

## Контекст QEMU и границы результата

Регистры перечисляются в vCPU init callback. Чтения выполняются только из
instruction-exec callback с `QEMU_PLUGIN_CB_R_REGS`. При API 6 результат
`qemu_plugin_read_register()` — `bool`; длина проверяется отдельно. Нулевой opaque
handle EAX не считается отсутствующим регистром.

Точки — цели переходов после завершённых syscalls, чтение EIP сравнивается с адресом
символа. Это ограниченный контрольный случай: API чтения памяти сам по себе не
обещает flush всех ожидающих записей. Повторное чтение и точные ожидаемые байты
проверяют данный запуск; из них не следует общая гарантия согласованности.

В callback есть ограниченное по времени ожидание команды. Отдельный pthread
использует только host `poll`, монотонные часы и завершение процесса. Он не читает
регистры/память QEMU и не разбирает команды. Он также обнаруживает потерю контроллера
или общий таймаут, если гостевой callback ещё не вызван.

**Пауза одного vCPU не означает остановку всего QEMU, рабочих потоков или callbacks
анализатора.** Порядок выполнения callbacks двух плагинов не является барьером
quiescence. Само ожидание может влиять на QEMU/анализатор; два порядка загрузки
нужны именно для наблюдения такой совместимости. Второй vCPU отвергается.

В пределах одного сценария Python-supervisor запускает отдельный процесс
контроллера, который владеет Unix-сокетом. Supervisor не владеет подключённым
control endpoint и остаётся жив, когда тест убивает контроллер. Он собирает exit
status QEMU; принудительное убийство со стороны supervisor считается провалом теста.

Сокет находится в частном каталоге `/tmp` с правами 0700, сам сокет имеет 0600,
обе стороны проверяют SO_PEERCRED. Это **не изоляция от недоверенного гостя внутри
linux-user**. Используется только поставляемый безопасный ELF: у него нет сетевых
syscalls. Отдельный network namespace/seccomp этим прототипом не создаётся.

При ошибке используется `_exit(124/125/126)`: процесс завершается без запуска
atexit-финализации QEMU/фазы 1. Открытые FD закрывает ядро. Неполные артефакты
анализатора ожидаемы в отрицательных сценариях и не выдаются за финализированные.
Освобождение памяти анпакера, detach, checkpoint, RSP и фаззинг не реализованы.

## Матрица VM

| Сценарий | Ожидаемое завершение QEMU | Что проверяется |
|---|---:|---|
| `alone` | 0 | Два чтения в каждой точке, два продолжения, гостевой oracle |
| `phase1-first` | 0 | Сначала анпакер, затем capsule; подтверждённые события/артефакты Phase 1 |
| `capsule-first` | 0 | Обратный порядок загрузки с теми же проверками |
| `timeout-1`, `timeout-2` | 124 | Нет CONTINUE; гость не проходит соответствующую точку |
| `disconnect-1`, `disconnect-2` | 125 | Контроллер закрывает соединение |
| `kill-controller-1`, `kill-controller-2` | 125 | Настоящий SIGKILL процесса контроллера |
| `bad-command` | 126 | Неверный номер точки в CONTINUE |
| `slow-command` | 124 | Незавершённая команда не продлевает deadline |
| `total-timeout` | 124 | Общий лимит 5 с при лимите паузы 60 с |

Во всех отрицательных сценариях загружен анпакер первым. Проверяется его
`analysis_started` с правильным build_id/API и событие instruction callback;
финальный capture manifest после `_exit` не требуется. В двух положительных
совместных запусках используется существующий `Phase1Run.verify()`.

По умолчанию лимит одной паузы — 1500 мс, общий — 30000 мс. Для медленной VM можно
передать `--pause-ms 5000 --total-ms 120000`. У `total-timeout` собственный лимит 5 с:
если анализатор до первой точки работает дольше, тест честно завершится как failed,
а не заявит, что сценарий был пройден. Heartbeat не продлевает бюджеты.

## Отчёт

Путь `report.json` печатается в конце. Успешная матрица: верхний `status=passed` и
12 сценариев со `status=passed`. У ожидаемых аварий `qemu_exit` остаётся ненулевым.
`status=passed` означает выполнение критериев эксперимента, не готовность полноценной капсулы.

Внутри каждого сценария: `observations.jsonl`, `result.json`, `stdout.log`,
`stderr.log`, `capsule-fd.txt` и, где применимо, `phase1/`. При SIGKILL файл
`controller.json` может отсутствовать; supervisor проверяет сигнал завершения
контроллера и предварительно записанное событие `controller_kill`.
Сокет удаляется при завершении supervisor. Сохраняются версии, SHA-256 QEMU,
Phase 1 runtime, собранных артефактов и проверка исходной интеграции.

Для разбора неудачи нужны `report.json`, `result.json` и `stderr.log` соответствующего
сценария. Коды: 124 — таймаут, 125 — потеря контроллера, 126 — нарушение контракта;
77 — собственная проверка ELF не прошла. Ошибка загрузки плагина — отдельный failed.

## Локальные тесты без QEMU

```bash
cc -std=c11 -O1 -g -Wall -Wextra -Werror -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I experiments/execution_capsule_probe/vendor \
  experiments/execution_capsule_probe/tests/host_harness.c \
  $(pkg-config --cflags --libs glib-2.0) -o /tmp/capsule-host-tests

CAPSULE_HARNESS=/tmp/capsule-host-tests ASAN_OPTIONS=detect_leaks=0 \
  python3 experiments/execution_capsule_probe/tests/test_host.py
```

Это 14 модельных тестов: CPU API подставной, C-код плагина настоящий, IPC проходит
через socketpair. Создание/listen/connect Unix-сокета подменены только в test harness.
Тестовый API проверяет, что обращения к состоянию идут из назначенного CPU-потока.
Такие тесты не подтверждают фактический контекст QEMU, co-load или гостевой oracle.
Проверка утечек выключена, поскольку отказные сценарии намеренно используют `_exit`.

Фактически выполненные проверки и ограничения среды перечислены в
`LOCAL_VALIDATION.md` и `LOCAL_VALIDATION.json`.

## Закреплённые источники API

Использован тег `v11.0.1`, commit `6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55`:

- [Заголовок plugin API](https://github.com/qemu/qemu/blob/6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55/include/plugins/qemu-plugin.h).
- [Реализация read_register/read_memory](https://github.com/qemu/qemu/blob/6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55/plugins/api.c).
- [Генерация TCG callbacks](https://github.com/qemu/qemu/blob/6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55/accel/tcg/plugin-gen.c).

Заголовок включён в `vendor/` без изменений; Git blob
`4eb1d2cd85c615916dcf60c70aceb4f450f185d3` проверен. Документация master не используется
как контракт этой версии. Лицензия исходников — GPL-2.0-or-later; notices заголовка сохранены.
