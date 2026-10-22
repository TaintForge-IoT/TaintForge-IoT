# Ресурсы Phase 1 в M4

Учёт включается параметром `m4-memory-bytes` только в профиле `--capsule-hardening`. Основной attempt contract связан с бюджетами через `observer-contract.json`: он содержит полный основной contract, его SHA, nonce и settings; SHA этого файла проверяется при запуске и финализации.

`phase1_alloc.h` включается при сборке всех C-модулей плагина. Явные malloc/calloc/realloc и используемые g_malloc/g_new/g_strdup проходят через `phase1_resources.c`. Запись содержит адрес, запрошенный размер и модуль-владелец. Реестр имеет 65 536 слотов и до 64 владельцев; его статические структуры входят в учитываемый бюджет. Проверяются переполнение произведений и память на время realloc, включая одновременно старый и новый блок. Перед free старый блок обнуляется volatile-записями. GLib-контейнеры и память, выделенная внутри внешних библиотек, этим перехватом не охвачены.

| Группа | Владелец / очистка | Область |
| --- | --- | --- |
| page_t и write bitmap | pages → page_destroy | Структуры учёта гостевых страниц; явное обнуление, затем free. Гостевые страницы сохраняются. |
| Состояние vCPU и регистровые scratch | g_vcpu_states → plugin_vcpu_state_destroy | Структура и используемые данные GByteArray обнуляются; handles QEMU заимствованы. |
| Метаданные инструкций и callback userdata | meta_free, insn_exec_contexts_destroy | Объекты плагина освобождаются после снятия callbacks. |
| Trace, aux, branch index и DCFG | trace_buffer_destroy, dse_aux_destroy, branch_event_buffer_destroy, dcfg_graph_destroy | Явные массивы/узлы проходят ledger; внутренности GLib остаются внешней областью. |
| Provenance, shadow и metadata FD | provenance_runtime_destroy | Собственные массивы и строки освобождаются; числовые guest FD здесь — ссылки, их закрывать нельзя. |
| Файловые/сетевые зависимости, импорты и OEP candidates | phase1_release_owned, net_dep_destroy | Собственные элементы/строки очищаются; контейнеры уничтожаются штатными средствами GLib. |
| JSON/GString и GByteArray | phase1_release_owned и локальные деструкторы | Освобождение контейнеров подтверждается cleanup; обнуление всех внутренних capacity не заявляется. |
| events, IR и временные export-файлы | tf_phase1_finish/destroy, tf_atomic_commit/abort | Собственные FILE/FD закрываются. Файлы доказательств на диске сохраняются. |
| Retirement socket | tf_retire_close | Закрывается до возврата removed callback. Observer socket принадлежит другому плагину. |
| Capstone/Z3 и код QEMU | cs_close / штатные библиотечные деструкторы | Все внутренние выделения и allocator caches не перечислены ledger; общий предел задаёт cgroup. |

До удаления `unpacked.json` содержит `resource_inventory` с counters по модулям. После удаления пакет `resources_released` содержит `resource_ledger` с нулём живых учтённых аллокаций. Проверяющий код требует совпадения лимита с контрактом, равенства allocations/releases и согласованности export/release. Счётчик wiped_bytes отражает объём операций обнуления; повторно использованные адреса и realloc могут считаться неоднократно. Счётчики плагина не заменяют независимое наблюдение unmap.

Переполнение памяти/реестра даёт native exit 92. При таком `_exit` отдельные деструкторы не исполняются: процесс и его FD освобождает ОС, дерево очищает supervisor/systemd. Успешный wipe при отказе не заявляется; failed claim блокирует resume.

M4 задаёт 512 МиБ учтённой памяти, 256 МиБ экспорта и 32 МиБ журналов по умолчанию. Общий cgroup остаётся 1 ГиБ со swap 0. RLIMIT_FSIZE ограничивает отдельный файл; supervisor проверяет совокупные размеры каждые 10 мс и перед принятием результата/permit. Это проверяемый порог отказа с возможным превышением между опросами, не точная квота файловой системы. Сохранённые копии export и упаковка portable evidence имеют отдельные пределы; их объём не прибавляется к native export budget.

Привилегированный wrapper готовит rootfs и mounts. Launcher входит в chroot, затем выставляет RLIMIT, NoNewPrivileges, удаляет bounding/ambient/inheritable/permitted/effective capabilities, supplementary groups и задаёт UID/GID 65534. В обеих точках HOLD внешний controller читает реальные status, mountinfo, namespace identities и FD через приватный proc. Runtime mount требует ro,nosuid,nodev; управляющие JSON — 0600, каталог config — 0700. После teardown ownership временной rootfs возвращается вызывающему пользователю для наблюдения и ремонта; байты исходного ELF сохраняются.

Linux-user использует общую таблицу host FD процесса QEMU. `probe_linux_user_fd.py` воспроизводит запись безвредного гостя в переданный host FD. Права файлов, nonce и SO_PEERCRED не создают границу между гостем и native plugin в этой таблице. Для защищённого канала требуется отдельное решение backend: отдельная граница исполнения гостевых syscalls или системная эмуляция. Поэтому protected_control_channel, memory_isolation, hostile_sample_ready и fuzzing_ready остаются false; anti-VM не реализован.
