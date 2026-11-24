"""Diagnose a guest MAPERR by comparing a packed run with its rebuilt image."""
import hashlib
import inspect
import re
import shutil
import signal
import stat
import subprocess

from taintforge_env.log_io import LogReadError, iter_log_lines
from taintforge_env.strace_parser import SYSCALL_RE
from taintforge_env.syscall_result import parse_result

try:
    from .mvp import ct_elf
    from .unpack_process import compare_results, run_process, save
except ImportError:
    from mvp import ct_elf
    from unpack_process import compare_results, run_process, save


TRACE_LIMIT = 8 * 1024**2
PC = re.compile(r'^Trace 0: \S+ \[[\da-fA-F]+/([\da-fA-F]+)/')
MAPERR = re.compile(r'^--- SIGSEGV \{si_signo=SIGSEGV, si_code=(?:1|SEGV_MAPERR), '
                    r'si_addr=(0x[\da-fA-F]+|NULL)\} ---$')
PAGE_ROW = re.compile(r'^([\da-fA-F]+)-([\da-fA-F]+)\s+([\da-fA-F]+)\s+([r-][w-][x-])$')
PAGE_HEADER = re.compile(r'^start\s+end\s+size\s+prot$')
PROCESS_CALLS = {'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat'}
OBSERVATIONS = ('returncode', 'stdout_sha256', 'stderr_sha256', 'output_files')


def need(value, detail):
    if not value:
        raise ValueError(detail)


def page_end(address):
    return (address + ct_elf.PAGE - 1) & -ct_elf.PAGE


def image_hash(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= ct_elf.MAX_BYTES,
         'Diagnostic input is not a bounded regular ELF file')
    return ct_elf.sha256(path)


def read_rebuilt_elf(path):
    """Use the TLS profile when the installed capture reader supports it."""
    reader = ct_elf.read_elf
    if 'allow_tls' in inspect.signature(reader).parameters:
        return reader(path, allow_tls=True)
    return reader(path)


def check_single_process(result):
    if any(key in result for key in ('payload_role', 'process_exits', 'process_exit_error')):
        need(result.get('payload_role') == 'parent' and 'process_exit_error' not in result
             and set(result.get('process_exits') or {}) == {'parent'},
             'Mapping attribution requires a complete exit record for a single guest process')


def events(path):
    result, pids = [], set()
    for raw in iter_log_lines(path):
        line = raw.strip()
        pc = PC.match(line)
        if pc:
            result.append(('pc', int(pc[1], 16)))
            continue
        fault = MAPERR.fullmatch(line)
        if fault:
            result.append(('fault', 0 if fault[1] == 'NULL' else int(fault[1], 16)))
            continue
        call = SYSCALL_RE.fullmatch(line)
        if call and call['pid']:
            need(call['name'] not in PROCESS_CALLS, 'Replay changed process or executable')
            pids.add(call['pid'])
            result.append(('call', (call['name'], call['args'], call['result'])))
            continue
        exit_call = re.fullmatch(r'(\d+) (exit|exit_group)\((-?\d+)\)', line)
        if exit_call:
            pids.add(exit_call[1])
            result.append(('exit', int(exit_call[3])))
            continue
        if line.startswith('--- SIG'):
            raise ValueError('Guest signal was not an unhandled SEGV_MAPERR on this trace')
        need(not line, 'Unsupported or incomplete QEMU event')
    need(len(pids) <= 1, 'More than one guest PID in trace')
    return result


def mapping_history(history, boundary, fault):
    """Keep an allocation only across operations that preserve its lifetime."""
    candidate = None
    for index, (kind, item) in enumerate(history):
        if kind != 'call':
            continue
        name, arguments, returned = item
        if name not in {'mmap2', 'mmap', 'munmap', 'mprotect', 'pkey_mprotect', 'mremap',
                        'brk', 'shmat', 'shmdt', 'ipc', 'remap_file_pages'}:
            continue
        value, error = parse_result(returned)
        if error:
            continue
        if value is None or value < 0:
            candidate = None
            continue
        args = [s.strip() for s in arguments.split(',')]
        if name in ('mmap2', 'mmap') and len(args) == 6:
            # The successful return gives the actual allocation base, including
            # for an unhonoured hint. Keep the unrounded requested length.
            start, length = value, int(args[1], 0)
        elif name in ('munmap', 'mprotect', 'pkey_mprotect') and len(args) >= 2:
            start, length = int(args[0], 0), int(args[1], 0)
        else:
            candidate = None
            continue
        need(start % ct_elf.PAGE == 0 and length >= 0 and start + length <= 2**32,
             'Unrecognized address interval in mapping history')
        stop = page_end(start + length)
        if candidate:
            if start < page_end(candidate['end']) and candidate['start'] < stop:
                candidate = None
        if (index < boundary and name in ('mmap2', 'mmap') and start <= fault < start + length
                and set(args[2].split('|')) == {'PROT_READ', 'PROT_WRITE'}
                and set(args[3].split('|')) in (
                    {'MAP_PRIVATE', 'MAP_ANONYMOUS'}, {'MAP_PRIVATE', 'MAP_ANONYMOUS', 'MAP_FIXED'},
                    {'MAP_PRIVATE', 'MAP_ANONYMOUS', 'MAP_FIXED_NOREPLACE'})
                and args[4] == '-1' and int(args[5], 0) == 0):
            candidate = dict(start=start, end=start + length, length=length, permissions='rw-',
                             allocation=dict(syscall=name, arguments=arguments, returned=returned,
                                             trace_event=index + 1))
    need(candidate, 'No surviving pre-entry private anonymous RW allocation covers the fault')
    return candidate


def correlate(packed, rebuilt, entry):
    need(rebuilt and rebuilt[0] == ('pc', entry) and rebuilt[-1][0] == 'fault' and
         sum(k == 'fault' for k, _ in rebuilt) == 1, 'Expected one terminal guest SEGV_MAPERR')
    fault = rebuilt[-1][1]
    prefix = rebuilt[:-1]
    need(prefix and prefix[-1][0] == 'pc', 'No final guest instruction before the fault')
    need(('pc', entry) in packed and all(k != 'fault' for k, _ in packed),
         'Packed replay did not reach the captured entry cleanly')
    first = packed.index(('pc', entry))
    end = first + len(prefix)
    need(len(packed) > end and packed[first:end] == prefix,
         'Observed PCs or system calls already diverged before the fault')
    mapping = mapping_history(packed[:end], first, fault)
    site = prefix[-1]
    return dict(fault_address=fault, last_traced_pc=site[1], site_occurrence=prefix.count(site),
                aligned_instruction_events=sum(k == 'pc' for k, _ in prefix),
                prior_payload_syscalls=sum(k == 'call' for k, _ in prefix), **mapping)


def payload_calls(trace, entry, exit_code):
    need(trace and trace[-1][0] == 'exit' and (trace[-1][1] & 255) == exit_code
         and ('pc', entry) in trace, 'No complete post-entry syscall trace')
    return [event for event in trace[trace.index(('pc', entry)):] if event[0] != 'pc']


def maps_at_site(path, entry, site, occurrence):
    """Read the most recent full guest page table at the aligned instruction."""
    pages, in_table, entered = [], False, False
    for raw in iter_log_lines(path):
        line = raw.strip()
        if PAGE_HEADER.fullmatch(line):
            pages, in_table = [], True
            continue
        if in_table:
            row = PAGE_ROW.fullmatch(line)
            if row:
                lo, hi, size = (int(row[i], 16) for i in (1, 2, 3))
                need(0 <= lo < hi <= 2**32 and hi - lo == size and
                     lo % ct_elf.PAGE == hi % ct_elf.PAGE == 0 and (not pages or pages[-1][1] <= lo),
                     'Invalid guest page table')
                pages.append((lo, hi, row[4]))
                continue
            need(not re.match(r'^[\da-fA-F]+-', line), 'Incomplete guest page-table row')
            in_table = False
        hit = PC.match(line)
        if hit:
            address = int(hit[1], 16)
            entered |= address == entry
            if entered and address == site:
                occurrence -= 1
                if not occurrence:
                    need(pages, 'No guest page table at the comparison site')
                    return pages
    raise ValueError('Page replay did not reach the matching instruction occurrence')


def write_trial(image, target, start, length):
    """Add a zero-file-size RW load to the metadata page made by ct_elf.rebuild."""
    raw = bytearray(image['data'])
    header = list(ct_elf.ELF_HEADER.unpack_from(raw))
    offset, count = header[5], header[10]
    ph = ct_elf.PROGRAM_HEADER
    end = offset + count * ph.size
    rows = list(ph.iter_unpack(raw[offset:end]))
    metadata = [p for p in rows if p[0] == ct_elf.PT_LOAD and p[1] == 0 and p[6] == 4]
    need(len(metadata) == 1 and len(raw) >= end + ph.size and end + ph.size <= metadata[0][4]
         and raw[end:end + ph.size] == bytes(ph.size) and rows[0][0] == ct_elf.PT_PHDR and
         rows[-1][0] == ct_elf.PT_GNU_STACK, 'No spare program-header slot in rebuilt metadata')
    need(0 < length <= ct_elf.MAX_BYTES and start >= ct_elf.PAGE and all(
        p[0] != ct_elf.PT_LOAD or page_end(p[2] + p[5]) <= start or
        page_end(start + length) <= p[2] // ct_elf.PAGE * ct_elf.PAGE for p in rows),
        'Trial mapping is too large or overlaps a rebuilt load')
    pos = next(i for i, p in enumerate(rows) if
               (p[0] == ct_elf.PT_LOAD and p[2] > start) or p[0] in (ct_elf.PT_TLS, ct_elf.PT_GNU_STACK))
    rows.insert(pos, (ct_elf.PT_LOAD, 0, start, start, 0, length, 6, ct_elf.PAGE))
    header[10] = len(rows)
    size = len(rows) * ph.size
    rows[0] = (*rows[0][:4], size, size, *rows[0][6:])
    ct_elf.ELF_HEADER.pack_into(raw, 0, *header)
    for i, row in enumerate(rows):
        ph.pack_into(raw, offset + i * ph.size, *row)
    with target.open('xb') as stream:
        stream.write(raw)
    target.chmod(0o700)
    return hashlib.sha256(raw).hexdigest()


def diagnose(qemu, packed, rebuilt, case, directory, executions, *, expected_hashes, timeout,
             rss_limit_mib, environment, follow_fork=False, replay_process=run_process):
    directory.mkdir()
    report = dict(schema_version=1, case_id=case['id'], status='INCONCLUSIVE')
    budgets = dict(timeout=timeout, rss_limit_mib=rss_limit_mib, environment=environment)
    identities = {}

    def replay(binary, label, options, limit):
        # Identical argv[0] and exec filename, including its length on the
        # initial guest stack. Each case still has a fresh working directory.
        command = [str(qemu), *options, '-0', 'target.elf', '../image.elf', *case['argv']]
        result = replay_process(command, case, binary.parent / label, file_limit=limit, **budgets)
        check_single_process(result)
        return result

    def trace(label, binary, reference, options):
        path = directory / (label + '.log')
        result = replay(binary, label, [*options, '-D', str(path)], TRACE_LIMIT)
        need(all(result[k] == reference[k] for k in OBSERVATIONS) and not any(
             result[k] for k in ('timed_out', 'rss_limit_hit', 'output_limit_exceeded')),
             'Trace replay did not reproduce the ordinary execution')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size < TRACE_LIMIT, 'Missing or truncated trace')
        return path

    try:
        need(not follow_fork, 'Mapping attribution requires a single guest process')
        for result in (*executions['packed'], *executions['rebuilt']):
            check_single_process(result)
        need(compare_results(executions['packed']), 'Packed reference runs disagree')
        p, r = executions['packed'][0], executions['rebuilt'][-1]
        need(r['returncode'] == -signal.SIGSEGV and not any(r[k] for k in
             ('timed_out', 'rss_limit_hit', 'output_limit_exceeded')), 'No ordinary rebuilt SIGSEGV')
        staged = []
        for role, source in (('packed', packed), ('rebuilt', rebuilt)):
            target = directory / role[0] / 'image.elf'
            target.parent.mkdir()
            need(image_hash(source) == expected_hashes[role], 'Input differs from the captured pair')
            shutil.copyfile(source, target)
            target.chmod(0o500)
            need(image_hash(target) == expected_hashes[role], 'Input changed while staging the pair')
            identities[source] = identities[target] = expected_hashes[role]
            staged.append(target)
        packed, rebuilt = staged
        image = read_rebuilt_elf(rebuilt)
        entry = image['entry']
        report.update(entry=entry, packed_sha256=expected_hashes['packed'], rebuilt_sha256=image['sha256'])
        scope = ','.join(f"0x{p['address']:x}+0x{p['memsz']:x}" for p in image['loads']
                         if p['flags'] & 1 and p['memsz'])
        opts = ['-one-insn-per-tb', '-d', 'exec,nochain,strace']
        # Log every rebuilt PC. Skipped packed code cannot supply a rebuilt PC
        # outside the selected executable ranges. Counts refer to observed PCs.
        failed = events(trace('rebuilt-events', rebuilt, r, opts))
        if failed and failed[-1][0] == 'fault':
            report['fault_address'] = failed[-1][1]
        healthy = events(trace('packed-events', packed, p, [*opts, '-dfilter', scope]))
        reference_calls = payload_calls(healthy, entry, p['returncode'])
        prediction = correlate(healthy, failed, entry)
        site, nth = prediction['last_traced_pc'], prediction['site_occurrence']
        scope = ','.join(f'0x{addr:x}+1' for addr in sorted({entry, site}))
        opts = ['-one-insn-per-tb', '-dfilter', scope, '-d', 'page,exec,nochain']
        start, end = prediction['start'], page_end(prediction['end'])
        for name, binary, ref in (('packed', packed, p), ('rebuilt', rebuilt, r)):
            table = maps_at_site(trace(name + '-maps', binary, ref, opts), entry, site, nth)
            overlap = [(lo, hi, prot) for lo, hi, prot in table if lo < end and start < hi]
            if name == 'packed':
                need(any(lo <= start and end <= hi and prot == 'rw-' for lo, hi, prot in overlap),
                     'Packed page table does not confirm the complete RW interval')
            else:
                need(not overlap, 'Rebuilt page table already maps part of the interval')
        report.update(status='MAPPING_CANDIDATE', mapping=prediction)
        trial = directory / 't' / 'image.elf'
        trial.parent.mkdir()
        report['trial_elf'] = str(trial.relative_to(directory))
        report['trial_sha256'] = write_trial(image, trial, start, prediction['length'])
        identities[trial] = report['trial_sha256']
        trial_runs = [replay(trial, f'trial-{i}', [], 1024**2) for i in range(2)]
        matched = compare_results([*executions['packed'], *trial_runs])
        report['trial'] = dict(repetitions=2, matches_packed_observations=matched)
        if matched:
            opts = ['-one-insn-per-tb', '-dfilter', f'0x{entry:x}+1', '-d', 'exec,nochain,strace']
            final_trace = events(trace('trial-events', trial, p, opts))
            calls = payload_calls(final_trace, entry, p['returncode'])
            report['trial'].update(post_entry_syscalls=len(calls), matches_packed_syscalls=calls == reference_calls)
            if calls == reference_calls:
                report['status'] = 'MAPPING_RESTORES_CASE'
            else:
                report['detail'] = 'Post-entry system calls differed on the diagnostic copy'
        else:
            report['detail'] = 'Zero-filled trial did not reproduce the packed workload'
    except (ValueError, OSError, LogReadError, subprocess.SubprocessError) as error:
        report['detail'] = str(error)
    try:
        need(all(image_hash(path) == digest for path, digest in identities.items()),
             'Input or trial image changed during diagnosis')
    except (ValueError, OSError) as error:
        report.update(status='INCONCLUSIVE', detail=str(error))
    save(directory / 'report.json', report)
    return report
