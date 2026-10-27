"""Rebuild a selected QEMU observer with live IA-32 condition-code reads.

The existing observer API patch is preserved.  Only the two named x86 functions
below are changed, and an unknown function layout is rejected before any write.
The configured source tree, compiler and linked dependencies remain trusted.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

try:
    from .oep_capture import configured_source_binding
except ImportError:
    from oep_capture import configured_source_binding


API_NAMES = tuple('qemu_plugin_taintforge_user_' + name + '_v1'
                  for name in ('vmas', 'entry', 'brk'))
FLAGS_PATH = 'target/i386/gdbstub.c'
SELECTOR_PATH = 'target/i386/tcg/translate.c'
FLAGS_BEFORE = 'return gdb_get_reg32(mem_buf, env->eflags);'
FLAGS_AFTER = 'return gdb_get_reg32(mem_buf, cpu_compute_eflags(env));'
SELECTOR_BLOCK = '''    /* R_REGS observers must see the current lazy condition-code selector.
     * Save before the rollback boundary so a failed decode retains this store.
     */
    if (dcbase->plugin_enabled) {
        gen_update_cc_op(dc);
    }
'''
SELECTOR_ANCHOR = '''    dc->prev_insn_start = dc->base.insn_start;
    dc->prev_insn_end = tcg_last_op();'''


def _require(value, message):
    if not value:
        raise ValueError(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _read(path, limit=4 * 1024 * 1024):
    path = Path(path)
    _require(path.is_file() and not path.is_symlink(), 'Runtime source missing or symlink: ' + str(path))
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    _require(len(data) <= limit, 'Runtime input exceeds bound: ' + str(path))
    return data


def _tokens(text):
    """C tokens with original offsets; comments cannot impersonate code."""
    pattern = re.compile(r'''\s+|/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_]\w*|\d[\w.]*|->|==|!=|<=|>=|&&|\|\||<<|>>|\+\+|--|.''')
    result = []
    cursor = 0
    for match in pattern.finditer(text):
        _require(match.start() == cursor, 'Unsupported C source token')
        value = match.group()
        cursor = match.end()
        _require(value != '/' or text[match.start():match.start() + 2] != '/*',
                 'Unterminated C source comment')
        if value.isspace() or value.startswith(('/*', '//')):
            continue
        result.append((value, match.start(), match.end()))
    _require(cursor == len(text), 'Unsupported C source framing')
    return result


def _function(text, name):
    # Restrict replacements to a definition at file scope. Braces in comments
    # and string literals are not delimiters and cannot truncate a function.
    pattern = r'(?m)^(?:static\s+)?(?:int|void)\s+' + re.escape(name) + r'\([^;{}]*\)\s*\{'
    tokens = _tokens(text)
    positions = {token[1]: index for index, token in enumerate(tokens)}
    matches = [match for match in re.finditer(pattern, text) if match.start() in positions]
    _require(len(matches) == 1, 'Unsupported QEMU function definition: ' + name)
    start = matches[0].start()
    index = positions.get(matches[0].end() - 1)
    _require(index is not None, 'Unsupported QEMU function opening: ' + name)
    depth = 0
    for token, _begin, end in tokens[index:]:
        depth += (token == '{') - (token == '}')
        if depth == 0:
            return start, end, text[start:end]
    raise ValueError('Unterminated QEMU function: ' + name)


def _replace_function(text, name, transform):
    start, end, body = _function(text, name)
    return text[:start] + transform(body) + text[end:]


def _matched_close(tokens, start, opening='(', closing=')'):
    depth = 0
    for index in range(start, len(tokens)):
        value = tokens[index][0]
        depth += (value == opening) - (value == closing)
        if depth == 0:
            return index
    raise ValueError('Unbalanced x86 flag-register expression')


def _flags_arm(body):
    """Locate only the unique flags case, stopping at its enclosing switch."""
    tokens = _tokens(body)
    matches = [index for index in range(len(tokens) - 2)
               if [token[0] for token in tokens[index:index + 3]] == ['case', 'IDX_FLAGS_REG', ':']]
    _require(len(matches) == 1, 'Unsupported x86 flag-register case')
    start = matches[0] + 3
    level = sum((token[0] == '{') - (token[0] == '}') for token in tokens[:start])
    current = level
    for end in range(start, len(tokens)):
        value = tokens[end][0]
        if current == level and value in ('case', 'default', '}'):
            return tokens[start:end], tokens[start][1] if end > start else tokens[end][1], tokens[end][1]
        current += (value == '{') - (value == '}')
    raise ValueError('Unterminated x86 flag-register case')


_WIDE_INTEGER_CASTS = {
    ('uint32_t',), ('uint64_t',), ('target_ulong',), ('unsigned',), ('unsigned', 'int'),
    ('unsigned', 'long'), ('unsigned', 'long', 'int'), ('unsigned', 'long', 'long'),
    ('unsigned', 'long', 'long', 'int'),
}


def _plain_expression(tokens, *, casts=True):
    """Remove redundant grouping and only known non-narrowing integer casts."""
    while tokens and tokens[0][0] == '(':
        close = _matched_close(tokens, 0)
        if close == len(tokens) - 1:
            tokens = tokens[1:-1]
        elif casts and tuple(token[0] for token in tokens[1:close]) in _WIDE_INTEGER_CASTS:
            tokens = tokens[close + 1:]
        else:
            break
    return tokens


def _expression_kind(tokens):
    tokens = _plain_expression(tokens)
    values = [token[0] for token in tokens]
    if values == ['env', '->', 'eflags']:
        return 'raw'
    if (len(tokens) >= 4 and values[:2] == ['cpu_compute_eflags', '(']
            and _matched_close(tokens, 1) == len(tokens) - 1
            and [token[0] for token in _plain_expression(tokens[2:-1], casts=False)] == ['env']):
        return 'live'
    return None


def _flags_buffer(body):
    # Bind both guarded returns to the unique output parameter.
    header = _tokens(body[:body.find('{')])
    buffers = [header[index + 2][0] for index in range(len(header) - 2)
               if [token[0] for token in header[index:index + 2]] == ['GByteArray', '*']]
    _require(len(buffers) == 1 and re.fullmatch(r'[A-Za-z_]\w*', buffers[0]),
             'Unsupported x86 flag-register output buffer')
    return buffers


def _flags_return(arm, buffers):
    _require(len(arm) >= 8 and [token[0] for token in arm[:3]] == ['return', 'gdb_get_reg32', '(']
             and arm[-1][0] == ';' and _matched_close(arm, 2) == len(arm) - 2,
             'Unsupported x86 flag-register return')
    arguments = arm[3:-2]
    depth = 0
    commas = []
    for index, token in enumerate(arguments):
        value = token[0]
        if value == ',' and depth == 0:
            commas.append(index)
        depth += (value == '(') - (value == ')')
    _require(len(commas) == 1, 'Unsupported x86 flag-register arguments')
    comma = commas[0]
    _require([token[0] for token in _plain_expression(arguments[:comma], casts=False)] == buffers,
             'Unsupported x86 flag-register output buffer')
    return arguments[comma + 1:]


def _flags(body, reverse):
    arm, _begin, _end = _flags_arm(body)
    while arm and arm[0][0] == '{' and _matched_close(arm, 0, '{', '}') == len(arm) - 1:
        arm = arm[1:-1]
    buffers = _flags_buffer(body)
    if arm and arm[0][0] == 'if':
        # Some QEMU trees switch between lazy TCG flags and fully stored
        # flags. Preserve that representation guard, including on reversal.
        guard = ['if', '(', 'cpu', '->', 'eflags_in_tcg', ')', '{']
        _require([token[0] for token in arm[:len(guard)]] == guard,
                 'Unsupported x86 flag-register guard')
        close = _matched_close(arm, len(guard) - 1, '{', '}')
        live = _flags_return(arm[len(guard):close], buffers)
        raw = _flags_return(arm[close + 1:], buffers)
        _require(_expression_kind(live) == 'live' and _expression_kind(raw) == 'raw',
                 'Unsupported x86 flag-register guarded values')
        return body
    # A local materialization is already correct. Writing computed flags back
    # to env->eflags is unsafe: lazy CC/DF bits could then become sticky.
    materialized = None
    semicolons = [index for index, token in enumerate(arm) if token[0] == ';']
    if len(semicolons) == 2:
        assignment = arm[:semicolons[0]]
        values = [token[0] for token in assignment]
        equals = [index for index, value in enumerate(values) if value == '=']
        _require(len(equals) == 1, 'Unsupported x86 flag-register materialization')
        equals = equals[0]
        declaration = values[:equals]
        if declaration and declaration[0] == 'const':
            declaration = declaration[1:]
        _require(len(declaration) >= 2 and tuple(declaration[:-1]) in _WIDE_INTEGER_CASTS
                 and re.fullmatch(r'[A-Za-z_]\w*', declaration[-1])
                 and declaration[-1] != 'env' and _expression_kind(assignment[equals + 1:]) == 'live',
                 'Unsupported x86 flag-register materialization')
        materialized = declaration[-1]
        arm = arm[semicolons[0] + 1:]
    expression = _flags_return(arm, buffers)
    kind = _expression_kind(expression)
    if materialized is not None:
        _require([token[0] for token in _plain_expression(expression)] == [materialized],
                 'Unsupported x86 flag-register materialized return')
        return body
    _require(kind is not None, 'Unsupported x86 flag-register value expression')
    if kind == ('raw' if reverse else 'live'):
        return body
    replacement = 'env->eflags' if reverse else 'cpu_compute_eflags(env)'
    return body[:expression[0][1]] + replacement + body[expression[-1][2]:]


def _selector(body, reverse):
    tokens = _tokens(body)
    values = [token[0] for token in tokens]

    def positions(fragment):
        pattern = [token[0] for token in _tokens(fragment)]
        return [index for index in range(len(values) - len(pattern) + 1)
                if values[index:index + len(pattern)] == pattern]

    anchors = positions(SELECTOR_ANCHOR)
    _require(len(anchors) == 1
             and len(positions('tcg_gen_insn_start(pc_arg, dc->cc_op);')
                     + positions('tcg_gen_insn_start(pc_arg, dc->cc_op, 0);')) == 1
             and len(positions('DisasContext *dc = container_of(dcbase, DisasContext, base);')) == 1,
             'Unsupported x86 instruction-start layout')
    anchor = anchors[0]
    _require(sum((value == '{') - (value == '}') for value in values[:anchor]) == 1,
             'Unsupported x86 instruction-start layout')
    sync = 'if (dcbase->plugin_enabled) { gen_update_cc_op(dc); }'
    blocks = positions(sync)
    _require(values.count('gen_update_cc_op') == len(blocks) and len(blocks) <= 1,
             'Unknown existing x86 condition-code observer change')
    statement = blocks[0] if blocks else anchor
    # Brace depth alone misses an enclosing unbraced `if`, `else`, or loop.
    _require(statement > 0 and values[statement - 1] in (';', '{', '}'),
             'Unsupported x86 instruction-start statement boundary')
    if blocks:
        _require(blocks[0] + len(_tokens(sync)) == anchor,
                 'Condition-code save must precede the decode rollback boundary')
        # Only our exact annotated insertion is removable. A pre-existing
        # equivalent synchronization belongs to the selected QEMU tree.
        owned = body.find(SELECTOR_BLOCK)
        if (reverse and owned >= 0
                and owned + len(SELECTOR_BLOCK.rstrip()) == tokens[anchor - 1][2]):
            return body[:owned] + body[owned + len(SELECTOR_BLOCK):]
    elif not reverse:
        start = tokens[anchor][1]
        line = body.rfind('\n', 0, start) + 1
        # Preserve any original indentation (including compact formatting).
        if body[line:start].strip():
            return body[:start] + SELECTOR_BLOCK + body[start:]
        return body[:line] + SELECTOR_BLOCK + body[line:]
    return body


def source_diagnostics(source):
    """Bounded failure evidence; no build or mutation is performed here."""
    source = Path(source).resolve()
    result = {'source_directory': str(source), 'captured_at': 'runtime_preparation_failure',
              'function_limit_characters': 16384, 'case_limit_characters': 8192, 'files': {}}
    for name, function in ((FLAGS_PATH, 'x86_cpu_gdb_read_register'),
                           (SELECTOR_PATH, 'i386_tr_insn_start')):
        item = {}
        result['files'][name] = item
        try:
            data = _read(source / name)
            item.update(sha256=_digest(data), bytes=len(data))
            text = data.decode('utf-8')
            _start, _end, body = _function(text, function)
            item.update(function_name=function, function_text=body[:16384],
                        function_truncated=len(body) > 16384)
            if name == FLAGS_PATH:
                _arm, start, end = _flags_arm(body)
                case = body[start:end]
                item.update(flags_case_text=case[:8192], flags_case_truncated=len(case) > 8192)
        except (OSError, ValueError, UnicodeError) as error:
            item['inspection_error'] = type(error).__name__ + ': ' + str(error)
    return result


def apply_flags_fix(source, output=None, *, reverse=False):
    """Apply/reverse only known flag-read changes, atomically validating first."""
    source = Path(source).resolve()
    original = {name: _read(source / name) for name in (FLAGS_PATH, SELECTOR_PATH)}
    updated = {
        FLAGS_PATH: _replace_function(original[FLAGS_PATH].decode('utf-8'),
                                     'x86_cpu_gdb_read_register', lambda body: _flags(body, reverse)).encode(),
        SELECTOR_PATH: _replace_function(original[SELECTOR_PATH].decode('utf-8'),
                                        'i386_tr_insn_start', lambda body: _selector(body, reverse)).encode(),
    }
    changed = [name for name in original if original[name] != updated[name]]
    patch = ''.join(''.join(difflib.unified_diff(
        original[name].decode().splitlines(keepends=True), updated[name].decode().splitlines(keepends=True),
        fromfile='a/' + name, tofile='b/' + name)) for name in changed)
    receipt = {'schema_version': 1, 'source_directory': str(source),
               'state': ('REVERSED' if reverse else 'APPLIED') if changed else 'ALREADY_IN_REQUESTED_STATE',
               'reverse_requested': reverse, 'changed_files': changed,
               'source_before_sha256': {name: _digest(data) for name, data in original.items()},
               'source_after_sha256': {name: _digest(data) for name, data in updated.items()},
               'applied_patch_sha256': _digest(patch.encode()),
               'observer_API_patch_modified': False}
    # All layouts have been checked before modifying either source file.
    for name in changed:
        _require(_read(source / name) == original[name], 'QEMU source changed during patch preparation')
    for name in changed:
        (source / name).write_bytes(updated[name])
    if output is not None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / 'flags.patch').write_text(patch)
        for name, data in original.items():
            for prefix, content in (('before', data), ('after', updated[name])):
                target = output / prefix / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        (output / 'flags-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def prepare_runtime(source, build, output):
    """Patch and rebuild an already configured observer for the selected source."""
    source, build, output = (Path(path).resolve() for path in (source, build, output))
    _require(source.is_dir() and (source / 'VERSION').is_file(), 'QEMU source directory missing')
    _require((build / 'build.ninja').is_file(),
             'QEMU observer build must already be configured with i386-linux-user and plugins')
    binding = configured_source_binding(source, build)
    compilation = json.loads(_read(build / 'compile_commands.json', 32 * 1024 * 1024))
    selected = {(Path(row['directory']) / row['file']).resolve() for row in compilation}
    flags_sources = {source / name for name in (FLAGS_PATH, SELECTOR_PATH)}
    _require(flags_sources <= selected, 'QEMU build does not compile the selected flag-observer source files')
    binding['selected_source_files'] = sorted(set(binding['selected_source_files']) | set(map(str, flags_sources)))
    sdk_paths = [source / 'include' / name / 'qemu-plugin.h' for name in ('plugins', 'qemu')]
    sdk_paths = [path for path in sdk_paths if path.is_file()]
    _require(len(sdk_paths) == 1, 'Matching QEMU plugin SDK must be unambiguous')
    sdk = sdk_paths[0]
    _require(not sdk.is_symlink(), 'Matching QEMU plugin SDK is a symlink')
    header = _read(sdk)
    _require(all(name.encode() in header for name in API_NAMES),
             'Existing QEMU observer API declarations missing; apply the observer API patch first')
    _require(not output.exists() or not any(output.iterdir()), 'Runtime output directory is not empty')
    output.mkdir(parents=True, exist_ok=True)
    patch = apply_flags_fix(source, output)
    ninja = os.environ.get('TF_QEMU_NINJA') or shutil.which('ninja')
    _require(ninja is not None, 'Ninja executable missing; set TF_QEMU_NINJA')
    command = [str(ninja), '-C', str(build), '-j', str(min(8, os.cpu_count() or 1)), 'qemu-i386']
    with (output / 'build.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    _require(result.returncode == 0, 'QEMU rebuild failed; inspect ' + str(output / 'build.log'))
    qemu = build / 'qemu-i386'
    _require(qemu.is_file() and not qemu.is_symlink() and os.access(qemu, os.X_OK), 'Built qemu-i386 missing')
    symbols = subprocess.run(['nm', '-D', '--defined-only', str(qemu)], capture_output=True,
                             text=True, timeout=30, check=True).stdout
    (output / 'nm-dynamic.txt').write_text(symbols)
    exported = {line.split()[-1].split('@')[0] for line in symbols.splitlines() if line.split()}
    _require(set(API_NAMES) <= exported, 'Built QEMU does not export all observer APIs')
    version = subprocess.run([str(qemu), '--version'], capture_output=True,
                             text=True, timeout=30, check=True).stdout
    receipt = {'schema_version': 1, 'source_directory': str(source), 'build_directory': str(build),
               'qemu_path': str(qemu), 'qemu_sha256': _digest(qemu.read_bytes()),
               'qemu_bytes': qemu.stat().st_size, 'version': version,
               'SDK_path': str(sdk.parent), 'SDK_sha256': _digest(header),
               'commands': [command], 'build_exit': result.returncode,
               'flags_patch': patch, 'configured_source_binding': binding,
               'required_exported_APIs': list(API_NAMES),
               'source_built': True, 'configured_build_and_toolchain_trusted': True,
               'source_signature_or_runtime_correctness_proved': False,
               'historical_reference_observer_patch_modified': False}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return qemu, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu-source', type=Path, required=True,
                        help='Existing QEMU source tree with observer APIs applied')
    parser.add_argument('--qemu-build', type=Path, required=True,
                        help='Existing configured i386-linux-user observer build directory')
    parser.add_argument('--output', type=Path, required=True,
                        help='New or empty runtime evidence directory')
    args = parser.parse_args(argv)
    output = args.output.resolve()
    # Do not place a failure receipt inside a pre-existing, occupied result.
    writable_output = not output.exists() or output.is_dir() and not any(output.iterdir())
    try:
        qemu, receipt = prepare_runtime(args.qemu_source, args.qemu_build, output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        if writable_output:
            try:
                output.mkdir(parents=True, exist_ok=True)
                failure = {'schema_version': 1, 'status': 'RUNTIME_PREPARATION_FAILED',
                           'source_directory': str(args.qemu_source.resolve()),
                           'build_directory': str(args.qemu_build.resolve()),
                           'error_type': type(error).__name__, 'error': str(error),
                           'observer_runtime_confirmed': False,
                           'source_diagnostics': source_diagnostics(args.qemu_source)}
                (output / 'failure.json').write_text(json.dumps(failure, indent=2) + '\n')
                print('Failure receipt: ' + str(output / 'failure.json'), file=sys.stderr)
            except OSError:
                pass
        return 1
    print('QEMU: ' + str(qemu))
    print('SDK: ' + receipt['SDK_path'])
    print('SHA256: ' + receipt['qemu_sha256'])
    print('Receipt: ' + str(output / 'receipt.json'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
