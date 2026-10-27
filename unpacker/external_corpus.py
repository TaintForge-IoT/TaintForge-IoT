#!/usr/bin/env python3
"""Build pinned upstream i386 CLIs and pack them with an authenticated UPX.

These are real upstream programs, not the project's controlled decoder fixtures.
The resulting manifest supplies a source-built reference only to later checks;
it is never an unpacking hint or an initial state for the proof machine.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request

try:
    from .unpack_process import validate_cases
except ImportError:
    from unpack_process import validate_cases


MAX_DOWNLOAD = 16 * 1024**2
MAX_TAR = 64 * 1024**2
MAX_MEMBER = 8 * 1024**2
MAX_MEMBERS = 10000
BUILD_FLAGS = ('-m32', '-O2', '-static', '-no-pie', '-Wl,--build-id=none')


class CorpusError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CorpusError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    sha256: str
    root: str
    compression: str
    sha512: str | None = None


XXHASH = Source('xxHash-0.8.3.tar.gz',
    'https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz',
    'aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80',
    'xxHash-0.8.3', 'gz')
BZIP2 = Source('bzip2-1.0.8.tar.gz',
    'https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz',
    'ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269',
    'bzip2-1.0.8', 'gz',
    '083f5e675d73f3233c7930ebe20425a533feedeaaa9d8cc86831312a6581cefbe6ed0d08d2fa89be81082f2a5abdabca8b3c080bf97218a1bd59dc118a30b9f3')
UPX = Source('upx-5.2.1-amd64_linux.tar.xz',
    'https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz',
    '402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657',
    'upx-5.2.1-amd64_linux', 'xz')
SOURCES = (XXHASH, BZIP2, UPX)


def _regular(path, maximum=MAX_DOWNLOAD):
    p = Path(path)
    require(not p.is_symlink() and p.is_file() and
            stat.S_ISREG(p.stat().st_mode) and 0 < p.stat().st_size <= maximum,
            'Missing, symlink or oversized regular file: ' + str(p))
    return p


def _verify(path, source):
    path = _regular(path)
    require(digest(path) == source.sha256, 'Pinned archive SHA256 differs: ' + source.name)
    if source.sha512:
        with path.open('rb') as stream:
            require(hashlib.file_digest(stream, 'sha512').hexdigest() == source.sha512,
                    'Upstream archive SHA512 differs: ' + source.name)


def fetch(source, cache):
    """Only the fixed source table is downloadable; cached bytes are rechecked."""
    require(source in SOURCES, 'Unknown upstream source')
    cache = Path(cache).absolute()
    require(not cache.is_symlink(), 'Download cache cannot be a symlink')
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / source.name
    if target.exists() or target.is_symlink():
        _verify(target, source)
        return target
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.download-', dir=cache, delete=False) as stream:
            temporary = Path(stream.name)
            request = urllib.request.Request(source.url,
                headers={'User-Agent': 'TaintForge-IoT-external-corpus/1'})
            with urllib.request.urlopen(request, timeout=90) as response:
                require(response.geturl().startswith('https://'), 'Insecure source redirect')
                size = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= MAX_DOWNLOAD, 'Source download byte budget exceeded')
                    stream.write(chunk)
            stream.flush(); os.fsync(stream.fileno())
        _verify(temporary, source)
        # Preserve any unexpected concurrent replacement rather than overwrite it.
        try:
            os.link(temporary, target)
        except FileExistsError:
            _verify(target, source)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def extract_archive(archive, destination, *, root, compression,
                    max_tar=MAX_TAR, max_member=MAX_MEMBER, max_members=MAX_MEMBERS):
    """Validate the entire bounded tar inventory before any extraction write."""
    archive, destination = _regular(archive), Path(destination).absolute()
    require(not destination.exists() and not destination.is_symlink(), 'Extraction output exists')
    require(compression in ('gz', 'xz') and type(root) is str and
            root and '/' not in root and root not in ('.', '..'), 'Invalid archive profile')
    decoder = gzip.open if compression == 'gz' else lzma.open
    with decoder(archive, 'rb') as stream:
        raw = stream.read(max_tar + 1)
    require(len(raw) <= max_tar, 'Decoded archive byte budget exceeded')
    inventory, seen, total = [], set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
        for member in source:
            require(len(inventory) < max_members, 'Archive member count budget exceeded')
            name = member.name
            require(type(name) is str and 0 < len(name) <= 1024 and '\\' not in name and
                    '\0' not in name and not name.startswith('/'), 'Unsafe archive path')
            parts = PurePosixPath(name).parts
            require(parts and '..' not in parts and len(parts) <= 32 and
                    parts[0] == root, 'Archive path escapes expected upstream root')
            normalized = '/'.join(parts)
            require(normalized not in seen, 'Duplicate normalized archive path')
            seen.add(normalized)
            require(member.isfile() or member.isdir(), 'Archive links/special files are unsupported')
            require(type(member.size) is int and 0 <= member.size <= max_member and
                    (not member.isdir() or member.size == 0), 'Archive member byte budget exceeded')
            require(not member.mode & 0o7000, 'Privileged archive mode is unsupported')
            total += member.size
            require(total <= max_tar, 'Archive extracted byte budget exceeded')
            inventory.append((member, normalized))
        require(inventory, 'Archive inventory is empty')
        # Detect file-vs-directory collisions in either member order.
        kinds = {name: member.isdir() for member, name in inventory}
        for member, name in inventory:
            for parent in PurePosixPath(name).parents:
                if str(parent) != '.':
                    require(kinds.get(str(parent), True), 'Archive file shadows a parent directory')
        destination.mkdir(parents=True, exist_ok=False)
        for member, name in inventory:
            target = destination.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream, target.open('xb') as output:
                    shutil.copyfileobj(stream, output, length=65536)
                require(target.stat().st_size == member.size, 'Short archive extraction')
                target.chmod(member.mode & 0o777)
    return destination / root


def _tool(value):
    text = os.fspath(value)
    path = shutil.which(text) if '/' not in text else text
    require(path is not None, 'Tool not found: ' + text)
    path = Path(path).resolve(strict=True)
    _regular(path, 512 * 1024**2)
    require(os.access(path, os.X_OK), 'Tool is not executable: ' + str(path))
    return path


def _command(command, cwd, prefix, *, timeout=300):
    command = list(map(str, command)); prefix = Path(prefix)
    started = time.monotonic()
    with prefix.with_suffix('.stdout').open('wb') as out, prefix.with_suffix('.stderr').open('wb') as err:
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, timeout=timeout,
            env={**os.environ, 'LC_ALL':'C', 'TZ':'UTC'})
    record = dict(argv=command, cwd=str(cwd), returncode=result.returncode,
                  wall_seconds=time.monotonic()-started)
    save(prefix.with_suffix('.json'), record)
    require(result.returncode == 0, 'Upstream tool failed; inspect ' + str(prefix.with_suffix('.stderr')))
    return record


def input_cases(program):
    require(program in ('xxhsum','bzip2'), 'Unknown external program')
    inputs = [b'', b'a', b'abc', b'\0', b'\xff', b'hello\nworld\n',
              bytes(range(256)), b'\0\xff\x80\x01'*16,
              *(bytes((i*17+3)&255 for i in range(n))
                for n in (3,4,5,15,16,17,63,64,65,4095,4096,4097))]
    require(len(inputs) == 20 and len(set(inputs)) == 20, 'External input inventory differs')
    cases = [dict(id=f'input-{i:02d}', argv=['-'] if program == 'xxhsum' else ['-c'],
                  stdin_base64=base64.b64encode(data).decode(), files={}, output_files=[])
             for i,data in enumerate(inputs)]
    return validate_cases(cases)


def elf_profile(path):
    """Read format facts without silently removing unsupported TLS headers."""
    data = _regular(path,16*1024**2).read_bytes()
    require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01', 'Reference is not ELF32 little endian')
    fields = struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    require(fields[1:4] == (2,3,1) and fields[8:10] == (52,32), 'Reference is not static-profile i386 ET_EXEC')
    phoff,count=fields[5],fields[10]
    require(0 < count <= 256 and phoff >= 52 and phoff+32*count <= len(data), 'Reference program-header extent')
    types=[struct.unpack_from('<I',data,phoff+32*i)[0] for i in range(count)]
    require(2 not in types and 3 not in types, 'Reference unexpectedly requires dynamic linking')
    return dict(ELF_class=32, little_endian=True, machine=3, type=2, entry=fields[4],
                program_header_types=types, PT_TLS_present=7 in types,
                supported_without_TLS_model=7 not in types,
                TLS_headers_removed=False)


def build_corpus(output, *, cc, upx=None, jobs=2):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'Corpus output exists')
    require(type(jobs) is int and 1 <= jobs <= 8, 'Build jobs must be in 1..8')
    ccargv = list(cc) if type(cc) in (tuple,list) else [os.fspath(cc)]
    require(ccargv and len(ccargv) <= 16 and
            all(type(arg) is str and arg and '\0' not in arg for arg in ccargv), 'Invalid compiler argument list')
    compiler = _tool(ccargv[0]); ccargv[0] = str(compiler)
    make = _tool('make')
    output.mkdir(parents=True, exist_ok=False)
    cache = output.parent/'external-download-cache'
    source_rows=[]; extracted={}
    for source in SOURCES:
        archive=fetch(source,cache)
        extracted[source.name]=extract_archive(archive,output/'sources'/source.root,
            root=source.root,compression=source.compression)
        source_rows.append(dict(name=source.name,url=source.url,sha256=source.sha256,
                                sha512=source.sha512,cache_file=str(archive),root=source.root))
    official_upx=extracted[UPX.name]/'upx'
    selected_upx=_tool(upx) if upx is not None else _tool(official_upx)
    require(digest(selected_upx)==digest(official_upx),
            'Selected UPX is not byte-identical to the authenticated official 5.2.1 archive')
    tools={key:dict(path=str(path),sha256=digest(path)) for key,path in
           [('cc',compiler),('make',make),('upx',selected_upx)]}
    tools['cc']['argv']=ccargv
    for key,path in [('cc',compiler),('upx',selected_upx)]:
        argv=ccargv+['--version'] if key=='cc' else [str(path),'--version']
        _command(argv,output,output/(key+'-version'),timeout=30)
        tools[key]['version']=(output/(key+'-version.stdout')).read_text(errors='replace')
    require('5.2.1' in tools['upx']['version'], 'UPX version identity differs')
    samples=[];builds=[]
    for program,source,binary in [('xxhsum',XXHASH,'xxhsum'),('bzip2',BZIP2,'bzip2')]:
        directory=output/'programs'/program;directory.mkdir(parents=True)
        tree=extracted[source.name]
        flags=[*BUILD_FLAGS,*(['-D_FILE_OFFSET_BITS=64'] if program=='bzip2' else [])]
        command=[str(make),f'-j{jobs}',binary,'CC='+shlex.join(ccargv),
                 'CFLAGS='+shlex.join(flags),'LDFLAGS=-static -no-pie -Wl,--build-id=none']
        if program=='xxhsum':command+=['DISPATCH=0']
        built=_command(command,tree,directory/'build',timeout=600)
        original=directory/'original.elf';shutil.copy2(tree/binary,original);original.chmod(0o700)
        profile=elf_profile(original);original_sha=digest(original)
        cases=directory/'cases.json';save(cases,input_cases(program))
        receipt=dict(schema_version=1,program=program,source_archive_sha256=source.sha256,
            source_version='0.8.3' if program=='xxhsum' else '1.0.8',
            upstream_standalone_CLI=True,project_fixture_or_custom_payload=False,
            command=built,compiler=tools['cc'],original_sha256=original_sha,
            original=str(original.relative_to(output)),original_profile=profile,
            cases_sha256=digest(cases),source_edited_before_build=False,
            original_built_before_packing=True,original_supplies_unpacking_or_SMT_state=False)
        build_receipt=directory/'build-receipt.json';save(build_receipt,receipt)
        builds.append(dict(program=program,receipt=str(build_receipt.relative_to(output)),
                           sha256=digest(build_receipt)))
        for packing in ('default','lzma'):
            sample=output/'samples'/(program+'-'+packing);sample.mkdir(parents=True)
            packed=sample/'packed.elf'
            require(digest(original)==original_sha,'Reference changed before packing')
            argv=[str(selected_upx),'-q','--no-progress',
                  *(['--lzma'] if packing=='lzma' else []),'-o',str(packed),str(original)]
            # Persist the input identity before invoking the packer.
            prepack=dict(schema_version=1,program=program,packing=packing,
                original_sha256=original_sha,original=str(original.relative_to(output)),
                source_archive_sha256=source.sha256,build_receipt_sha256=digest(build_receipt),
                upx_sha256=tools['upx']['sha256'],argv=argv,
                recorded_before_packer_invocation=True)
            prepack_path=sample/'prepack.json';save(prepack_path,prepack)
            packed_run=_command(argv,sample,sample/'pack',timeout=120)
            _command([str(selected_upx),'-t',str(packed)],sample,sample/'pack-test',timeout=120)
            packed.chmod(0o700);packed_profile=elf_profile(packed)
            require(digest(original)==original_sha,'Packer changed the original reference')
            pack_receipt=sample/'pack-receipt.json';save(pack_receipt,dict(
                schema_version=1,prepack_sha256=digest(prepack_path),
                original_sha256=original_sha,packed_sha256=digest(packed),
                upx_sha256=tools['upx']['sha256'],run=packed_run,upx_test_succeeded=True,
                packed_profile=packed_profile,original_unchanged=True))
            samples.append(dict(id=program+'-'+packing,program=program,packing=packing,
                original=str(original.relative_to(output)),packed=str(packed.relative_to(output)),
                cases=str(cases.relative_to(output)),original_sha256=original_sha,
                packed_sha256=digest(packed),cases_sha256=digest(cases),
                build_receipt=str(build_receipt.relative_to(output)),
                pack_receipt=str(pack_receipt.relative_to(output)),prepack=str(prepack_path.relative_to(output))))
    for name,row in tools.items():require(digest(Path(row['path']))==row['sha256'],'Tool identity changed: '+name)
    manifest=output/'corpus.json';save(manifest,dict(schema_version=1,
        corpus_kind='upstream_static_i386_UPX',sources=source_rows,tools=tools,builds=builds,
        samples=samples,expected_samples=4,cases_per_program=20,
        proof_or_behavior_evaluation_performed=False,controlled_decoder_fixtures_used=False))
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default=os.environ.get('TF_EXTERNAL_CC'))
    parser.add_argument('--upx',type=Path)
    parser.add_argument('--jobs',type=int,default=2)
    args=parser.parse_args()
    if args.cc is None:parser.error('--cc or TF_EXTERNAL_CC is required')
    try:
        print(build_corpus(args.output,cc=args.cc,upx=args.upx,jobs=args.jobs),flush=True)
    except (CorpusError,OSError,ValueError,subprocess.SubprocessError,tarfile.TarError) as error:
        print('FAIL:',type(error).__name__+':',error,flush=True)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
