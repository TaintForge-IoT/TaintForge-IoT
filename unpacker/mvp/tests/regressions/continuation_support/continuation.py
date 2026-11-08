"""Explicit reuse of audited analysis directories; ordinary fresh runs keep their behavior."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

import runtime_dedup

CONTEXT='TF_REGRESSION_CONTINUATION_CONTEXT'
CONTEXT_SHA='TF_REGRESSION_CONTINUATION_CONTEXT_SHA256'


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):return runtime_dedup.digest(path)


def context(required=False):
    name=os.environ.get(CONTEXT);expected=os.environ.get(CONTEXT_SHA)
    require(bool(name)==bool(expected),'Incomplete continuation context')
    if not name:
        require(not required,'Resume requires an explicit verified continuation context')
        return None
    path=Path(name)
    require(path.is_absolute() and path.resolve(strict=True)==path and path.stat().st_size<=1024*1024,'Invalid continuation context path')
    require(digest(path)==expected,'Continuation context changed')
    value=json.loads(path.read_text());require(value['profile']=='taintforge-regression-continuation-v1','Unknown continuation profile')
    for member,h in value['support_files'].items():
        require(digest(Path(__file__).parent/member)==h,'Continuation support changed')
    return value


def work_directory(previous,parent,prefix):
    if previous is None:return Path(tempfile.mkdtemp(prefix=prefix,dir=parent))
    cfg=context(True);work=Path(previous).expanduser().resolve(strict=True)
    require(work.is_dir() and work.parent==parent and work.name.startswith(prefix) and str(work) in cfg['nodes'],
            'Resume directory is not a verified node of the source run')
    archive_sudo_journal(work,cfg)
    return work


def archive_sudo_journal(work,cfg):
    """Preserve a closed session journal so the unchanged sudo guard can create a new one."""
    path=work/'sudo-session.json'
    if not path.exists() and not path.is_symlink():return
    expected=digest(path)
    require(path.stat().st_size<=8*1024**2,'Saved sudo session journal exceeds its byte budget')
    value=json.loads(path.read_text())
    require(value.get('profile')=='same-process-noninteractive-sudo-session-v1' and
            value.get('active') is False and value.get('executor_binding_restored') is True and
            value.get('thread_stopped') is True,'Cannot archive a sudo journal that is not closed')
    backup=work/('sudo-session.before-resume.'+expected+'.json')
    if backup.exists():require(digest(backup)==expected,'Historical sudo session journal differs')
    else:os.link(path,backup)
    require(digest(path)==expected and digest(backup)==expected,'Sudo journal changed before preservation')
    row={'source':str(path),'archived':str(backup),'sha256':expected,'previous_process_id':value.get('process_id')}
    fd=os.open(Path(cfg['work'])/'sudo-journal-history.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:os.write(fd,(json.dumps(row,sort_keys=True)+'\n').encode());os.fsync(fd)
    finally:os.close(fd)
    path.unlink()


def child_arguments(parent,resuming):
    if not resuming:return []
    cfg=context(True);candidates=[Path(p) for p in cfg['nodes'] if Path(p).parent==parent]
    require(len(candidates)==1,'Child resume identity is ambiguous')
    return ['--resume-work',str(candidates[0])]


def is_resuming(work):
    cfg=context()
    return bool(cfg and str(Path(work).resolve(strict=True)) in cfg['nodes'])


def copyfile(source,destination,preserve=False):
    destination=Path(destination)
    if preserve and destination.exists():
        require(digest(source)==digest(destination),'Existing fixed definition differs')
        return str(destination)
    return shutil.copyfile(source,destination)


def materialize(function,*arguments,preserve=False):
    destination=Path(arguments[-1])
    if not preserve or not destination.exists():return function(*arguments)
    cfg=context(True);fd,name=tempfile.mkstemp(prefix='fixed-elf-check.',dir=cfg['work']);os.close(fd)
    temporary=Path(name)
    try:
        function(*arguments[:-1],temporary)
        require(digest(destination)==digest(temporary) and
                stat.S_IMODE(destination.stat().st_mode)==stat.S_IMODE(temporary.stat().st_mode),
                'Existing fixed ELF differs from its materializer')
    finally:temporary.unlink(missing_ok=True)


def oracle_directory(path,resuming):
    path=Path(path)
    if not resuming or not path.exists():return path
    cfg=context(True);fresh=Path(tempfile.mkdtemp(prefix='legacy-oracle.',dir=cfg['work']));fresh.rmdir()
    return fresh


def export_reports(original,work,resuming):
    destination=work/('taintforge_regression_'+work.name+'_reports.zip')
    if resuming and destination.exists():
        expected=digest(destination);backup=work/(destination.stem+'.before-resume.'+expected[:12]+'.zip')
        if backup.exists():require(digest(backup)==expected,'Existing historical report differs')
        else:os.link(destination,backup)
        require(digest(destination)==expected,'Report changed before preservation');destination.unlink()
    return original(work)


def request_identity(result,kind,params):
    require(result['status']=='passed' and result['original_inputs_unchanged'] is True,'Cached analysis is not passed')
    expected=['solve','observe'] if kind=='invert_file' else ['observe']
    require(kind in ('invert_file','observe_file') and [r['case'] for r in result['runs']]==expected,'Cached method differs')
    for key,parameter in [('binary','binary'),('seed','seed'),('qemu','qemu'),('plugin','plugin'),('flags_receipt','flags_receipt')]:
        path=Path(params[parameter]).resolve(strict=True);old=result['inputs'][key]
        require(Path(old['path'])==path and old['sha256']==digest(path) and old['size']==path.stat().st_size,
                'Cached request input differs: '+key)
    require(result['branch_pc']==params['branch_pc'] and result['offsets']==list(params['offsets']) and
            result['occurrence']==params['occurrence'] and result['input_path']==params['input_path'] and
            result['argv']==list(params['argv']) and result['max_steps']==params['max_steps'] and
            result['budgets']=={'case_cpu_seconds':params['seconds'],'memory_mib':params['memory_mib']},
            'Cached selected branch, input scope or budget differs')


def event(cfg,destination,kind,result,origin):
    row={'directory':str(Path(destination).resolve(strict=True)),'kind':kind,'origin':origin,
         'summary_sha256':digest(Path(destination)/'summary.json'),'execution_receipts':len(result['runs'])}
    fd=os.open(cfg['events'],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:os.write(fd,(json.dumps(row,sort_keys=True)+'\n').encode());os.fsync(fd)
    finally:os.close(fd)


def cached(api,kind,params,destination):
    cfg=context();destination=Path(destination)
    if not cfg or not destination.exists():return None
    path=destination.resolve(strict=True)
    require(str(path) in cfg['allowlist'],'Existing analysis is not in the verified allowlist')
    summary=path/'summary.json';require(digest(summary)==cfg['allowlist'][str(path)],'Cached analysis summary changed')
    result=json.loads(summary.read_text());request_identity(result,kind,params)
    require(api.audit_file_run(directory=path)==result,'Cached original API reconstruction differs')
    event(cfg,path,kind,result,'reused')
    return result


def completed(api,kind,params,destination,result):
    cfg=context()
    if not cfg:return
    destination=Path(destination).resolve(strict=True)
    require(str(destination) in cfg['expected_analyses'],'Fresh analysis is outside the fixed cohort')
    request_identity(result,kind,params)
    require(result['bundle_sha256']==cfg['bundle_sha256'],'Fresh runtime bundle differs')
    unified=importlib.import_module('taintforge_env.unified_runtime')
    def audit(path):require(api.audit_file_run(directory=path)==result,'Post-link fresh API reconstruction differs')
    runtime_dedup.compact([destination],Path(cfg['pool']),Path(cfg['transactions']),cfg['bundle_sha256'],unified.verify_bundle,audit)
    event(cfg,destination,kind,result,'fresh')
