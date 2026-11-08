"""Transactional hardlink deduplication of verified immutable runtime bundles."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),'Missing regular runtime file: '+str(path))
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):
    path=Path(path);fd,name=tempfile.mkstemp(prefix='.journal-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)


def signature(path):
    st=Path(path).stat()
    attrs=tuple((name,os.getxattr(path,name).hex()) for name in sorted(os.listxattr(path)))
    return (st.st_dev,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),attrs)


def replace_runtime(source,target,journal,state):
    """Lease owner-write on the exact destination directory, restoring it before auditing."""
    target=Path(target);parent=target.parent
    require(parent.resolve(strict=True)==parent,'Runtime directory contains a symlink')
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd);mode=stat.S_IMODE(st.st_mode)
        require(st.st_uid==os.getuid(),'Runtime directory is not owned by the current user: '+str(parent))
        leases=state.setdefault('directory_permissions',{});old=leases.get(str(parent))
        if old:
            require((st.st_dev,st.st_ino,st.st_uid,st.st_gid,mode)==
                    (old['device'],old['inode'],old['uid'],old['gid'],old['mode']) and not old['restore_needed'],
                    'Runtime directory changed during compaction: '+str(parent))
        if mode&stat.S_IWUSR:
            os.replace(source,target.name,dst_dir_fd=fd);return
        lease={'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,
               'mode':mode,'restore_needed':True}
        leases[str(parent)]=lease;save(journal,state)
        try:
            os.fchmod(fd,mode|stat.S_IWUSR)
            os.replace(source,target.name,dst_dir_fd=fd)
        finally:
            os.fchmod(fd,mode)
            require(stat.S_IMODE(os.fstat(fd).st_mode)==mode,'Runtime directory mode was not restored')
            lease['restore_needed']=False;save(journal,state)
    finally:os.close(fd)


def restore_directory_permissions(journal,state,directories):
    """Close a recorded permission lease left open by a terminated process."""
    for name,lease in state.get('directory_permissions',{}).items():
        path=Path(name)
        require(path.is_absolute() and path.resolve(strict=True)==path and
                any(path==d/'runtime' or path.is_relative_to(d/'runtime') for d in directories),
                'Journal permission path escapes verified runtimes')
        mode=lease['mode'];require(type(mode) is int and 0<=mode<=0o7777,'Invalid recorded runtime directory mode')
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd);current=stat.S_IMODE(st.st_mode)
            require((st.st_dev,st.st_ino,st.st_uid,st.st_gid)==
                    (lease['device'],lease['inode'],lease['uid'],lease['gid']) and st.st_uid==os.getuid(),
                    'Runtime permission journal inode or owner differs')
            require(current in (mode,mode|stat.S_IWUSR) if lease['restore_needed'] else current==mode,
                    'Runtime directory mode changed outside the recorded lease')
            if lease['restore_needed']:
                os.fchmod(fd,mode);lease['restore_needed']=False;save(journal,state)
        finally:os.close(fd)


def compact(directories,pool,journal_parent,bundle_hash,verify_bundle,audit,progress=None):
    """Keep every old inode via a backup link until all reconstruction audits pass."""
    directories=[Path(p).resolve(strict=True) for p in directories]
    require(len(set(directories))==len(directories),'Duplicate analysis in runtime compaction')
    pool=Path(pool).resolve(strict=True);journal_parent=Path(journal_parent).resolve(strict=True)
    require(pool.stat().st_dev==journal_parent.stat().st_dev,'Pool and journal must share a filesystem')
    transaction=Path(tempfile.mkdtemp(prefix='runtime-links.',dir=journal_parent));backups=transaction/'backups';backups.mkdir()
    state={'state':'staging','analyses':list(map(str,directories)),'bundle_sha256':bundle_hash,
           'pool':str(pool),'entries':[],'created_pool':[],'files_linked':0,'files_already_shared':0,'files_skipped':0}
    journal=transaction/'transaction.json';save(journal,state)
    free_before=shutil.disk_usage(pool).free
    try:
        for index,directory in enumerate(directories,1):
            manifest=verify_bundle(directory/'runtime',bundle_hash)
            require(manifest['bundle_sha256']==bundle_hash,'Runtime bundle identity differs')
            for item in manifest['files']:
                relative=Path(item['path']);require(relative.parts and not relative.is_absolute() and '..' not in relative.parts,'Invalid runtime path')
                target=directory/'runtime'/relative
                require(target.resolve(strict=True).is_relative_to(directory/'runtime'),'Runtime file escapes bundle')
                require(digest(target)==item['sha256'] and target.stat().st_size==item['size'],'Runtime file changed')
                if target.stat().st_dev!=pool.stat().st_dev or target.stat().st_uid!=os.getuid():
                    state['files_skipped']+=1;continue
                identity=(item['sha256'],item['size'],signature(target))
                key=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest();canonical=pool/key
                if not canonical.exists():
                    state['created_pool'].append(str(canonical));save(journal,state);os.link(target,canonical)
                require(digest(canonical)==item['sha256'] and signature(canonical)==signature(target),'Pool object differs')
                if target.samefile(canonical):state['files_already_shared']+=1;continue
                require(shutil.disk_usage(pool).free>=4*1024**3+16*1024**2,'Runtime compaction stopped at metadata reserve')
                backup=backups/str(len(state['entries']))
                entry={'target':str(target),'backup':str(backup),'canonical':str(canonical),
                       'sha256':item['sha256'],'replaced':False}
                state['entries'].append(entry);save(journal,state)
                os.link(target,backup)
                require(target.samefile(backup) and digest(backup)==item['sha256'],'Runtime changed before link publication')
                temporary=transaction/'replacement'
                os.link(canonical,temporary);replace_runtime(temporary,target,journal,state)
                entry['replaced']=True;state['files_linked']+=1;save(journal,state)
            if progress and (index%10==0 or index==len(directories)):progress('Runtime link preparation: %d/%d'%(index,len(directories)))
        state['state']='auditing';save(journal,state)
        restore_directory_permissions(journal,state,directories)
        for index,directory in enumerate(directories,1):
            verify_bundle(directory/'runtime',bundle_hash)
            audit(directory)
            if progress and (index%10==0 or index==len(directories)):progress('Post-link API audits: %d/%d'%(index,len(directories)))
        state['state']='validated';save(journal,state)
        for entry in state['entries']:Path(entry['backup']).unlink(missing_ok=True)
        state['state']='committed';state['filesystem_free_change_bytes']=shutil.disk_usage(pool).free-free_before
        save(journal,state)
        return {'journal':str(journal),'analyses':len(directories),'files_linked':state['files_linked'],
                'files_already_shared':state['files_already_shared'],'files_skipped':state['files_skipped'],
                'filesystem_free_change_bytes':state['filesystem_free_change_bytes'],'all_api_audits_passed':True}
    except BaseException:
        if state['state'] not in ('validated','committed'):
            (transaction/'replacement').unlink(missing_ok=True)
            restore_directory_permissions(journal,state,directories)
            for entry in reversed(state['entries']):
                target,backup,canonical=map(Path,(entry['target'],entry['backup'],entry['canonical']))
                if not backup.exists():continue
                require(digest(target)==entry['sha256'],'Concurrent runtime edit prevents rollback: '+str(target))
                if not target.samefile(backup):
                    require(target.samefile(canonical),'Runtime inode changed outside transaction')
                    replace_runtime(backup,target,journal,state)
                else:backup.unlink()
            for name in reversed(state['created_pool']):Path(name).unlink(missing_ok=True)
            state['state']='rolled_back';save(journal,state)
        else:
            state['reclaim_interrupted']=True;save(journal,state)
        raise


def recover(journal,allowed_directories,bundle_hash,verify_bundle,audit):
    journal=Path(journal).resolve(strict=True)
    require(journal.name=='transaction.json' and journal.parent.parent.name=='runtime-transactions','Unexpected runtime journal location')
    state=json.loads(journal.read_text());allowed={Path(p).resolve(strict=False) for p in allowed_directories}
    directories=[Path(p).resolve(strict=True) for p in state['analyses']]
    require(set(directories)<=allowed and state['bundle_sha256']==bundle_hash,'Runtime journal belongs to another cohort')
    pool=journal.parent.parent.parent/'runtime-pool';require(Path(state['pool'])==pool,'Runtime journal pool path differs')
    for entry in state['entries']:
        target=Path(entry['target']);backup=Path(entry['backup']);canonical=Path(entry['canonical'])
        require(any(target.is_relative_to(d/'runtime') for d in directories) and target.resolve(strict=True)==target,
                'Journal target escapes verified runtimes')
        require(backup.parent==journal.parent/'backups' and backup.name.isdecimal() and canonical.parent==pool,
                'Journal backup or canonical path is invalid')
        require(digest(target)==entry['sha256'],'Runtime changed since journal creation')
        if backup.exists():require(digest(backup)==entry['sha256'],'Runtime backup changed')
    for name in state['created_pool']:
        path=Path(name);require(path.parent==pool and len(path.name)==64 and all(c in '0123456789abcdef' for c in path.name),
                                'Invalid journal pool object')
    restore_directory_permissions(journal,state,directories)
    (journal.parent/'replacement').unlink(missing_ok=True)
    if state['state']=='rolled_back':return {'journal':str(journal),'state':'rolled_back'}
    try:
        for directory in directories:verify_bundle(directory/'runtime',bundle_hash);audit(directory)
    except BaseException:
        if state['state'] in ('validated','committed'):raise
        for entry in reversed(state['entries']):
            target,backup,canonical=map(Path,(entry['target'],entry['backup'],entry['canonical']))
            if backup.exists():
                if not target.samefile(backup):
                    require(target.samefile(canonical),'Concurrent edit prevents journal rollback');replace_runtime(backup,target,journal,state)
                else:backup.unlink()
            else:require(not entry['replaced'],'Missing rollback inode for a replaced runtime file')
        for name in reversed(state['created_pool']):Path(name).unlink(missing_ok=True)
        state['state']='rolled_back';save(journal,state)
        for directory in directories:verify_bundle(directory/'runtime',bundle_hash);audit(directory)
        return {'journal':str(journal),'state':'rolled_back'}
    state['state']='validated';save(journal,state)
    for entry in state['entries']:Path(entry['backup']).unlink(missing_ok=True)
    state['state']='committed';save(journal,state)
    return {'journal':str(journal),'state':'committed'}
