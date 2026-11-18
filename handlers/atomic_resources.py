"""Явна підготовка pinned супровідних файлів; жодних команд визначення."""
import hashlib
import json
from pathlib import Path
import re
import tempfile
from uuid import uuid4
import zipfile
import yaml

from handlers import dependencies as deps
from handlers.installation import (plain_path, installation_lock, load_state, save_state,
    save_state_after_error, place_file, component)
from handlers.component_inventory import begin_operation, finish_operation, create_component_record, utc_now
from handlers.package_cache import obtain_package, verify_package_file
from handlers.package_extract import inspect_zip, extract_files
from handlers.runtime_paths import data_root, read_settings, generation_path, runtime_config
from handlers.atomic_lifecycle import build_plan, public_plan
from handlers.release_manifest import validate_release_path, describe_file


def resource_plan(project, technique, number, *, root=None, cache=None, offline=False,
                  inputs=None, asset_techniques=(), asset_files=()):
    
    
    root=data_root() if root is None else plain_path(root)
    
    if deps.status(project,root=root)['status']!='passed':
        raise ValueError('Base modules are not ready; run dependencies prepare')
    
    technique=str(technique).upper()
    
    if not re.fullmatch(r'T\d{4}(?:\.\d{3})?',technique):raise ValueError('Invalid technique')
    if type(number) is not int or number<1:raise ValueError('Invalid test number')
    
    config=runtime_config(project,root=root)
    config['atomic'].pop('managed_catalog',None);config['atomic'].pop('selected_tests',None)
    package=deps.locked_packages(project)['atomic_definitions']
    cache=plain_path(cache) if cache else root/'cache'
    archive=Path(obtain_package(package,cache,offline=offline)['path'])
    files={};unresolved=[];external=[]
    
    with zipfile.ZipFile(archive) as zipped:
        entries=inspect_zip(zipped,max_entries=50000,max_unpacked_bytes=2*1024**3)
        prefixes={name.split('/atomics/',1)[0]+'/atomics/' for _,name,_ in entries if '/atomics/' in name}
        
        if len(prefixes)!=1:raise ValueError('Unexpected Atomic archive layout')
        
        prefix=prefixes.pop()
        available={name[len(prefix):]:entry for entry,name,directory in entries if not directory and name.startswith(prefix)}
        definition_name=f'{technique}/{technique}.yaml'
        
        if definition_name not in available:raise ValueError('Selected definition is absent from pinned archive')
        if available[definition_name].file_size>8*1024*1024:raise ValueError('Selected definition exceeds size limit')
        
        raw=zipped.read(available[definition_name])
        plan=build_plan(config,technique,number,inputs=inputs,prepare=True,definition_bytes=raw)
        selected=yaml.safe_load(raw.decode('utf-8-sig'))['atomic_tests'][number-1]
        wanted={definition_name}
        
        def strings(value):
            if isinstance(value,str):yield value
            
            elif isinstance(value,dict):
                for child in value.values():yield from strings(child)
            
            elif isinstance(value,list):
                for child in value:yield from strings(child)
        
        
        code_inputs=[selected['executor'].get('command',''),selected['executor'].get('cleanup_command','')]
        
        for dependency in selected.get('dependencies') or []:
            code_inputs.extend([dependency.get('prereq_command',''),dependency.get('get_prereq_command','')])
        
        for text in strings(code_inputs):
            
            for key,value in plan['inputs'].items():text=text.replace('#{'+key+'}',value)
            for match in re.finditer(r'''(?:\$?PathToAtomicsFolder)[/\\]+([^\s"'`<>|;&)]+)''',text):
                relative=match.group(1).replace('\\','/').rstrip('/')
                
                if relative.startswith('../'):
                    external.append(relative);continue
                if any(char in relative for char in '$*?{}'):
                    unresolved.append(relative);continue
                
                validate_release_path(relative)
                
                if relative in available:wanted.add(relative)
                
                else:
                    nested={name for name in available if name.startswith(relative+'/')}
                    if nested:wanted.update(nested)
                    else:external.append(relative)
        
        for name in asset_files:
            name=name.replace('\\','/');validate_release_path(name)
            
            if name not in available:raise ValueError('Requested asset absent from pinned archive: '+name)
            
            wanted.add(name)
        
        for family in asset_techniques:
            family=family.upper()
            
            if not re.fullmatch(r'T\d{4}(?:\.\d{3})?',family):raise ValueError('Invalid asset technique')
            
            names={name for name in available if name.startswith(family+'/')}
            
            if not names:raise ValueError('Requested asset technique absent from pinned archive: '+family)
            
            wanted.update(names)
        
        for name in sorted(wanted):
            entry=available[name];digest=hashlib.sha256()
            
            with zipped.open(entry) as stream:
                while chunk:=stream.read(1024*1024):digest.update(chunk)
            
            files[name]={'size':entry.file_size,'sha256':digest.hexdigest()}
    
    families=sorted({name.split('/')[0] for name in files})
    
    return {'status':'blocked' if unresolved and not (asset_files or asset_techniques) else 'planned',
        'reason':'Review dynamic resource paths and supply --asset-file or --asset-technique' if unresolved else None,
        'technique':technique,'test_number':number,'inputs':inputs or {},'asset_techniques':families,
        'files':files,'package':package,'archive':str(archive),'base_definition_sha256':plan['definition_sha256'],
        'atomic_plan':public_plan(plan),'dynamic_paths':sorted(set(unresolved)),
        'prerequisite_or_external_paths':sorted(set(external)),
        'scope':'selected_definition_and_referenced_or_explicit_resources',
        'limitations':'The upstream technique YAML contains multiple test definitions. Only the selected test is executed after separate consent. '
            'Dynamic paths require engineer review; --asset-technique explicitly includes a whole folder. '
            'Resource preparation does not execute prerequisites or establish live readiness.'}

def prepare_resources(project, proposal, *, approved=False, root=None):
    if proposal.get('status')!='planned':return {'status':'blocked','reason':'Resource plan is not ready','plan':proposal}
    
    if not approved:return {'status':'blocked','reason':'Selected resource preparation requires explicit consent'}
    
    root=data_root() if root is None else plain_path(root)
    
    with installation_lock(root/'dependency-operation'):
        if deps.status(project,root=root)['status']!='passed':raise ValueError('Base dependency integrity failed')
        
        target=generation_path(root,read_settings(root)['active']);state=load_state(target)
        key=f"{proposal['technique']}:{proposal['test_number']}"
        current=state.get('selected_tests',{}).get(key)
        
        if current and current['status']=='passed' and current['files']==proposal['files']:
            for name,expected in current['files'].items():
                if describe_file(plain_path(Path(current['atomics_path'])/name))!=expected:
                    
                    return {'status':'blocked','reason':'Prepared selected resource changed','path':name}
            
            return {'status':'passed','repeated':True,'resources':current,'scope':'resources_only_not_test_readiness'}
        
        if current and current['status']=='passed':raise ValueError('Existing selected resources are preserved; remove dependencies before changing resource selection')
        if current:state.setdefault('selected_test_attempts',[]).append(dict(current,selection=key))
        
        package=deps.locked_packages(project)['atomic_definitions']
        
        if package!=proposal['package']:raise ValueError('Dependency lock changed after resource approval')
        
        archive=Path(proposal['archive']);verify_package_file(archive,package)
        relative_root='managed/selected/'+str(uuid4())+'/atomics'
        component_key='atomic_resources:'+key+':'+str(uuid4())
        item=create_component_record(component_key);item.update(presence='absent',shared=False)
        state['inventory']['components'].append(item)
        state['inventory'],op=begin_operation(state['inventory'],item['component_id'],'install')
        item=component(state,component_key)
        
        record={'status':'preparing','atomics_path':str(target/relative_root),'files':proposal['files'],
            'asset_techniques':proposal['asset_techniques'],'scope':proposal['scope'],'operation_id':op}
        
        state.setdefault('selected_tests',{})[key]=record;save_state(target,state)
        
        try:
            with tempfile.TemporaryDirectory(prefix='dvp-selected-resources-') as temporary:
                work=Path(temporary)
                with zipfile.ZipFile(archive) as zipped:
                    entries=inspect_zip(zipped,max_entries=50000,max_unpacked_bytes=2*1024**3)
                    selected=[]
                    
                    for entry,name,directory in entries:
                        
                        if directory or '/atomics/' not in name:continue
                        relative=name.split('/atomics/',1)[1]
                        
                        if relative in proposal['files']:selected.append((entry,relative,False))
                    
                    failures=[]
                    
                    for entry,relative,directory in selected:
                        try:
                            actual=extract_files(zipped,[(entry,relative,directory)],work,max_unpacked_bytes=2*1024**3)
                            observed={k:actual[0][k] for k in ('size','sha256')}
                            
                            if observed!=proposal['files'][relative]:raise ValueError('Selected file differs from pinned plan')
                            
                            place_file(target,state,item,op,relative_root+'/'+relative,work/relative,observed)
                        
                        except Exception as exc:
                            failure=deps.failure_details(exc,component_id=key,operation='prepare_selected_file',path=relative)
                            failures.append(failure)
                            record['failures']=failures
                            save_state(target,state)
                    
                    if set(name for _,name,_ in selected)!=set(proposal['files']):
                        raise ValueError('Approved file list is not present in pinned archive')
                    
                    if failures:
                        record.update(status='blocked' if any(f['status']=='blocked' for f in failures) else 'error',ready=False)
                        state['inventory']=finish_operation(state['inventory'],op,status='failed',verification='unknown',details='Some selected files were not installed; independent files were attempted')
                        save_state(target,state)
                        
                        return {'status':record['status'],'resources':record,'failures':failures,'scope':'selected_resources_only','base_modules_affected':False}
            
            state['inventory']=finish_operation(state['inventory'],op,status='succeeded',verification='passed',details='Approved selected resources installed and verified')
            item=component(state,component_key)
            item.update(origin='installed_by_dvp',presence='present',shared=False,path=str(target/relative_root),version=package['version'],installation_operation_id=op,last_checked_at=utc_now())
            item['source'].update(kind='url',location=package['url'],revision=package['version'],sha256=package['sha256'])
            record['status']='passed';save_state(target,state)
            
            return {'status':'passed','resources':record,'scope':'resources_only_not_test_readiness'}
        
        except (Exception,KeyboardInterrupt) as exc:
            record.update(status='interrupted' if isinstance(exc,KeyboardInterrupt) else 'error',reason=str(exc))
            
            if any(entry['operation_id']==op and entry['status']=='pending' for entry in state['inventory']['operations']):
                state['inventory']=finish_operation(state['inventory'],op,status='failed',verification='unknown',details=str(exc) or type(exc).__name__)
            
            persistence=save_state_after_error(target,state)
            
            if isinstance(exc,KeyboardInterrupt):raise
            
            return {'status':'blocked' if getattr(exc,'winerror',None) in (225,226) else 'error',
                'reason':str(exc),'error_type':type(exc).__name__,'errno':getattr(exc,'errno',None),
                'winerror':getattr(exc,'winerror',None),'persistence_error':persistence,
                'scope':'selected_resources','recovery':'Inspect the ledger; dependencies remove preserves unconfirmed or modified files. Protection settings are unchanged.'}
